using Azure.Core;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Azure.Messaging.EventHubs;
using Azure.Messaging.EventHubs.Producer;

namespace FBAuthenticate.Controllers
{
    public class AuthController
    {
        private readonly IMemoryCache _cache;
        private readonly IConfiguration _config;
        private readonly TimeSpan _expiry;
        private readonly EventHubProducerClient _eventHubProducer;

        // replace HashSet in cache with a thread-safe collection to track keys
        // We still keep the "token-keys" cache entry for compatibility, but we maintain a thread-safe set here.
        private static readonly ConcurrentDictionary<string, byte> _tokenKeys = new ConcurrentDictionary<string, byte>();

        public AuthController(IMemoryCache cache, IConfiguration config, EventHubProducerClient eventHubProducer)
        {
            _cache = cache;
            _config = config;
            _eventHubProducer = eventHubProducer;

            // Default to 24 hours if TokenExpiryHours is not specified
            double hours = config.GetValue<double>("TokenExpiryHours", 24);
            _expiry = TimeSpan.FromHours(hours);
        }

        /// <summary>
        /// Generates a token for the given IP and timestamp, caches it, and returns it to the client.
        /// Note: In the Azure Functions Isolated Worker model we use FunctionContext to get a logger.
        /// </summary>
        [Function("FBAutenticate")]
        public async Task<HttpResponseData> FBAutenticate(
            [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req,
            FunctionContext context)
        {
            var log = context.GetLogger<AuthController>();
            log.LogInformation("FBAutenticate triggered.");

            AuthRequest? request = await ParseRequest<AuthRequest>(req, log, "Invalid JSON");
            if (request == null || string.IsNullOrEmpty(request.ip) || string.IsNullOrEmpty(request.timestamp))
            {
                log.LogWarning("Invalid request: missing ip or timestamp.");
                return await CreateJsonResponse(req, HttpStatusCode.BadRequest, new { message = "IP and timestamp required" });
            }

            string tokenCacheKey = $"fbt-{request.ip}-token";
            log.LogInformation("Token cache key computed: {TokenCacheKey}", tokenCacheKey);

            if (!_cache.TryGetValue(tokenCacheKey, out string token))
            {
                token = GenerateToken(request.ip, request.timestamp);
                _cache.Set(tokenCacheKey, token, _expiry);

                // Track the key in a thread-safe manner
                _tokenKeys.TryAdd(tokenCacheKey, 0);

                log.LogInformation("Generated and cached new token for IP {IP}.", request.ip);
            }
            else
            {
                log.LogInformation("Token retrieved from cache for IP {IP}.", request.ip);
            }

            return await CreateJsonResponse(req, HttpStatusCode.OK, new { token });
        }

        /// <summary>
        /// Lists all active tokens from the in-memory cache.
        /// </summary>
        [Function("ListTokens")]
        public async Task<HttpResponseData> ListTokens(
            [HttpTrigger(AuthorizationLevel.Function, "get")] HttpRequestData req,
            FunctionContext context)
        {
            var log = context.GetLogger<AuthController>();
            log.LogInformation("ListTokens triggered.");

            var result = new Dictionary<string, string>();

            // Use the thread-safe key tracker to enumerate keys and read cached tokens
            foreach (var kv in _tokenKeys)
            {
                var key = kv.Key;
                if (_cache.TryGetValue(key, out string token))
                {
                    result[key] = token;
                }
            }

            log.LogInformation("Returning {Count} token(s).", result.Count);
            return await CreateJsonResponse(req, HttpStatusCode.OK, result);
        }

        /// <summary>
        /// Validates headers and request body, converts JSON to XML, sends lead data to the API with retry.
        /// On failure/timeout after retries, writes the JSON request body to Event Hub.
        /// </summary>
        [Function("SubmitLead")]
        public async Task<HttpResponseData> SubmitLead(
            [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req,
            FunctionContext context)
        {
            var log = context.GetLogger<AuthController>();
            log.LogInformation("SubmitLead triggered.");

            var authHeaders = new AuthHeaders
            {
                AuthorizationToken = req.Headers.TryGetValues("AuthorizationToken", out var tokenValues) ? tokenValues.FirstOrDefault() : null,
                AuthorizationId = req.Headers.TryGetValues("AuthorizationId", out var idValues) ? idValues.FirstOrDefault() : null
            };

            if (string.IsNullOrEmpty(authHeaders.AuthorizationToken) || string.IsNullOrEmpty(authHeaders.AuthorizationId))
            {
                log.LogWarning("Missing Authorization headers.");
                return await CreateJsonResponse(req, HttpStatusCode.BadRequest, new { message = "Missing Authorization headers" });
            }

            LeadRequest? body = await ParseRequest<LeadRequest>(req, log, "Invalid JSON body");
            if (body == null || body.Id == null || string.IsNullOrEmpty(body.Val))
            {
                log.LogWarning("Invalid lead request body: missing required fields.");
                return await CreateJsonResponse(req, HttpStatusCode.BadRequest, new { message = "Body is missing required fields" });
            }

            // Decrypt header; handle failure explicitly (return 400/403)
            string? ipAddress = DecryptHeaderValue(authHeaders.AuthorizationId, log);
            if (string.IsNullOrEmpty(ipAddress))
            {
                log.LogWarning("Failed to decrypt AuthorizationId header.");
                return await CreateJsonResponse(req, HttpStatusCode.BadRequest, new { message = "Invalid AuthorizationId header." });
            }

            string tokenCacheKey = $"fbt-{ipAddress}-token";
            log.LogInformation("Decrypted IP: {IP}. Checking token with key {Key}", ipAddress, tokenCacheKey);

            if (!_cache.TryGetValue(tokenCacheKey, out string cachedToken) || cachedToken != authHeaders.AuthorizationToken)
            {
                log.LogWarning("Token validation failed for IP: {IP}", ipAddress);
                return await CreateJsonResponse(req, HttpStatusCode.Forbidden, new { Message = "Invalid or expired token." });
            }

            // Prepare JSON and XML forms
            string jsonRequestBody = JsonConvert.SerializeObject(body);
            string xmlRequestBody = ConvertJsonToXml(jsonRequestBody);
            log.LogInformation("Converted lead request body to XML.");

            string leadApiResponse;
            try
            {
                leadApiResponse = await LeadApiRequest(_config, xmlRequestBody);
                log.LogInformation("Lead API response received.");
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Lead API failed after retries; writing payload to Event Hub.");
                await SendToEventHubAsync(jsonRequestBody, log);

                return await CreateJsonResponse(req, HttpStatusCode.Accepted, new
                {
                    message = "Lead queued for async processing via Event Hub.",
                    queued = true
                });
            }

            return await CreateJsonResponse(req, HttpStatusCode.OK, new
            {
                message = "Lead processed successfully",
                headers = authHeaders,
                body,
                xmlRequestBody,
                leadApiResponse
            });
        }

        private string GenerateToken(string ip, string timestamp)
        {
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes($"{ip}-{timestamp}"));
            return Convert.ToBase64String(bytes);
        }

        // Return null on failure instead of "Invalid IP" string
        public static string? DecryptHeaderValue(string encryptedHeader, ILogger? log = null)
        {
            if (string.IsNullOrEmpty(encryptedHeader))
            {
                log?.LogWarning("Empty encrypted header passed to DecryptHeaderValue.");
                return null;
            }

            var parts = encryptedHeader.Split(':');
            if (parts.Length != 2)
            {
                log?.LogWarning("Invalid encrypted header format.");
                return null;
            }
            try
            {
                byte[] iv = Convert.FromBase64String(parts[0]);
                byte[] encryptedData = Convert.FromBase64String(parts[1]);

                // NOTE: move key to config or Key Vault in production
                byte[] key = Encoding.UTF8.GetBytes("ASDFGHJKLASDFGHJASDFGHJKLASDFGHJ");
                if (key.Length != 32) return null;

                using var aesAlg = Aes.Create();
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                using var msDecrypt = new MemoryStream(encryptedData);
                using var csDecrypt = new CryptoStream(msDecrypt, aesAlg.CreateDecryptor(), CryptoStreamMode.Read);
                using var srDecrypt = new StreamReader(csDecrypt);
                return srDecrypt.ReadToEnd();
            }
            catch (Exception ex)
            {
                log?.LogWarning(ex, "Exception while decrypting header.");
                return null;
            }
        }

        public static string ConvertJsonToXml(string json)
        {
            try
            {
                XmlDocument xmlDoc = JsonConvert.DeserializeXmlNode(json, "root");
                return xmlDoc.OuterXml;
            }
            catch (Exception ex)
            {
                // escape message and return error XML
                return $"<error>{System.Security.SecurityElement.Escape(ex.Message)}</error>";
            }
        }

        // Note: now includes retry logic and throws on final failure.
        public static async Task<string> LeadApiRequest(IConfiguration config, string xmlData)
        {
            int maxRetries = Math.Max(1, config.GetValue<int>("LeadApiMaxRetries", 3));
            int baseDelayMs = Math.Max(100, config.GetValue<int>("LeadApiBaseDelayMs", 500));
            int timeoutSeconds = Math.Max(5, config.GetValue<int>("LeadApiTimeoutSeconds", 30));

            var authValue = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{config["LeadApiUsername"]}:{config["LeadApiPassword"]}"));
            var requestUri = config["LeadApiUrl"];

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    using var client = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(timeoutSeconds) };
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", authValue);

                    var content = new System.Net.Http.StringContent(xmlData, Encoding.UTF8, "application/xml");
                    var response = await client.PostAsync(requestUri, content);

                    if (response.IsSuccessStatusCode)
                    {
                        return await response.Content.ReadAsStringAsync();
                    }

                    // Non-success considered failure
                    if (attempt == maxRetries)
                    {
                        string responseBody = await response.Content.ReadAsStringAsync();
                        throw new Exception($"Lead API failed with status {(int)response.StatusCode} {response.ReasonPhrase}: {responseBody}");
                    }
                }
                catch (TaskCanceledException) when (attempt < maxRetries)
                {
                    // timeout or cancellation - retry
                }
                catch (System.Net.Http.HttpRequestException) when (attempt < maxRetries)
                {
                    // transient network failure - retry
                }

                // Exponential backoff with jitter
                int delayMs = (int)(baseDelayMs * Math.Pow(2, attempt - 1));
                int jitter = Random.Shared.Next(0, baseDelayMs);
                await Task.Delay(delayMs + jitter);
            }

            throw new Exception("Lead API request failed after retries.");
        }

        private async Task SendToEventHubAsync(string jsonBody, ILogger log)
        {
            try
            {
                using EventDataBatch batch = await _eventHubProducer.CreateBatchAsync();
                var eventData = new EventData(Encoding.UTF8.GetBytes(jsonBody));

                if (!batch.TryAdd(eventData))
                {
                    // Payload too large for batch; send as a single event
                    await _eventHubProducer.SendAsync(new[] { eventData });
                    return;
                }

                await _eventHubProducer.SendAsync(batch);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Failed to write to Event Hub.");
                throw;
            }
        }

        private static async Task<T?> ParseRequest<T>(HttpRequestData req, ILogger log, string errorMessage)
        {
            try
            {
                string bodyString = await new StreamReader(req.Body).ReadToEndAsync();
                return JsonConvert.DeserializeObject<T>(bodyString);
            }
            catch (Exception ex)
            {
                log.LogError(ex, errorMessage);
                return default;
            }
        }

        private static async Task<HttpResponseData> CreateJsonResponse(HttpRequestData req, HttpStatusCode statusCode, object obj)
        {
            var response = req.CreateResponse(statusCode);
            response.Headers.Add("Content-Type", "application/json");
            await response.WriteStringAsync(JsonConvert.SerializeObject(obj));
            return response;
        }
    }

    public class AuthRequest { public string? ip { get; set; } public string? timestamp { get; set; } }
    public class AuthHeaders { public string? AuthorizationToken { get; set; } public string? AuthorizationId { get; set; } }
    public class LeadRequest { public LeadId? Id { get; set; } public string? Val { get; set; } }
    public class LeadId { public string? Sequence { get; set; } public string? Source { get; set; } public string? Name { get; set; } }
}
