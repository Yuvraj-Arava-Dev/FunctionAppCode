using Azure.Core;
using Azure.Messaging.EventHubs;
using Azure.Messaging.EventHubs.Producer;
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
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Xml;

namespace FBAuthenticate.Controllers
{
    public class AuthController
    {
        private readonly IMemoryCache _cache;
        private readonly IConfiguration _config;
        private readonly TimeSpan _expiry;
        private readonly EventHubProducerClient _eventHubProducer;

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
        [Function("authenticateFBSubmitLead")]
        public async Task<HttpResponseData> authenticateFBSubmitLead(
    [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req,
    FunctionContext context)
        {
            var log = context.GetLogger<AuthController>();
            log.LogInformation("FBAutenticate triggered.");

            AuthRequest? request = await ParseRequest<AuthRequest>(req, log, "Invalid JSON");

            if (request == null)
            {
                log.LogWarning("Failed to parse request JSON.");
                return await CreateJsonResponse(req, HttpStatusCode.BadRequest, new { message = "Invalid JSON" });
            }

            // Trim only IP address
            var ip = request.ip?.Trim();
            var timestamp = request.timestamp;

            if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(timestamp))
            {
                log.LogWarning("Missing IP or timestamp in request.");
                return await CreateJsonResponse(req, (HttpStatusCode)417, new { message = "IP and timestamp required" });
            }

            string tokenCacheKey = $"fbsl-{ip}-token";
            log.LogInformation("Token cache key computed: {TokenCacheKey}", tokenCacheKey);

            if (!_cache.TryGetValue(tokenCacheKey, out string token))
            {
                token = GenerateToken(ip, timestamp);
                _cache.Set(tokenCacheKey, token, _expiry);

                log.LogInformation("Generated and cached new token for IP {IP}.", ip);
            }
            else
            {
                log.LogInformation("Token retrieved from cache for IP {IP}.", ip);
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
        [Function("fbSubmitLead")]
        public async Task<HttpResponseData> fbSubmitLead(
            [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req,
            FunctionContext context)
        {
            var log = context.GetLogger<AuthController>();
            log.LogInformation("fbSubmitLead triggered.");

            // Check if this is a retry job from Databricks using query parameter
            // Use configurable query parameter name (defaults to "retryJob")
            string retryJobParamName = _config.GetValue<string>("RetryJobParamName", "retryJob");

            // Parse query parameters
            var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
            string? retryJobValue = query[retryJobParamName];
            bool isDatabricksRetry = !string.IsNullOrEmpty(retryJobValue) &&
                                   retryJobValue.ToLowerInvariant() == "true";

            if (isDatabricksRetry)
            {
                log.LogInformation("Detected Databricks retry job (query param: {ParamName}={ParamValue}) - skipping authentication and Event Hub fallback.", retryJobParamName, retryJobValue);
            }

            if (!isDatabricksRetry)
            {
                var authHeaders = new AuthHeaders
                {
                    AuthorizationToken = req.Headers.TryGetValues("AuthorizationToken", out var tokenValues) ? tokenValues.FirstOrDefault() : null,
                    AuthorizationId = req.Headers.TryGetValues("AuthorizationId", out var idValues) ? idValues.FirstOrDefault() : null
                };

                // 417 Expectation Failed - When header values are empty
                if (string.IsNullOrEmpty(authHeaders.AuthorizationToken) || string.IsNullOrEmpty(authHeaders.AuthorizationId))
                {
                    log.LogWarning("Missing Authorization headers.");
                    return await CreateJsonResponse(req, (HttpStatusCode)417, new { message = "Expected header values are missing" });
                }

                // Decrypt header; handle failure explicitly
                string? ipAddress = DecryptHeaderValue(authHeaders.AuthorizationId, log);
                if (string.IsNullOrEmpty(ipAddress))
                {
                    log.LogWarning("Failed to decrypt AuthorizationId header.");
                    return await CreateJsonResponse(req, (HttpStatusCode)401, new { message = "Access Denied" });
                }

                string tokenCacheKey = $"fbsl-{ipAddress.Trim()}-token";
                log.LogInformation("Decrypted IP: {IP}. Checking token with key {Key}", ipAddress, tokenCacheKey);

                // 401 Access Denied - Invalid or expired token
                if (!_cache.TryGetValue(tokenCacheKey, out string cachedToken) || cachedToken != authHeaders.AuthorizationToken)
                {
                    log.LogWarning("Token validation failed for IP: {IP}", ipAddress);
                    return await CreateJsonResponse(req, (HttpStatusCode)401, new { message = "Access Denied" });
                }
            }

            LeadRequest? body = await ParseRequest<LeadRequest>(req, log, "Invalid JSON body");
            if (isDatabricksRetry && body != null)
            {
                log.LogInformation("Databricks retry job detected – removing Id from lead request.");
                body.Id = null;
            }
            if (body == null || string.IsNullOrEmpty(body.Val) || (!isDatabricksRetry && body.Id == null))
            {
                log.LogWarning("Invalid lead request body: missing required fields.");
                return await CreateJsonResponse(req, HttpStatusCode.BadRequest, new { message = "Body is missing required fields" });
            }

            // Prepare JSON and XML forms
            string jsonRequestBody = JsonConvert.SerializeObject(body);
            string xmlRequestBody = ConvertJsonToXml(jsonRequestBody);
            log.LogInformation("Converted lead request body to XML.");

            string leadApiResponse;
            bool apiSucceeded = false;
            Exception? apiException = null;
            HttpStatusCode? apiStatusCode = null;

            try
            {
                var apiResult = await LeadApiRequest(_config, xmlRequestBody);
                leadApiResponse = apiResult.Response;
                apiStatusCode = apiResult.StatusCode;
                apiSucceeded = true;
                log.LogInformation("Lead API response received with status code: {StatusCode}", apiStatusCode);
            }
            // Handle timeout specifically
            catch (TaskCanceledException tex)
            {
                log.LogError(tex, "Timeout occurred during Lead API call.");
                leadApiResponse = string.Empty;
                apiException = tex;

                if (isDatabricksRetry)
                {
                    // 525 Retry Failure - Timeout case
                    return await CreateJsonResponse(req, (HttpStatusCode)525, new
                    {
                        message = "Retry Failure due to timeout",
                        error = tex.Message,
                        isRetryJob = true
                    });
                }

                // For UI requests, write to Event Hub and return success
                try
                {
                    await SendToEventHubAsync(jsonRequestBody, log);
                }
                catch (Exception eventHubEx)
                {
                    log.LogError(eventHubEx, "Failed to write to Event Hub after timeout.");
                    return await CreateJsonResponse(req, HttpStatusCode.InternalServerError, new
                    {
                        message = "Unknown error from API"
                    });
                }

                return await CreateJsonResponse(req, HttpStatusCode.OK, new { message = "Lead received" });
            }
            // Handle socket/network exceptions specifically
            catch (SocketException sockex)
            {
                log.LogError(sockex, "Socket error during Lead API call.");
                leadApiResponse = string.Empty;
                apiException = sockex;

                if (isDatabricksRetry)
                {
                    // 525 Retry Failure - Network/socket case
                    return await CreateJsonResponse(req, (HttpStatusCode)525, new
                    {
                        message = "Retry Failure due to network issue",
                        error = sockex.Message,
                        isRetryJob = true
                    });
                }

                // For UI requests, write to Event Hub and return success
                try
                {
                    await SendToEventHubAsync(jsonRequestBody, log);
                }
                catch (Exception eventHubEx)
                {
                    log.LogError(eventHubEx, "Failed to write to Event Hub after socket error.");
                    return await CreateJsonResponse(req, HttpStatusCode.InternalServerError, new
                    {
                        message = "Unknown error from API"
                    });
                }

                return await CreateJsonResponse(req, HttpStatusCode.OK, new { message = "Lead received" });
            }
            // Handle HTTP request exceptions specifically
            catch (System.Net.Http.HttpRequestException httpEx)
            {
                log.LogError(httpEx, "HTTP request error during Lead API call.");
                leadApiResponse = string.Empty;
                apiException = httpEx;

                if (isDatabricksRetry)
                {
                    // 525 Retry Failure - HTTP request case
                    return await CreateJsonResponse(req, (HttpStatusCode)525, new
                    {
                        message = "Retry Failure due to HTTP request issue",
                        error = httpEx.Message,
                        isRetryJob = true
                    });
                }

                // For UI requests, write to Event Hub and return success
                try
                {
                    await SendToEventHubAsync(jsonRequestBody, log);
                }
                catch (Exception eventHubEx)
                {
                    log.LogError(eventHubEx, "Failed to write to Event Hub after HTTP request error.");
                    return await CreateJsonResponse(req, HttpStatusCode.InternalServerError, new
                    {
                        message = "Unknown error from API"
                    });
                }

                return await CreateJsonResponse(req, HttpStatusCode.OK, new { message = "Lead received" });
            }
            catch (Exception ex)
            {
                leadApiResponse = string.Empty;
                apiException = ex;

                if (isDatabricksRetry)
                {
                    // 525 Retry Failure - For Databricks retry jobs, return failure status with detailed info
                    log.LogError(ex, "Lead API failed for Databricks retry job - returning 525 status.");
                    return await CreateJsonResponse(req, (HttpStatusCode)525, new
                    {
                        message = "Retry Failure with Deliver response status code and response message",
                        error = ex.Message,
                        isRetryJob = true
                    });
                }
                else
                {
                    // For UI requests, write to Event Hub but still return 200 with "Lead received"
                    log.LogError(ex, "Lead API failed after retries; writing payload to Event Hub but returning success to UI.");

                    try
                    {
                        await SendToEventHubAsync(jsonRequestBody, log);
                    }
                    catch (Exception eventHubEx)
                    {
                        log.LogError(eventHubEx, "Failed to write to Event Hub after API failure.");
                        // 500 Internal Server Error - Unknown error from API and Event Hub failure
                        return await CreateJsonResponse(req, HttpStatusCode.InternalServerError, new
                        {
                            message = "Unknown error from API"
                        });
                    }

                    // 200 Success - Lead received (even though API failed, Event Hub succeeded)
                    return await CreateJsonResponse(req, HttpStatusCode.OK, new
                    {
                        message = "Lead received"
                    });
                }
            }

            // Handle successful API responses
            if (isDatabricksRetry)
            {
                // For retry jobs, provide detailed response with status code info
                return await CreateJsonResponse(req, HttpStatusCode.OK, new
                {
                    message = "Lead received",
                    isRetryJob = true,
                    apiStatusCode = (int?)apiStatusCode,
                    response = leadApiResponse
                });
            }
            else
            {
                // 200 Success - Lead received (for UI requests, always return simple success message)
                return await CreateJsonResponse(req, HttpStatusCode.OK, new
                {
                    message = "Lead received"
                });
            }
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

        // Updated to return both response and status code
        public static async Task<(string Response, HttpStatusCode StatusCode)> LeadApiRequest(IConfiguration config, string xmlData)
        {
            int maxRetries = Math.Max(1, config.GetValue<int>("LeadApiMaxRetries", 3));
            int baseDelayMs = Math.Max(100, config.GetValue<int>("LeadApiBaseDelayMs", 500));
            int timeoutSeconds = Math.Max(5, config.GetValue<int>("LeadApiTimeoutSeconds", 30));

            var authValue = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{config["LeadApiUsername"]}:{config["LeadApiPassword"]}"));
            var requestUri = config["LeadApiUrl"];

            HttpStatusCode lastStatusCode = HttpStatusCode.InternalServerError;
            string lastResponseBody = string.Empty;

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    using var client = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(timeoutSeconds) };
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", authValue);

                    var content = new System.Net.Http.StringContent(xmlData, Encoding.UTF8, "application/xml");
                    var response = await client.PostAsync(requestUri, content);

                    lastStatusCode = response.StatusCode;
                    lastResponseBody = await response.Content.ReadAsStringAsync();

                    if (response.StatusCode == HttpStatusCode.Continue) // Status code 100
                    {
                        return (lastResponseBody, lastStatusCode);
                    }

                    // Status code is not 100 - continue to retry logic
                    if (attempt == maxRetries)
                    {
                        throw new Exception($"Lead API failed with status {(int)response.StatusCode} {response.ReasonPhrase}: {lastResponseBody}");
                    }
                }
                catch (TaskCanceledException)
                {
                    // timeout or cancellation - don't retry, let caller handle immediately
                    throw;
                }
                catch (System.Net.Http.HttpRequestException)
                {
                    // network failure - don't retry, let caller handle immediately
                    throw;
                }

                // Exponential backoff with jitter
                int delayMs = (int)(baseDelayMs * Math.Pow(2, attempt - 1));
                int jitter = Random.Shared.Next(0, baseDelayMs);
                await Task.Delay(delayMs + jitter);
            }

            throw new Exception($"Lead API request failed after {maxRetries} retries. Last status: {(int)lastStatusCode}. Last response: {lastResponseBody}");
        }

        private async Task SendToEventHubAsync(string jsonBody, ILogger log)
        {
            try
            {
                // Deserialize incoming JSON into a dynamic object
                var leadData = JsonConvert.DeserializeObject<dynamic>(jsonBody);

                // Wrap with RequestId
                var eventPayload = new
                {
                    LeadData = leadData,
                    RequestId = Guid.NewGuid().ToString()
                };

                // Serialize to JSON string
                string finalJson = JsonConvert.SerializeObject(eventPayload);

                using EventDataBatch batch = await _eventHubProducer.CreateBatchAsync();
                var eventData = new EventData(Encoding.UTF8.GetBytes(finalJson));

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