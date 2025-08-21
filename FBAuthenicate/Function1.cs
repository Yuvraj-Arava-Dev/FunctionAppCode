using Azure;
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
        private readonly static string RetryJobParamName = "retryJob";

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
            string? retryJobValue = query[RetryJobParamName];
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

            // Parse the request body
            dynamic? body = await ParseRequest<dynamic>(req, log, "Invalid lead request JSON");

            // Prepare JSON and XML forms
            string jsonRequestBody = JsonConvert.SerializeObject(body);
            string xmlRequestBody = ConvertJsonToXml(jsonRequestBody);
            log.LogInformation("Converted lead request body to XML.");

            // Implement pseudo code logic
            bool isSuccess = false;
            string deliver_response_msg_and_status_code = "";
            string leadApiResponse = "";
            HttpStatusCode apiStatusCode = HttpStatusCode.InternalServerError; //null or 200

            try
            {
                // Call API
                var apiResult = await submitLeadToDelivr(_config, xmlRequestBody);
                leadApiResponse = apiResult.Response;
                apiStatusCode = apiResult.StatusCode;
                
                isSuccess = true;
                deliver_response_msg_and_status_code = "";
                log.LogInformation("Lead API response received with status code: {StatusCode}", apiStatusCode);

                // If status code != 100
                if (apiStatusCode != HttpStatusCode.Continue) // Status code 100
                {
                    isSuccess = false;
                    deliver_response_msg_and_status_code = $"Status code: {(int)apiStatusCode}, Response: {leadApiResponse}";
                    log.LogWarning("Lead API returned non-success status code: {StatusCode}", apiStatusCode);
                }
            }
            catch (Exception ex)
            {
                isSuccess = false;
                deliver_response_msg_and_status_code = ex.Message;
                log.LogError(ex, "Exception occurred during Lead API call: {Message}", ex.Message);
            }

            // Handle response based on success status
            if (isSuccess)
            {
                // Respond to API call - 200 - lead received
                return await CreateJsonResponse(req, HttpStatusCode.OK, new { message = "Lead received" });
            }
            else
            {
                // Call failed
                if (!isDatabricksRetry)
                {
                    // Call not from retry job
                    // Add request id and send payload to event hub
                    try
                    {
                        await SendToEventHubAsync(jsonRequestBody, log);
                        log.LogInformation("Payload sent to Event Hub after API failure.");
                        
                        // Respond to user as 200 - lead received
                        return await CreateJsonResponse(req, HttpStatusCode.OK, new { message = "Lead received" });
                    }
                    catch (Exception eventHubEx)
                    {
                        log.LogError(eventHubEx, "Failed to write to Event Hub after API failure.");
                        return await CreateJsonResponse(req, HttpStatusCode.InternalServerError, new
                        {
                            message = "Unknown error from API while writing the failure to eventhub with message " + eventHubEx.ToString()
                        });
                    }
                }
                else
                {
                    // Call from retry job
                    // Respond with 525 + deliver_response_msg_and_status_code (this has to go to retry table in databricks)
                    log.LogWarning("Databricks retry job failed - returning 525 with details: {Details}", deliver_response_msg_and_status_code);
                    return await CreateJsonResponse(req, (HttpStatusCode)525, deliver_response_msg_and_status_code);
                }
            } // manoj - check existing function - no changes to it
        }
        private string GenerateToken(string ip, string timestamp)
        {
            var data = $"{ip}-{timestamp}";
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
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
        public static async Task<(string Response, HttpStatusCode StatusCode)> submitLeadToDelivr(IConfiguration config, string xmlData)
        {
            //int maxRetries = Math.Max(1, config.GetValue<int>("LeadApiMaxRetries", 1));
            //int baseDelayMs = Math.Max(100, config.GetValue<int>("LeadApiBaseDelayMs", 500));
            int timeoutSeconds = Math.Max(5, config.GetValue<int>("LeadApiTimeoutSeconds", 10));

            var authValue = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{config["LeadApiUsername"]}:{config["LeadApiPassword"]}"));
            var requestUri = config["LeadApiUrl"];

            HttpStatusCode respStatusCode = HttpStatusCode.InternalServerError;
            string responseBody = string.Empty;
            HttpResponseMessage response = null;
                try
                {
                    using var client = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(timeoutSeconds) };
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", authValue);

                    var content = new System.Net.Http.StringContent(xmlData, Encoding.UTF8, "application/xml");
                    response = await client.PostAsync(requestUri, content);

                respStatusCode = response.StatusCode;
                responseBody = await response.Content.ReadAsStringAsync();
                return (responseBody, respStatusCode);
                }
                catch (TaskCanceledException)
                {
                // timeout or cancellation - don't retry, let caller handle immediately
                responseBody = "Timeout Exception on calling Delivr API";
                respStatusCode = HttpStatusCode.InternalServerError;
                return (responseBody, respStatusCode);
            }
                catch (System.Net.Http.HttpRequestException)
                {
                    responseBody = "HttpRequest Exception on calling Delivr API";
                    if (response != null && response.StatusCode != null)
                    {
                        respStatusCode = response.StatusCode;
                    } else
                    {
                        respStatusCode = HttpStatusCode.InternalServerError;
                    }
                    return (responseBody, respStatusCode);
            }
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
            //manoj - only status code and message to be there in response
        }
    }

    public class AuthRequest { public string? ip { get; set; } public string? timestamp { get; set; } }
    public class AuthHeaders { public string? AuthorizationToken { get; set; } public string? AuthorizationId { get; set; } }
}