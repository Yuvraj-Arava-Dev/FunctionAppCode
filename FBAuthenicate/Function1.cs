using Azure.Core;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json; // ✅ Added Newtonsoft.Json
using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace FBAuthenticate.Controllers
{
    public class AuthController
    {
        private readonly IMemoryCache _cache;
        private readonly TimeSpan _expiry;

        public AuthController(IMemoryCache cache, IConfiguration config)
        {
            _cache = cache;

            double hours = config.GetValue<double>("TokenExpiryHours", 24);
            _expiry = TimeSpan.FromHours(hours);
        }

        [Function("FBAutenticate")]
        public async Task<HttpResponseData> FBAutenticate(
            [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req, ILogger log)
        {
            AuthRequest? request;
            try
            {
                // Read body as string and use Newtonsoft.Json
                var bodyString = await new System.IO.StreamReader(req.Body).ReadToEndAsync();
                request = JsonConvert.DeserializeObject<AuthRequest>(bodyString);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Failed to parse request body");
                var badResp = req.CreateResponse(HttpStatusCode.BadRequest);
                badResp.Headers.Add("Content-Type", "application/json");
                await badResp.WriteStringAsync(JsonConvert.SerializeObject(new { message = "Invalid JSON" }));
                return badResp;
            }

            if (request == null || string.IsNullOrEmpty(request.ip) || string.IsNullOrEmpty(request.timestamp))
            {
                var badResp = req.CreateResponse(HttpStatusCode.BadRequest);
                badResp.Headers.Add("Content-Type", "application/json");
                await badResp.WriteStringAsync(JsonConvert.SerializeObject(new { message = "IP and timestamp required" }));
                return badResp;
            }

            string tokenCacheKey = $"fbt-{request.ip}-token";

            if (!_cache.TryGetValue(tokenCacheKey, out string token))
            {
                token = GenerateToken(request.ip, request.timestamp);
                _cache.Set(tokenCacheKey, token, _expiry);

                var keys = _cache.GetOrCreate("token-keys", e => new HashSet<string>());

                if (!keys.Contains(tokenCacheKey))
                {
                    keys.Add(tokenCacheKey);
                }
            }

            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteStringAsync(JsonConvert.SerializeObject(new { token }));
            return response;
        }

        [Function("ListTokens")]
        public async Task<HttpResponseData> ListTokens(
            [HttpTrigger(AuthorizationLevel.Function, "get")] HttpRequestData req)
        {
            var result = new Dictionary<string, string>();

            if (_cache.TryGetValue("token-keys", out HashSet<string> keys))
            {
                foreach (var key in keys)
                {
                    if (_cache.TryGetValue(key, out string token))
                    {
                        result[key] = token;
                    }
                }
            }

            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteStringAsync(JsonConvert.SerializeObject(result));
            return response;
        }

        [Function("SubmitLead")]
        public async Task<HttpResponseData> SubmitLead(
            [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req,
            ILogger log)
        {
            // Extract headers safely into AuthHeaders
            var authHeaders = new AuthHeaders
            {
                AuthorizationToken = req.Headers.TryGetValues("AuthorizationToken", out var tokenValues)
                    ? tokenValues.FirstOrDefault()
                    : null,
                AuthorizationId = req.Headers.TryGetValues("AuthorizationId", out var idValues)
                    ? idValues.FirstOrDefault()
                    : null
            };

            if (string.IsNullOrEmpty(authHeaders.AuthorizationToken) || string.IsNullOrEmpty(authHeaders.AuthorizationId))
            {
                log.LogWarning("Missing required headers");
                var badResp = req.CreateResponse(HttpStatusCode.BadRequest);
                badResp.Headers.Add("Content-Type", "application/json");
                await badResp.WriteStringAsync(JsonConvert.SerializeObject(new { message = "Missing Authorization headers" }));
                return badResp;
            }

            // Extract body into LeadRequest object
            LeadRequest? body;
            try
            {
                var bodyString = await new StreamReader(req.Body).ReadToEndAsync();
                body = JsonConvert.DeserializeObject<LeadRequest>(bodyString);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Failed to parse request body");
                var badResp = req.CreateResponse(HttpStatusCode.BadRequest);
                badResp.Headers.Add("Content-Type", "application/json");
                await badResp.WriteStringAsync(JsonConvert.SerializeObject(new { message = "Invalid JSON body" }));
                return badResp;
            }

            if (body == null || body.Id == null || string.IsNullOrEmpty(body.Val))
            {
                var badResp = req.CreateResponse(HttpStatusCode.BadRequest);
                badResp.Headers.Add("Content-Type", "application/json");
                await badResp.WriteStringAsync(JsonConvert.SerializeObject(new { message = "Body is missing required fields" }));
                return badResp;
            }

            string ipAddress = DecryptHeaderValue(authHeaders.AuthorizationId);
            string token = authHeaders.AuthorizationToken;
            string tokenCacheKey = $"fbt-{ipAddress}-token";
            string cachedToken = _cache.TryGetValue(tokenCacheKey, out string cachedValue) ? cachedValue : null;

            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(cachedToken) || cachedToken != token)
            {
                var forbiddenResp = req.CreateResponse(HttpStatusCode.Forbidden);
                forbiddenResp.Headers.Add("Content-Type", "application/json");
                await forbiddenResp.WriteStringAsync(JsonConvert.SerializeObject(new { Message = "Invalid or expired token." }));
                return forbiddenResp;
            }

            // Fix: Declare and initialize xmlRequestBody
            string xmlRequestBody = ConvertJsonToXml(JsonConvert.SerializeObject(body));

            // Example response (you can modify this as needed)
            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteStringAsync(JsonConvert.SerializeObject(new
            {
                message = "Headers and body processed successfully",
                headers = authHeaders,
                body,
                xmlRequestBody
            }));
            return response;
        }
        private string GenerateToken(string ip, string timestamp)
        {
            var data = $"{ip}-{timestamp}";
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
            return Convert.ToBase64String(bytes);
        }
        public static string DecryptHeaderValue(string encryptedHeader)
        {
            // Split the encrypted header into IV and Encrypted data (separated by ":")
            var parts = encryptedHeader.Split(':');
            if (parts.Length != 2)
            {
                throw new ArgumentException("Invalid encrypted header format.");
            }
            try
            {
                // Decode the Base64-encoded IV and encrypted data
                byte[] iv = Convert.FromBase64String(parts[0]);
                byte[] encryptedData = Convert.FromBase64String(parts[1]);
                // Convert the secret key into a byte array
                byte[] key = Encoding.UTF8.GetBytes("ASDFGHJKLASDFGHJASDFGHJKLASDFGHJ");
                // AES-GCM Decryption
                if (key.Length != 32)
                {
                    throw new ArgumentException("The secret key must be 32 bytes.");
                }
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = key;
                    aesAlg.IV = iv;
                    aesAlg.Mode = CipherMode.CBC;
                    aesAlg.Padding = PaddingMode.PKCS7;

                    // Create a decryptor to perform the decryption
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    // Decrypt the data
                    using (MemoryStream msDecrypt = new MemoryStream(encryptedData))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                return srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                return "Invalid IP";
            }
        }
        public static string ConvertJsonToXml(string json)
        {
            try
            {
                // Convert JSON to XmlDocument
                XmlDocument xmlDoc = JsonConvert.DeserializeXmlNode(json, "root");

                // Return the XML string with indentation
                return xmlDoc.OuterXml;
            }
            catch (Exception ex)
            {
                // Handle any parsing errors
                return $"<error>{System.Security.SecurityElement.Escape(ex.Message)}</error>";
            }
        }
    }

    public class AuthRequest
    {
        public string? ip { get; set; }
        public string? timestamp { get; set; }
    }
    public class AuthHeaders
    {
        public string? AuthorizationToken { get; set; }
        public string? AuthorizationId { get; set; }
    }
    public class LeadRequest
    {
        public LeadId? Id { get; set; }
        public string? Val { get; set; }
    }

    public class LeadId
    {
        public string? Sequence { get; set; }
        public string? Source { get; set; }
        public string? Name { get; set; }
    }
}
