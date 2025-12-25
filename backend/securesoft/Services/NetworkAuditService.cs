using SecureSoftAPI.Models;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Net.Sockets;
using System.Text.RegularExpressions;

using System.Text.Json;
using System.IO;

namespace ComplianceSecurityAuditor.Services
{
    public class NetworkAuditService
    {
        private readonly HttpClient _httpClient;
        private readonly string _storagePath;

        public NetworkAuditService()
        {
            _storagePath = Path.Combine(Directory.GetCurrentDirectory(), "App_Data", "NetworkReports");
            Directory.CreateDirectory(_storagePath);

            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
                {
                    // We capture certificate details here but return true to allow connection for analysis
                    return true; 
                }
            };
            _httpClient = new HttpClient(handler);
            _httpClient.Timeout = TimeSpan.FromSeconds(120); // Increased to 120s for slow targets
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
        }

        public async Task<NetworkScanResult> ScanWebsiteAsync(string url)
        {
            if (!url.StartsWith("http"))
            {
                url = "https://" + url;
            }

            var result = new NetworkScanResult { Url = url };

            try
            {
                // To capture SSL info, we need to access the request message context or handle it via a custom handler per request.
                // However, HttpClient handles are shared. For simple analysis, we can make a HEAD request first.
                // But capturing the specific cert used for THIS request is tricky with just HttpClient.
                // We will use a separate detailed handshake for SSL if needed, but for now let's try to get what we can.
                
                // Note: To get the actual certificate object used, we might need to use Sockets or a specific callback.
                // For Phase 1, we will focus on Headers and Status. 
                // We can improve SSL extraction in Phase 2 with TcpClient/SslStream.

                var response = await _httpClient.GetAsync(url);
                
                result.StatusCode = (int)response.StatusCode;
                result.StatusReason = response.ReasonPhrase ?? "OK";

                foreach (var header in response.Headers)
                {
                    result.Headers[header.Key] = string.Join(", ", header.Value);
                }
                foreach (var header in response.Content.Headers)
                {
                    result.Headers[header.Key] = string.Join(", ", header.Value);
                }

                AnalyzeHeaders(result);
                
                // Phase 2: PII Detection
                var content = await response.Content.ReadAsStringAsync();
                AnalyzeContent(content, result);

                // Phase 2: Port Scanning
                await ScanPortsAsync(new Uri(url).Host, result);

                // Basic Score Calculation based on Headers
                CalculateScore(result);
            }
            catch (TaskCanceledException)
            {
                result.StatusCode = 0;
                result.StatusReason = "Error: Connection timed out (120s limit). The target might be down or blocking requests.";
            }
            catch (HttpRequestException ex)
            {
                result.StatusCode = 0;
                result.StatusReason = $"Error: Unable to connect. {ex.Message}";
            }
            catch (Exception ex)
            {
                result.StatusCode = 0;
                result.StatusReason = $"Error: {ex.Message}";
            }

            return result;
        }

        public async Task SaveScanResultAsync(Guid userId, NetworkScanResult result)
        {
            var userDir = Path.Combine(_storagePath, userId.ToString());
            Directory.CreateDirectory(userDir);
            
            var filePath = Path.Combine(userDir, $"{result.Id}.json");
            var json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
            
            await File.WriteAllTextAsync(filePath, json);
        }

        public async Task<List<NetworkScanResult>> GetUserScanResultsAsync(Guid userId)
        {
            var userDir = Path.Combine(_storagePath, userId.ToString());
            if (!Directory.Exists(userDir)) return new List<NetworkScanResult>();

            var results = new List<NetworkScanResult>();
            var files = Directory.GetFiles(userDir, "*.json");

            foreach (var file in files)
            {
                try
                {
                    var json = await File.ReadAllTextAsync(file);
                    var result = JsonSerializer.Deserialize<NetworkScanResult>(json);
                    if (result != null) results.Add(result);
                }
                catch { /* Ignore corrupt files */ }
            }

            return results.OrderByDescending(r => r.CreatedAt).ToList();
        }

        private void AnalyzeHeaders(NetworkScanResult result)
        {
            var requiredHeaders = new List<string>
            {
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy"
            };

            foreach (var req in requiredHeaders)
            {
                if (!result.Headers.Keys.Any(k => k.Equals(req, StringComparison.OrdinalIgnoreCase)))
                {
                    result.MissingSecurityHeaders.Add(req);
                }
            }
        }

        private void AnalyzeContent(string html, NetworkScanResult result)
        {
             // Regex patterns for PII
            var patterns = new Dictionary<string, string>
            {
                { "Email Address", @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" },
                { "US Phone Number", @"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b" },
                { "SSN (Potential)", @"\b\d{3}-\d{2}-\d{4}\b" },
                { "API Key (Generic)", @"(?i)(api_key|apikey|access_token|secret)[=:]\s*['""]?[a-zA-Z0-9-_]{20,}['""]?" }
            };

            foreach (var pattern in patterns)
            {
                var matches = Regex.Matches(html, pattern.Value);
                if (matches.Count > 0)
                {
                    // Limit findings to avoid clutter
                    var sample = matches[0].Value;
                    if (sample.Length > 50) sample = sample.Substring(0, 47) + "...";
                    result.PiiFindings.Add($"{pattern.Key} detected (Found {matches.Count}, e.g., '{sample}')");
                }
            }
        }

        private async Task ScanPortsAsync(string host, NetworkScanResult result)
        {
            // Common ports to check
            var portsToCheck = new[] { 21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080 };
            
            var tasks = portsToCheck.Select(async port =>
            {
                using var client = new TcpClient();
                try
                {
                    // Timeout of 2 seconds per port
                    var connectTask = client.ConnectAsync(host, port);
                    var timeoutTask = Task.Delay(2000);
                    
                    if (await Task.WhenAny(connectTask, timeoutTask) == connectTask)
                    {
                        // Connection successful?
                        if (client.Connected)
                        {
                            lock (result.OpenPorts)
                            {
                                result.OpenPorts.Add(port);
                            }
                        }
                    }
                }
                catch
                {
                    // Port is closed or filtered
                }
            });

            await Task.WhenAll(tasks);
            result.OpenPorts.Sort();
        }

        private void CalculateScore(NetworkScanResult result)
        {
            if (result.StatusCode == 0) 
            {
                result.SecurityScore = 0;
                return;
            }

            int score = 100;
            
            // Deduct for missing headers
            score -= result.MissingSecurityHeaders.Count * 10;

            // Deduct for server leakage
            if (result.Headers.ContainsKey("Server") || result.Headers.ContainsKey("X-Powered-By"))
            {
                score -= 10;
            }

            // Deduct for open risky ports (excluding 80/443)
            var riskyPorts = result.OpenPorts.Where(p => p != 80 && p != 443).Count();
            score -= riskyPorts * 15;

            // Deduct for PII
            score -= result.PiiFindings.Count * 20;

            if (score < 0) score = 0;
            
            result.SecurityScore = score;
        }
    }
}
