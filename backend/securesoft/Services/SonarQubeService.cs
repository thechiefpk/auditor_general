using System;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using ComplianceSecurityAuditor.Models;
using ComplianceSecurityAuditor.Data;

namespace ComplianceSecurityAuditor.Services
{
    public class SonarQubeService
    {
        private readonly HttpClient _httpClient;

        public SonarQubeService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<bool> RunAnalysisAsync(string projectPath, string projectKey, string token, string hostUrl, string jobId, IScanProgressRepository progressRepo)
        {
            // 1. Begin
            await progressRepo.UpdateAsync(jobId, "Preparing", "Initializing SonarScanner...", 0, 0, 0, 0);
            await RunCommandAsync("dotnet", $"sonarscanner begin /k:\"{projectKey}\" /d:sonar.host.url=\"{hostUrl}\" /d:sonar.token=\"{token}\"", projectPath);

            // 2. Build
            await progressRepo.UpdateAsync(jobId, "Building", "Building Project...", 0, 0, 0, 0);
            await RunCommandAsync("dotnet", "build", projectPath);

            // 3. End
            await progressRepo.UpdateAsync(jobId, "Analyzing", "Finalizing Analysis...", 0, 0, 0, 0);
            await RunCommandAsync("dotnet", $"sonarscanner end /d:sonar.token=\"{token}\"", projectPath);

            return true;
        }

        private async Task RunCommandAsync(string fileName, string arguments, string workingDirectory)
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = psi };
            
            var outputBuilder = new StringBuilder();
            var errorBuilder = new StringBuilder();

            process.OutputDataReceived += (s, e) => { if (e.Data != null) outputBuilder.AppendLine(e.Data); };
            process.ErrorDataReceived += (s, e) => { if (e.Data != null) errorBuilder.AppendLine(e.Data); };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            await process.WaitForExitAsync();

            if (process.ExitCode != 0)
            {
                throw new Exception($"Command failed: {fileName} {arguments}\nError: {errorBuilder}\nOutput: {outputBuilder}");
            }
        }

        public async Task<string> GetIssuesAsync(string projectKey, string hostUrl, string token)
        {
            // Prepare request to SonarQube API
            var requestUrl = $"{hostUrl.TrimEnd('/')}/api/issues/search?componentKeys={projectKey}&ps=500";
            
            var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
            var authString = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{token}:"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", authString);

            var response = await _httpClient.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                throw new Exception($"Failed to fetch issues: {response.ReasonPhrase}");
            }

            return await response.Content.ReadAsStringAsync();
        }
    }
}
