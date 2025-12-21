using ComplianceSecurityAuditor.Data;
using ComplianceSecurityAuditor.Models;
using Hangfire;
using System.Diagnostics;

namespace ComplianceSecurityAuditor.Services
{
    public class ScanJobService
    {
        private readonly ComplianceService _compliance;
        private readonly ISqlReportRepository _repo;
        private readonly IScanProgressRepository _progress;
        private readonly PrivadoScanner _privado;

        public ScanJobService(ComplianceService compliance, ISqlReportRepository repo, IScanProgressRepository progress, PrivadoScanner privado)
        {
            _compliance = compliance;
            _repo = repo;
            _progress = progress;
            _privado = privado;
        }

        public async Task RunLocalScan(string jobId, Guid userId, string path, bool isAdvanced = false)
        {
            try
            {
                var summary = await _compliance.ScanWithProgressAsync(userId, path, _progress, jobId);

                if (isAdvanced)
                {
                    await _progress.UpdateAsync(jobId, "Deep Scan", "Running Advanced Analysis (Privado)...", 0, 0, 0, 0);
                    var privadoViolations = await _privado.RunScanAsync(path, jobId);
                    summary.Violations.AddRange(privadoViolations);
                    summary.ViolationsFound += privadoViolations.Count;
                }

                var reportId = await _repo.SaveReportAsync(userId, path, summary);
                var cancelRequested = await _progress.IsCancelRequestedAsync(jobId);
                if (cancelRequested)
                {
                    await _progress.MarkCancelledAsync(jobId, reportId);
                }
                else
                {
                    await _progress.CompleteAsync(jobId, reportId);
                }
            }
            catch (Exception ex)
            {
                await _progress.FailAsync(jobId, ex.Message);
            }
        }

        public async Task RunGitScan(string jobId, Guid userId, string repoUrl, string? branch, string? accessToken, bool isAdvanced = false)
        {
            string? tempDirectory = null;
            try
            {
                await _progress.UpdateAsync(jobId, "Cloning", "Cloning Repository...", 0, 0, 0, 0);
                tempDirectory = Path.Combine(Path.GetTempPath(), $"securesoft_scan_{Guid.NewGuid()}");
                Directory.CreateDirectory(tempDirectory);
                var cloned = await CloneRepositoryAsync(repoUrl, tempDirectory, jobId, branch, accessToken);
                if (!cloned)
                {
                    var isCancelled = await _progress.IsCancelRequestedAsync(jobId);
                    if (isCancelled)
                    {
                         await _progress.MarkCancelledAsync(jobId, Guid.Empty);
                         return;
                    }
                    await _progress.FailAsync(jobId, "Clone failed");
                    return;
                }

                // Check cancellation right after cloning
                if (await _progress.IsCancelRequestedAsync(jobId))
                {
                     await _progress.MarkCancelledAsync(jobId, Guid.Empty);
                     return;
                }

                await _progress.UpdateAsync(jobId, "Scanning", "Scanning Files...", 0, 0, 0, 0);
                
                // Pass a cancellation token source linked to a timeout for scanning activity
                // But since ScanWithProgressAsync manages its own loop, we'll rely on it updating 'UpdatedAt' frequently.
                // The GetProgress endpoint handles the passive timeout (if the job dies).
                // Here we just ensure we respect the user cancellation.
                
                var summary = await _compliance.ScanWithProgressAsync(userId, tempDirectory, _progress, jobId);
                summary.RepositoryUrl = repoUrl;
                summary.Branch = branch ?? "default";

                if (isAdvanced)
                {
                    await _progress.UpdateAsync(jobId, "Deep Scan", "Running Advanced Analysis (Privado)...", 0, 0, 0, 0);
                    var privadoViolations = await _privado.RunScanAsync(tempDirectory, jobId);
                    summary.Violations.AddRange(privadoViolations);
                    summary.ViolationsFound += privadoViolations.Count;
                }

                var reportId = await _repo.SaveReportAsync(userId, tempDirectory, summary);
                var cancelRequested = await _progress.IsCancelRequestedAsync(jobId);
                if (cancelRequested)
                {
                    await _progress.MarkCancelledAsync(jobId, reportId);
                }
                else
                {
                    await _progress.CompleteAsync(jobId, reportId);
                }
            }
            catch (Exception ex)
            {
                await _progress.FailAsync(jobId, ex.Message);
            }
            finally
            {
                if (tempDirectory != null && Directory.Exists(tempDirectory))
                {
                    try { Directory.Delete(tempDirectory, true); } catch { }
                }
            }
        }

        private async Task<bool> CloneRepositoryAsync(string repoUrl, string targetPath, string jobId, string? branch = null, string? accessToken = null)
        {
            try
            {
                var cloneUrl = repoUrl;
                if (!string.IsNullOrWhiteSpace(accessToken) && repoUrl.StartsWith("https://"))
                {
                    var uri = new Uri(repoUrl);
                    cloneUrl = $"https://{accessToken}@{uri.Host}{uri.PathAndQuery}";
                }
                var arguments = $"clone --depth 1 --single-branch";
                if (!string.IsNullOrWhiteSpace(branch))
                    arguments += $" --branch {branch}";
                arguments += $" \"{cloneUrl}\" \"{targetPath}\"";
                var psi = new ProcessStartInfo
                {
                    FileName = "git",
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                
                // Disable interactive prompts
                psi.EnvironmentVariables["GIT_TERMINAL_PROMPT"] = "0";
                psi.EnvironmentVariables["GCM_INTERACTIVE"] = "never";
                // Override credential helper to ensure only provided token is used
                arguments = $"-c credential.helper= {arguments}";
                psi.Arguments = arguments;

                using var process = new Process { StartInfo = psi };
                process.Start();

                // Poll for exit or cancellation
                var stopwatch = Stopwatch.StartNew();
                while (!process.HasExited)
                {
                    if (stopwatch.ElapsedMilliseconds > 120000) // 2 minutes timeout (reduced from 5)
                    {
                        process.Kill();
                        return false;
                    }

                    if (await _progress.IsCancelRequestedAsync(jobId))
                    {
                        try { process.Kill(); } catch { }
                        return false;
                    }

                    await Task.Delay(500);
                }

                return process.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }
    }
}
