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

        public ScanJobService(ComplianceService compliance, ISqlReportRepository repo, IScanProgressRepository progress)
        {
            _compliance = compliance;
            _repo = repo;
            _progress = progress;
        }

        public async Task RunLocalScan(string jobId, Guid userId, string path)
        {
            try
            {
                var summary = await _compliance.ScanWithProgressAsync(userId, path, _progress, jobId);
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

        public async Task RunGitScan(string jobId, Guid userId, string repoUrl, string? branch, string? accessToken)
        {
            string? tempDirectory = null;
            try
            {
                tempDirectory = Path.Combine(Path.GetTempPath(), $"securesoft_scan_{Guid.NewGuid()}");
                Directory.CreateDirectory(tempDirectory);
                var cloned = await CloneRepositoryAsync(repoUrl, tempDirectory, branch, accessToken);
                if (!cloned)
                {
                    await _progress.FailAsync(jobId, "Clone failed");
                    return;
                }
                await _progress.UpdateAsync(jobId, "Scanning", "Scanning", 0, 0, 0, 0);
                var summary = await _compliance.ScanWithProgressAsync(userId, tempDirectory, _progress, jobId);
                summary.RepositoryUrl = repoUrl;
                summary.Branch = branch ?? "default";
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

        private async Task<bool> CloneRepositoryAsync(string repoUrl, string targetPath, string? branch = null, string? accessToken = null)
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
                using var process = new Process { StartInfo = psi };
                process.Start();
                var completed = await Task.Run(() => process.WaitForExit(300000));
                if (!completed)
                {
                    process.Kill();
                    return false;
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
