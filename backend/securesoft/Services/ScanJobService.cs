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
        private readonly IScheduleRepository _scheduleRepo;
        private readonly PrivadoScanner _privado;
        private readonly SqlScanner _sqlScanner;
        private readonly NetworkAuditService _networkAuditService;

        public ScanJobService(ComplianceService compliance, ISqlReportRepository repo, IScanProgressRepository progress, IScheduleRepository scheduleRepo, PrivadoScanner privado, SqlScanner sqlScanner, NetworkAuditService networkAuditService)
        {
            _compliance = compliance;
            _repo = repo;
            _progress = progress;
            _scheduleRepo = scheduleRepo;
            _privado = privado;
            _sqlScanner = sqlScanner;
            _networkAuditService = networkAuditService;
        }

        public async Task RunNetworkScan(string jobId, Guid userId, string target, Guid? scheduleId = null)
        {
            try
            {
                await _progress.UpdateAsync(jobId, "Scanning", $"Running Network Scan on {target}...", 0, 0, 0, 0);

                var result = await _networkAuditService.ScanWebsiteAsync(target);

                // Save to NetworkAudits table
                await _networkAuditService.SaveScanResultAsync(userId, result);
                var reportId = result.Id;

                await _progress.CompleteAsync(jobId, reportId);

                if (scheduleId.HasValue)
                {
                    await _scheduleRepo.AddExecutionHistoryAsync(new ScanExecutionHistory
                    {
                        Id = Guid.NewGuid(),
                        ScheduleId = scheduleId.Value,
                        ExecutedAt = DateTime.UtcNow,
                        Status = "Success",
                        ResultSummary = reportId.ToString()
                    });
                    await _scheduleRepo.UpdateLastRunAsync(scheduleId.Value, DateTime.UtcNow);
                }
            }
            catch (Exception ex)
            {
                await _progress.FailAsync(jobId, ex.Message);
                if (scheduleId.HasValue)
                {
                    await _scheduleRepo.AddExecutionHistoryAsync(new ScanExecutionHistory
                    {
                        Id = Guid.NewGuid(),
                        ScheduleId = scheduleId.Value,
                        ExecutedAt = DateTime.UtcNow,
                        Status = "Failed",
                        ErrorMessage = ex.Message
                    });
                    await _scheduleRepo.UpdateLastRunAsync(scheduleId.Value, DateTime.UtcNow);
                }
            }
        }




        public async Task RunLocalScan(string jobId, Guid userId, string path, bool isAdvanced = false, Guid? scheduleId = null)
        {
            try
            {
                var summary = await _compliance.ScanWithProgressAsync(userId, path, _progress, jobId);

                if (isAdvanced)
                {
                    await _progress.UpdateAsync(jobId, "Deep Scan", "Running Advanced Analysis (3rd Party)...", 0, 0, 0, 0);
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
                    if (scheduleId.HasValue)
                    {
                        await _scheduleRepo.AddExecutionHistoryAsync(new ScanExecutionHistory
                        {
                            Id = Guid.NewGuid(),
                            ScheduleId = scheduleId.Value,
                            ExecutedAt = DateTime.UtcNow,
                            Status = "Success",
                            ResultSummary = reportId.ToString()
                        });
                        await _scheduleRepo.UpdateLastRunAsync(scheduleId.Value, DateTime.UtcNow);
                    }
                }
            }
            catch (Exception ex)
            {
                await _progress.FailAsync(jobId, ex.Message);
                if (scheduleId.HasValue)
                {
                    await _scheduleRepo.AddExecutionHistoryAsync(new ScanExecutionHistory
                    {
                        Id = Guid.NewGuid(),
                        ScheduleId = scheduleId.Value,
                        ExecutedAt = DateTime.UtcNow,
                        Status = "Failed",
                        ErrorMessage = ex.Message
                    });
                    await _scheduleRepo.UpdateLastRunAsync(scheduleId.Value, DateTime.UtcNow);
                }
            }
        }

        public async Task RunGitScan(string jobId, Guid userId, string repoUrl, string? branch, string? accessToken, bool isAdvanced = false, Guid? scheduleId = null)
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
                    if (scheduleId.HasValue)
                    {
                        await _scheduleRepo.AddExecutionHistoryAsync(new ScanExecutionHistory
                        {
                            Id = Guid.NewGuid(),
                            ScheduleId = scheduleId.Value,
                            ExecutedAt = DateTime.UtcNow,
                            Status = "Failed",
                            ErrorMessage = "Clone failed"
                        });
                        await _scheduleRepo.UpdateLastRunAsync(scheduleId.Value, DateTime.UtcNow);
                    }
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
                    await _progress.UpdateAsync(jobId, "Deep Scan", "Running Advanced Analysis (3rd Party)...", 0, 0, 0, 0);
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
                    if (scheduleId.HasValue)
                    {
                        await _scheduleRepo.AddExecutionHistoryAsync(new ScanExecutionHistory
                        {
                            Id = Guid.NewGuid(),
                            ScheduleId = scheduleId.Value,
                            ExecutedAt = DateTime.UtcNow,
                            Status = "Success",
                            ResultSummary = reportId.ToString()
                        });
                        await _scheduleRepo.UpdateLastRunAsync(scheduleId.Value, DateTime.UtcNow);
                    }
                }
            }
            catch (Exception ex)
            {
                await _progress.FailAsync(jobId, ex.Message);
                if (scheduleId.HasValue)
                {
                    await _scheduleRepo.AddExecutionHistoryAsync(new ScanExecutionHistory
                    {
                        Id = Guid.NewGuid(),
                        ScheduleId = scheduleId.Value,
                        ExecutedAt = DateTime.UtcNow,
                        Status = "Failed",
                        ErrorMessage = ex.Message
                    });
                    await _scheduleRepo.UpdateLastRunAsync(scheduleId.Value, DateTime.UtcNow);
                }
            }
            finally
            {
                if (tempDirectory != null && Directory.Exists(tempDirectory))
                {
                    try { Directory.Delete(tempDirectory, true); } catch { /* ignore */ }
                }
            }
        }

        public async Task RunSqlScan(string jobId, Guid userId, string path, Guid? scheduleId = null)
        {
            try
            {
                await _progress.UpdateAsync(jobId, "Scanning", "Analyzing SQL Files...", 0, 0, 0, 0);
                
                var violations = await _sqlScanner.ScanPathAsync(path);
                
                var summary = new ScanSummary
                {
                    ReportId = Guid.NewGuid(),
                    ScanPath = path,
                    FilesScanned = 1, // Simplified for now
                    ViolationsFound = violations.Count,
                    Violations = violations,
                    ScanDate = DateTime.UtcNow
                };

                var reportId = await _repo.SaveReportAsync(userId, path, summary);
                await _progress.CompleteAsync(jobId, reportId);

                if (scheduleId.HasValue)
                {
                    await _scheduleRepo.AddExecutionHistoryAsync(new ScanExecutionHistory
                    {
                        Id = Guid.NewGuid(),
                        ScheduleId = scheduleId.Value,
                        ExecutedAt = DateTime.UtcNow,
                        Status = "Success",
                        ResultSummary = reportId.ToString()
                    });
                    await _scheduleRepo.UpdateLastRunAsync(scheduleId.Value, DateTime.UtcNow);
                }
            }
            catch (Exception ex)
            {
                await _progress.FailAsync(jobId, ex.Message);
                if (scheduleId.HasValue)
                {
                    await _scheduleRepo.AddExecutionHistoryAsync(new ScanExecutionHistory
                    {
                        Id = Guid.NewGuid(),
                        ScheduleId = scheduleId.Value,
                        ExecutedAt = DateTime.UtcNow,
                        Status = "Failed",
                        ErrorMessage = ex.Message
                    });
                    await _scheduleRepo.UpdateLastRunAsync(scheduleId.Value, DateTime.UtcNow);
                }
            }
        }

        private async Task<bool> CloneRepositoryAsync(string repoUrl, string targetDir, string jobId, string? branch, string? accessToken)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "git",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = targetDir
            };

            // Basic auth insertion if token provided
            var cloneUrl = repoUrl;
            if (!string.IsNullOrEmpty(accessToken))
            {
                // Inject token into URL: https://TOKEN@github.com/user/repo.git
                if (repoUrl.StartsWith("https://"))
                {
                    cloneUrl = repoUrl.Insert(8, $"{accessToken}@");
                }
            }

            var args = $"clone {cloneUrl} .";
            if (!string.IsNullOrEmpty(branch))
            {
                args += $" -b {branch}";
            }

            startInfo.Arguments = args;

            try
            {
                using var process = Process.Start(startInfo);
                if (process == null) return false;

                // Capture output to detect hangs or prompts
                // We'll wait with a timeout
                var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5)); // 5 min timeout for clone
                
                // We can't easily access the process ID for the job table here without async complexity, 
                // but the Controller handles the main 'job' process ID. 
                // This is a child process.

                await process.WaitForExitAsync(cts.Token);
                return process.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }
    }
}
