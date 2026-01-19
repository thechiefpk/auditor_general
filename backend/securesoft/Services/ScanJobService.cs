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
        private readonly SqlScanner _sqlScanner;
        private readonly NetworkAuditService _networkAuditService;
        private readonly AdvancedScanPipeline _advancedPipeline;

        public ScanJobService(ComplianceService compliance, ISqlReportRepository repo, IScanProgressRepository progress, IScheduleRepository scheduleRepo, SqlScanner sqlScanner, NetworkAuditService networkAuditService, AdvancedScanPipeline advancedPipeline)
        {
            _compliance = compliance;
            _repo = repo;
            _progress = progress;
            _scheduleRepo = scheduleRepo;
            _sqlScanner = sqlScanner;
            _networkAuditService = networkAuditService;
            _advancedPipeline = advancedPipeline;
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
                if (isAdvanced)
                {
                    await _progress.UpdateAsync(jobId, "Deep Scan", "Running Advanced Analysis Pipeline...", 0, 0, 0, 0);
                    var advancedSummary = await _advancedPipeline.RunAsync(userId, path, jobId);
                    var advancedReportId = await _repo.SaveReportAsync(userId, path, advancedSummary);
                    var advancedCancelRequested = await _progress.IsCancelRequestedAsync(jobId);
                    if (advancedCancelRequested)
                    {
                        await _progress.MarkCancelledAsync(jobId, advancedReportId);
                    }
                    else
                    {
                        await _progress.CompleteAsync(jobId, advancedReportId);
                        if (scheduleId.HasValue)
                        {
                            await _scheduleRepo.AddExecutionHistoryAsync(new ScanExecutionHistory
                            {
                                Id = Guid.NewGuid(),
                                ScheduleId = scheduleId.Value,
                                ExecutedAt = DateTime.UtcNow,
                                Status = "Success",
                                ResultSummary = advancedReportId.ToString()
                            });
                            await _scheduleRepo.UpdateLastRunAsync(scheduleId.Value, DateTime.UtcNow);
                        }
                    }
                    return;
                }

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

                if (isAdvanced)
                {
                    await _progress.UpdateAsync(jobId, "Deep Scan", "Running Advanced Analysis Pipeline...", 0, 0, 0, 0);
                    var advancedSummary = await _advancedPipeline.RunAsync(userId, tempDirectory, jobId, repoUrl, branch ?? "default");
                    var advancedReportId = await _repo.SaveReportAsync(userId, tempDirectory, advancedSummary);
                    var advancedCancelRequested = await _progress.IsCancelRequestedAsync(jobId);
                    if (advancedCancelRequested)
                    {
                        await _progress.MarkCancelledAsync(jobId, advancedReportId);
                    }
                    else
                    {
                        await _progress.CompleteAsync(jobId, advancedReportId);
                        if (scheduleId.HasValue)
                        {
                            await _scheduleRepo.AddExecutionHistoryAsync(new ScanExecutionHistory
                            {
                                Id = Guid.NewGuid(),
                                ScheduleId = scheduleId.Value,
                                ExecutedAt = DateTime.UtcNow,
                                Status = "Success",
                                ResultSummary = advancedReportId.ToString()
                            });
                            await _scheduleRepo.UpdateLastRunAsync(scheduleId.Value, DateTime.UtcNow);
                        }
                    }
                }
                else
                {
                    await _progress.UpdateAsync(jobId, "Scanning", "Scanning Files...", 0, 0, 0, 0);
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
