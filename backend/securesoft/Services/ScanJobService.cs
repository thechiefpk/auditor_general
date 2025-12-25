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
        private readonly SonarQubeService _sonarService;
        private readonly NetworkAuditService _networkAuditService;

        public ScanJobService(ComplianceService compliance, ISqlReportRepository repo, IScanProgressRepository progress, IScheduleRepository scheduleRepo, PrivadoScanner privado, SqlScanner sqlScanner, SonarQubeService sonarService, NetworkAuditService networkAuditService)
        {
            _compliance = compliance;
            _repo = repo;
            _progress = progress;
            _scheduleRepo = scheduleRepo;
            _privado = privado;
            _sqlScanner = sqlScanner;
            _sonarService = sonarService;
            _networkAuditService = networkAuditService;
        }

        public async Task RunNetworkScan(string jobId, Guid userId, string target, Guid? scheduleId = null)
        {
            try
            {
                await _progress.UpdateAsync(jobId, "Scanning", $"Running Network Scan on {target}...", 0, 0, 0, 0);

                var result = await _networkAuditService.ScanWebsiteAsync(target);

                // Map NetworkScanResult to ScanSummary
                var violations = new List<Violation>();
                
                foreach (var missing in result.MissingSecurityHeaders)
                {
                    violations.Add(new Violation
                    {
                        FilePath = target,
                        LineNumber = 0,
                        MatchedText = missing,
                        ViolatedRule = new Audit.AuditRule("NET001", "Missing Security Header", "Network Security", "Missing recommended security header", Audit.AuditSeverity.Medium, "Add the header to server config", null, null)
                    });
                }

                foreach (var pii in result.PiiFindings)
                {
                     violations.Add(new Violation
                    {
                        FilePath = target,
                        LineNumber = 0,
                        MatchedText = pii,
                        ViolatedRule = new Audit.AuditRule("NET002", "PII Exposed", "Privacy", "PII found in response content", Audit.AuditSeverity.High, "Remove PII from response", null, null)
                    });
                }
                
                // Also add open ports as info or violations if critical? 
                // For now, let's keep it simple.

                var summary = new ScanSummary
                {
                    ReportId = Guid.NewGuid(),
                    ScanPath = target,
                    FilesScanned = 1,
                    ViolationsFound = violations.Count,
                    Violations = violations,
                    ScanDate = DateTime.UtcNow
                };

                var reportId = await _repo.SaveReportAsync(userId, target, summary);
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
                }
            }
        }


        public async Task RunSonarScan(string jobId, Guid userId, string projectPath, string projectKey, string token, string hostUrl, Guid? scheduleId = null)
        {
            try
            {
                await _progress.UpdateAsync(jobId, "Preparing", "Initializing SonarQube Scan...", 0, 0, 0, 0);
                
                var success = await _sonarService.RunAnalysisAsync(projectPath, projectKey, token, hostUrl, jobId, _progress);
                
                if (success)
                {
                    await _progress.UpdateAsync(jobId, "Fetching Results", "Retrieving Issues from SonarQube...", 0, 0, 0, 0);
                    var issuesJson = await _sonarService.GetIssuesAsync(projectKey, hostUrl, token);
                    
                    var summary = new ScanSummary
                    {
                        ReportId = Guid.NewGuid(),
                        ScanPath = projectPath,
                        FilesScanned = 1, 
                        ViolationsFound = 0, // We would need to parse issuesJson to get count
                        Violations = new List<Violation>(), // We would need to parse issuesJson
                        ScanDate = DateTime.UtcNow
                    };

                    var reportId = await _repo.SaveReportAsync(userId, projectPath, summary);
                    
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
