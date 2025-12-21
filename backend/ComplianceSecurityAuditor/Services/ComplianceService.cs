using ComplianceSecurityAuditor.Library;
using ComplianceSecurityAuditor.Models;
using ComplianceSecurityAuditor.Data;

namespace ComplianceSecurityAuditor.Services
{
    public class ComplianceService
    {
        private readonly FileScanner _fileScanner;
        private readonly ValidationEngine _validationEngine;
        private readonly ISqlReportRepository _repo;

        public ComplianceService(ISqlReportRepository repo = null)
        {
            _fileScanner = new FileScanner();
            var rules = RuleRegistry.GetRules();
            _validationEngine = new ValidationEngine(rules);
            _repo = repo;
        }

        public ScanSummary Scan(Guid userid, string path)
        {
            var allViolations = new List<Violation>();
            // FileScanner now handles all filtering (ignore lists, allowed extensions)
            var files = _fileScanner.FindFiles(path).ToList();

            foreach (var file in files)
            {
                var violations = _validationEngine.ScanFile(file);
                allViolations.AddRange(violations);
            }

            var summary = new ScanSummary
            {
                FilesScanned = files.Count,
                ViolationsFound = allViolations.Count,
                Violations = allViolations
            };

            if (_repo != null)
            {
                try
                {
                    Task.Run(async () =>
                    {
                        try
                        {
                            var id = await _repo.SaveReportAsync(userid, path, summary);
                            summary.ReportId = id;
                        }
                        catch { }
                    });
                }
                catch { }
            }

            return summary;
        }

        public async Task<ScanSummary> ScanWithProgressAsync(Guid userid, string path, IScanProgressRepository progressRepo, string jobId, CancellationToken ct = default)
        {
            var allViolations = new List<Violation>();
            // FileScanner now handles all filtering
            var files = _fileScanner.FindFiles(path).ToList();
            
            var total = files.Count;
            var processed = 0;
            var percentage = 0;
            await progressRepo.UpdateAsync(jobId, "Scanning", "Scanning", total, processed, 0, 0);
            
            var lastUpdate = DateTime.UtcNow;
            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) break;
                
                // Check cancellation from DB
                if (await progressRepo.IsCancelRequestedAsync(jobId)) break;

                // Check for activity timeout (if loop gets stuck on a single file for > 2 mins, unlikely but good safety)
                if (DateTime.UtcNow.Subtract(lastUpdate).TotalMinutes > 2)
                {
                    // Update heartbeat to prevent stale job detection killing us if we are just slow on a huge file
                    await progressRepo.UpdateAsync(jobId, "Scanning", "Scanning", total, processed, allViolations.Count, percentage);
                    lastUpdate = DateTime.UtcNow;
                }

                var violations = _validationEngine.ScanFile(file);
                allViolations.AddRange(violations);
                processed++;
                var newPercentage = total == 0 ? 100 : (int)Math.Min(100, Math.Round((double)processed * 100 / total));
                
                // Update progress every 1% or every 50 files or if percentage changed
                if (newPercentage > percentage || processed % 50 == 0)
                {
                    percentage = newPercentage;
                    await progressRepo.UpdateAsync(jobId, "Scanning", "Scanning", total, processed, allViolations.Count, percentage);
                    lastUpdate = DateTime.UtcNow;
                }
            }
            var summary = new ScanSummary
            {
                FilesScanned = files.Count,
                ViolationsFound = allViolations.Count,
                Violations = allViolations
            };
            return summary;
        }

        public async Task<Guid> ScanAndSaveAsync(Guid userid, string path)
        {
            var summary = Scan(userid, path);
            if (_repo == null) throw new InvalidOperationException("Repository not configured.");
            return await _repo.SaveReportAsync(userid, path, summary);
        }

        public async Task<ScanStatistics> GetStatisticsAsync(Guid reportId)
        {
            if (_repo == null) throw new InvalidOperationException("Repository not configured.");
            return await _repo.GetStatisticsAsync(reportId);
        }

        public async Task<ScanSummary> GetReportAsync(Guid reportId)
        {
            if (_repo == null) throw new InvalidOperationException("Repository not configured.");
            return await _repo.GetReportAsync(reportId);
        }

        public async Task<PagedResult<Violation>> GetReportViolationsPagedAsync(Guid reportId, int page, int pageSize, string? category = null, string? q = null, string sortBy = "filePath", string sortDir = "asc")
        {
            if (_repo == null) throw new InvalidOperationException("Repository not configured.");
            return await _repo.GetViolationsPagedAsync(reportId, page, pageSize, category, q, sortBy, sortDir);
        }

        public async Task<List<TopFile>> GetTopFilesAsync(Guid reportId, int limit = 10)
        {
            if (_repo == null) throw new InvalidOperationException("Repository not configured.");
            return await _repo.GetTopFilesAsync(reportId, limit);
        }

        public async Task<List<ScanSummary>> GetReportsByUserAsync(Guid userId)
        {
            if (_repo == null) throw new InvalidOperationException("Repository not configured.");
            return await _repo.GetReportsByUserAsync(userId);
        }

        public async Task<bool> DeleteReportAsync(Guid userId, Guid reportId)
        {
            if (_repo == null) throw new InvalidOperationException("Repository not configured.");
            return await _repo.DeleteReportAsync(userId, reportId);
        }

        public async Task<List<Violation>> GetViolationsAllAsync(Guid reportId)
        {
            if (_repo == null) throw new InvalidOperationException("Repository not configured.");
            return await _repo.GetViolationsAllAsync(reportId);
        }
    }
}