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

        // Files and patterns to ignore during scanning
        private readonly HashSet<string> _ignoredFileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".gitignore",
            ".git",
            ".vs",
            ".idea",
            "node_modules"
        };

        private readonly HashSet<string> _ignoredExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".db",
            ".sqlite",
            ".lock",
            ".log",
            ".DB",
            ".dbmdl",
            ".sqlproj",
            ".sln"
        };

        private readonly List<string> _ignoredPathPatterns = new List<string>
        {
            "\\.vs\\",
            "\\node_modules\\",
            "\\bin\\",
            "\\obj\\",
            "\\.git\\",
            "CopilotIndices",
            "CodeChunks"
        };

        public ComplianceService(ISqlReportRepository repo = null)
        {
            _fileScanner = new FileScanner();
            var rules = RuleRegistry.GetRules();
            _validationEngine = new ValidationEngine(rules);
            _repo = repo;
        }

        private bool ShouldIgnoreFile(string filePath)
        {
            var fileName = Path.GetFileName(filePath);
            var extension = Path.GetExtension(filePath);

            // Check if filename should be ignored
            if (_ignoredFileNames.Contains(fileName))
                return true;

            // Check if extension should be ignored
            if (_ignoredExtensions.Contains(extension))
                return true;

            // Check if path contains ignored patterns
            foreach (var pattern in _ignoredPathPatterns)
            {
                if (filePath.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        public ScanSummary Scan(Guid userid, string path)
        {
            var allViolations = new List<Violation>();
            var allFiles = _fileScanner.FindFiles(path).ToList();

            // Filter out ignored files
            var files = allFiles.Where(f => !ShouldIgnoreFile(f)).ToList();

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
            var allFiles = _fileScanner.FindFiles(path).ToList();
            var files = allFiles.Where(f => !ShouldIgnoreFile(f)).ToList();
            var total = files.Count;
            var processed = 0;
            await progressRepo.UpdateAsync(jobId, "Scanning", "Scanning", total, processed, 0, 0);
            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) break;
                if (await progressRepo.IsCancelRequestedAsync(jobId)) break;
                var violations = _validationEngine.ScanFile(file);
                allViolations.AddRange(violations);
                processed++;
                var percentage = total == 0 ? 100 : (int)Math.Min(100, Math.Round((double)processed * 100 / total));
                await progressRepo.UpdateAsync(jobId, "Scanning", "Scanning", total, processed, allViolations.Count, percentage);
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
