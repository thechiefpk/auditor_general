using ComplianceSecurityAuditor.Library;
using ComplianceSecurityAuditor.Models;
using ComplianceSecurityAuditor.Server;

namespace ComplianceSecurityAuditor.Services
{
    public class ComplianceService
    {
        private readonly FileScanner _fileScanner;
        private readonly ValidationEngine _validationEngine;
        private readonly ISqlReportRepository _repo;

        // new ctor with optional repo
        public ComplianceService(ISqlReportRepository repo = null)
        {
            _fileScanner = new FileScanner();
            var rules = RuleRegistry.GetRules();
            _validationEngine = new ValidationEngine(rules);
            _repo = repo;
        }

        public ScanSummary Scan(string path)
        {
            var allViolations = new List<Violation>();
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

            // Auto-save if repository is configured
            if (_repo != null)
            {
                try
                {
                    var id = _repo.SaveReport(path, summary);
                    summary.ReportId = id;
                }
                catch
                {
                    // swallow DB errors to not break scan. Consider logging in real app.
                }
            }

            return summary;
        }

        public Guid ScanAndSave(string path)
        {
            var summary = Scan(path);
            if (_repo == null) throw new InvalidOperationException("Repository not configured.");
            return _repo.SaveReport(path, summary);
        }

        public ScanStatistics GetStatistics(Guid reportId)
        {
            if (_repo == null) throw new InvalidOperationException("Repository not configured.");
            return _repo.GetStatistics(reportId);
        }
    }
}
