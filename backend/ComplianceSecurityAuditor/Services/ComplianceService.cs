using ComplianceSecurityAuditor.Library;
using ComplianceSecurityAuditor.Models;

namespace ComplianceSecurityAuditor.Services
{
    public class ComplianceService
    {
        private readonly FileScanner _fileScanner;
        private readonly ValidationEngine _validationEngine;

        public ComplianceService()
        {
            _fileScanner = new FileScanner();
            var rules = RuleRegistry.GetRules();
            _validationEngine = new ValidationEngine(rules);
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

            return new ScanSummary
            {
                FilesScanned = files.Count,
                ViolationsFound = allViolations.Count,
                Violations = allViolations
            };
        }
    }
}
