
namespace ComplianceSecurityAuditor.Models
{
    public class ScanSummary
    {
        public int FilesScanned { get; set; }
        public int ViolationsFound { get; set; }
        public List<Violation> Violations { get; set; }
    }
}
