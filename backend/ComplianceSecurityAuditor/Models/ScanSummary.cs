namespace ComplianceSecurityAuditor.Models
{
    public class ScanSummary
    {
        public int FilesScanned { get; set; }
        public int ViolationsFound { get; set; }
        public List<Violation> Violations { get; set; }
        // When saved to DB, this will contain the report id; null if not saved.
        public Guid? ReportId { get; set; }
    }
}
