namespace ComplianceSecurityAuditor.Models
{
    public class ScanProgress
    {
        public string JobId { get; set; } = string.Empty;
        public Guid UserId { get; set; }
        public string Status { get; set; } = string.Empty;
        public string Stage { get; set; } = string.Empty;
        public int TotalFiles { get; set; }
        public int ProcessedFiles { get; set; }
        public int ViolationsFound { get; set; }
        public int Percentage { get; set; }
        public Guid? ReportId { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public string? Error { get; set; }
        public string? HangfireId { get; set; }
        public bool CancelRequested { get; set; }
    }
}
