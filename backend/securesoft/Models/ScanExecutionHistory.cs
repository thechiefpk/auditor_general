using System;

namespace ComplianceSecurityAuditor.Models
{
    public class ScanExecutionHistory
    {
        public Guid Id { get; set; }
        public Guid ScheduleId { get; set; }
        public DateTime ExecutedAt { get; set; }
        public string Status { get; set; } // Success, Failed
        public string ResultSummary { get; set; }
        public string ErrorMessage { get; set; }
    }
}
