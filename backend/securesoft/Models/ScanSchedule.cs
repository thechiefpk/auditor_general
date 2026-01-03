using System;

namespace ComplianceSecurityAuditor.Models
{
    public class ScanSchedule
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public string Frequency { get; set; } // Hourly, Daily, Weekly, Monthly
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
        public string ScanType { get; set; } // Local, Git, Sql, Network
        public string ConfigJson { get; set; } // JSON serialized config
        public DateTime? LastRun { get; set; }
        public DateTime NextRun { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
