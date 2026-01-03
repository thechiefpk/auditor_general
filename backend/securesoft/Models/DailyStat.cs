namespace ComplianceSecurityAuditor.Models
{
    public class DailyStat
    {
        public string Date { get; set; } // YYYY-MM-DD
        public int ScanCount { get; set; }
        public int ViolationCount { get; set; }
        public decimal DollarsSaved { get; set; }
    }
}
