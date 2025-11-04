namespace ComplianceSecurityAuditor.Models
{
	public class ScanStatistics
	{
		public Guid ReportId { get; set; }
		public string Path { get; set; }
		public int FilesScanned { get; set; }
		public int ViolationsFound { get; set; }
		public DateTime CreatedAt { get; set; }
		public Dictionary<string, int> ViolationsByCategory { get; set; } = new Dictionary<string, int>();
	}
}