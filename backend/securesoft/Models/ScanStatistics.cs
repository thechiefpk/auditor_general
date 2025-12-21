namespace ComplianceSecurityAuditor.Models
{
	public class ScanStatistics
	{
		public Guid ReportId { get; set; }
		public string Path { get; set; }
		public int FilesScanned { get; set; }
		public int ViolationsFound { get; set; }
		public double ScanDuration { get; set; }
		public DateTime CreatedAt { get; set; }
		public Dictionary<string, int> ViolationsByCategory { get; set; } = new Dictionary<string, int>();
		public Dictionary<string, int> ViolationsBySeverity { get; set; } = new Dictionary<string, int>();
		public Dictionary<string, int> ViolationsByFileType { get; set; } = new Dictionary<string, int>();
		public List<TopViolation> TopViolations { get; set; } = new List<TopViolation>();
	}

	public class TopViolation
	{
		public string RuleId { get; set; }
		public string RuleName { get; set; }
		public string Category { get; set; }
		public int Count { get; set; }
		public string SuggestiveSolution { get; set; }
		public string ReferenceUrl { get; set; }
	}
}