using ComplianceSecurityAuditor.Models;

namespace ComplianceSecurityAuditor.Server
{
	public interface ISqlReportRepository
	{
		Guid SaveReport(string path, ScanSummary summary);
		ScanStatistics GetStatistics(Guid reportId);
	}
}