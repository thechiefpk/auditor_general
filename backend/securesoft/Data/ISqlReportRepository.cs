using ComplianceSecurityAuditor.Models;

namespace ComplianceSecurityAuditor.Data
{
	public interface ISqlReportRepository
	{
		Task<Guid> SaveReportAsync(Guid userId, string path, ScanSummary summary);
		Task<ScanStatistics> GetStatisticsAsync(Guid reportId);
		Task<ScanSummary> GetReportAsync(Guid reportId);
		Task<PagedResult<Violation>> GetViolationsPagedAsync(Guid reportId, int page, int pageSize, string? category = null, string? q = null, string sortBy = "filePath", string sortDir = "asc");
		Task<List<TopFile>> GetTopFilesAsync(Guid reportId, int limit = 10);
		Task<List<ScanSummary>> GetReportsByUserAsync(Guid userId);
		Task<bool> DeleteReportAsync(Guid userId, Guid reportId);
		Task<List<Violation>> GetViolationsAllAsync(Guid reportId);
		Task<List<DailyStat>> GetDailyStatsAsync(Guid userId);
		Task<Guid> SaveNetworkAuditAsync(Guid userId, NetworkScanResult result);
		Task<List<NetworkScanResult>> GetNetworkAuditsByUserAsync(Guid userId);
		Task<NetworkScanResult?> GetNetworkAuditByIdAsync(Guid id);
	}
}
