using ComplianceSecurityAuditor.Models;
using System.Threading.Tasks;

namespace ComplianceSecurityAuditor.Data
{
    public interface IScanProgressRepository
    {
        Task StartAsync(string jobId, Guid userId, string stage, string hangfireId);
        Task UpdateAsync(string jobId, string status, string stage, int totalFiles, int processedFiles, int violationsFound, int percentage);
        Task CompleteAsync(string jobId, Guid reportId);
        Task FailAsync(string jobId, string error);
        Task<ScanProgress?> GetAsync(string jobId);
        Task RequestCancelAsync(string jobId);
        Task<bool> IsCancelRequestedAsync(string jobId);
        Task UpdateProcessIdAsync(string jobId, int processId);
        Task<int?> GetProcessIdAsync(string jobId);
        Task<int> GetActiveCountAsync(Guid userId);
        Task MarkCancelledAsync(string jobId, Guid reportId);
    }
}
