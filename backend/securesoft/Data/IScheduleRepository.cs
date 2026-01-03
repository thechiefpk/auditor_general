using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using ComplianceSecurityAuditor.Models;

namespace ComplianceSecurityAuditor.Data
{
    public interface IScheduleRepository
    {
        Task<ScanSchedule> CreateAsync(ScanSchedule schedule);
        Task<IEnumerable<ScanSchedule>> GetByUserIdAsync(Guid userId);
        Task<ScanSchedule?> GetByIdAsync(Guid id);
        Task DeleteAsync(Guid id);
        Task UpdateAsync(ScanSchedule schedule);
        Task<IEnumerable<ScanSchedule>> GetDueSchedulesAsync();
        Task UpdateExecutionAsync(Guid id, DateTime lastRun, DateTime nextRun);
        Task UpdateLastRunAsync(Guid id, DateTime lastRun);
        Task AddExecutionHistoryAsync(ScanExecutionHistory history);
        Task<IEnumerable<ScanExecutionHistory>> GetHistoryAsync(Guid scheduleId);
    }
}
