using Microsoft.AspNetCore.Mvc;
using ComplianceSecurityAuditor.Data;
using ComplianceSecurityAuditor.Models;
using ComplianceSecurityAuditor.Services;
using Hangfire;
using System.Security.Claims;
using System;
using System.Threading.Tasks;
using System.Text.Json;

namespace ComplianceSecurityAuditor.Controllers
{
    [ApiController]
    [Route("api/schedules")]
    public class ScheduleController : ControllerBase
    {
        private readonly IScheduleRepository _repo;
        private readonly IScanProgressRepository _progressRepo;

        public ScheduleController(IScheduleRepository repo, IScanProgressRepository progressRepo)
        {
            _repo = repo;
            _progressRepo = progressRepo;
        }

        [HttpGet]
        public async Task<IActionResult> GetSchedules()
        {
            try
            {
                var userId = GetCurrentUserId();
                var schedules = await _repo.GetByUserIdAsync(userId);
                return Ok(schedules);
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetSchedule(Guid id)
        {
            try
            {
                var userId = GetCurrentUserId();
                var schedule = await _repo.GetByIdAsync(id);
                if (schedule == null) return NotFound();
                if (schedule.UserId != userId) return Unauthorized();
                return Ok(schedule);
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }
        }

        [HttpGet("{id}/history")]
        public async Task<IActionResult> GetHistory(Guid id)
        {
            try
            {
                var userId = GetCurrentUserId();
                var schedule = await _repo.GetByIdAsync(id);
                if (schedule == null) return NotFound();
                if (schedule.UserId != userId) return Unauthorized();

                var history = await _repo.GetHistoryAsync(id);
                return Ok(history);
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateSchedule(Guid id, [FromBody] ScanSchedule updatedSchedule)
        {
            try
            {
                var userId = GetCurrentUserId();
                var schedule = await _repo.GetByIdAsync(id);
                if (schedule == null) return NotFound();
                if (schedule.UserId != userId) return Unauthorized();

                schedule.Frequency = updatedSchedule.Frequency;
                schedule.StartDate = updatedSchedule.StartDate;
                schedule.EndDate = updatedSchedule.EndDate;
                schedule.IsActive = updatedSchedule.IsActive;
                schedule.ConfigJson = updatedSchedule.ConfigJson;
                schedule.ScanType = updatedSchedule.ScanType;

                await _repo.UpdateAsync(schedule);
                return Ok(schedule);
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }
        }

        [HttpPost]
        public async Task<IActionResult> CreateSchedule([FromBody] ScanSchedule schedule)
        {
            try
            {
                var userId = GetCurrentUserId();
                schedule.Id = Guid.NewGuid();
                schedule.UserId = userId;
                schedule.CreatedAt = DateTime.UtcNow;
                schedule.LastRun = null;
                schedule.IsActive = true;
                
                // If StartDate is in the past, treat it as "Run ASAP" (set NextRun to StartDate, which is < Now)
                // The scheduler picks up anything where NextRun <= Now.
                schedule.NextRun = schedule.StartDate;

                await _repo.CreateAsync(schedule);
                return Ok(schedule);
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }
        }

        [HttpPost("{id}/execute")]
        public async Task<IActionResult> ExecuteSchedule(Guid id)
        {
            try
            {
                var userId = GetCurrentUserId();
                var schedule = await _repo.GetByIdAsync(id);
                
                if (schedule == null) return NotFound(new { error = "Schedule not found" });
                if (schedule.UserId != userId) return Unauthorized();

                var jobId = Guid.NewGuid().ToString("N");
                string hangfireJobId = "";
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

                try
                {
                    switch (schedule.ScanType.ToLower())
                    {
                        case "local":
                            var localReq = JsonSerializer.Deserialize<ScanRequest>(schedule.ConfigJson, options);
                            if (localReq != null)
                            {
                                hangfireJobId = BackgroundJob.Enqueue<ScanJobService>(s => s.RunLocalScan(jobId, schedule.UserId, localReq.Path, localReq.IsAdvanced, schedule.Id));
                            }
                            break;

                        case "git":
                            var gitConfig = JsonSerializer.Deserialize<GitScanRequest>(schedule.ConfigJson, options);
                            if (gitConfig != null)
                            {
                                hangfireJobId = BackgroundJob.Enqueue<ScanJobService>(s => s.RunGitScan(jobId, schedule.UserId, gitConfig.RepositoryUrl, gitConfig.Branch, null, gitConfig.IsAdvanced, schedule.Id));
                            }
                            break;

                        case "sql":
                            var sqlReq = JsonSerializer.Deserialize<ScanRequest>(schedule.ConfigJson, options);
                            if (sqlReq != null)
                            {
                                hangfireJobId = BackgroundJob.Enqueue<ScanJobService>(s => s.RunSqlScan(jobId, schedule.UserId, sqlReq.Path, schedule.Id));
                            }
                            break;
                        
                        case "network":
                            var netConfig = JsonSerializer.Deserialize<NetworkScanConfig>(schedule.ConfigJson, options);
                            if (netConfig != null)
                            {
                                hangfireJobId = BackgroundJob.Enqueue<ScanJobService>(s => s.RunNetworkScan(jobId, schedule.UserId, netConfig.Target, schedule.Id));
                            }
                            break;
                        
                        default:
                            return BadRequest(new { error = "Unknown scan type" });
                    }

                    if (!string.IsNullOrEmpty(hangfireJobId))
                    {
                        await _progressRepo.StartAsync(jobId, schedule.UserId, "Manual Run", hangfireJobId);
                        
                        // We do NOT update NextRun for manual execution, but we should probably update LastRun?
                        // Actually, SchedulerService updates LastRun when it processes. 
                        // If we update LastRun here, it might confuse the user if the scheduled one runs shortly after.
                        // But for "History" purposes, it's just an execution. The history log is what matters.
                        // Let's just return the jobId.
                        return Ok(new { message = "Scan triggered successfully", jobId });
                    }
                    
                    return BadRequest(new { error = "Failed to parse configuration or trigger scan" });
                }
                catch (Exception ex)
                {
                    return StatusCode(500, new { error = ex.Message });
                }
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteSchedule(Guid id)
        {
            try
            {
                 var userId = GetCurrentUserId();
                 var schedule = await _repo.GetByIdAsync(id);
                 if (schedule == null) return NotFound();
                 if (schedule.UserId != userId) return Unauthorized();

                 await _repo.DeleteAsync(id);
                 return Ok();
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }
        }



        private Guid GetCurrentUserId()
        {
            var user = HttpContext?.User;
            if (user?.Identity?.IsAuthenticated != true)
                throw new UnauthorizedAccessException();

            var idClaim = user.FindFirst(ClaimTypes.NameIdentifier) 
                          ?? user.FindFirst("sub")
                          ?? user.FindFirst("user_id")
                          ?? user.FindFirst("userid");
            
            if (idClaim != null && Guid.TryParse(idClaim.Value, out var guid))
                return guid;
                
            throw new UnauthorizedAccessException();
        }

        private class NetworkScanConfig
        {
            public string Target { get; set; }
        }
    }
}
