using Microsoft.AspNetCore.Mvc;
using ComplianceSecurityAuditor.Data;
using ComplianceSecurityAuditor.Models;
using System.Security.Claims;
using System;
using System.Threading.Tasks;

namespace ComplianceSecurityAuditor.Controllers
{
    [ApiController]
    [Route("api/schedules")]
    public class ScheduleController : ControllerBase
    {
        private readonly IScheduleRepository _repo;

        public ScheduleController(IScheduleRepository repo)
        {
            _repo = repo;
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

        [HttpGet("{id}/history")]
        public async Task<IActionResult> GetHistory(Guid id)
        {
            try
            {
                var userId = GetCurrentUserId();
                var schedule = await _repo.GetByIdAsync(id);
                if (schedule == null) return NotFound();
                if (schedule.UserId != userId) return Unauthorized();

                var history = await _repo.GetHistoryByScheduleIdAsync(id);
                return Ok(history);
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
    }
}
