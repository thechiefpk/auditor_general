using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using SecureSoftAPI.Data;
using ComplianceSecurityAuditor.Data;
using System.Threading.Tasks;
using System;
using System.Linq;
using System.Security.Claims;

namespace SecureSoftAPI.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class StatsController : ControllerBase
    {
        private readonly ISqlReportRepository _repo;

        public StatsController(ISqlReportRepository repo)
        {
            _repo = repo;
        }

        [HttpGet("daily")]
        public async Task<IActionResult> GetDailyStats()
        {
            try
            {
                var userId = GetCurrentUserId();
                var stats = await _repo.GetDailyStatsAsync(userId);
                return Ok(stats);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }

        private Guid GetCurrentUserId()
        {
            var claim = User.FindFirst(ClaimTypes.NameIdentifier);
            if (claim == null) throw new UnauthorizedAccessException("User not found");
            return Guid.Parse(claim.Value);
        }
    }
}