using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using ComplianceSecurityAuditor.Library;

namespace ComplianceSecurityAuditor.Controllers
{
    [ApiController]
    [Route("api/system")]
    public class SystemController : ControllerBase
    {
        [HttpGet("docker-status")]
        public async Task<IActionResult> GetDockerStatus()
        {
            try
            {
                var isRunning = await Utility.IsDockerRunningAsync();
                return Ok(new { isRunning });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        [HttpPost("start-docker")]
        public IActionResult StartDocker()
        {
            try
            {
                var dockerPath = @"C:\Program Files\Docker\Docker\Docker Desktop.exe";
                if (!System.IO.File.Exists(dockerPath))
                {
                    return NotFound(new { error = "Docker Desktop executable not found at default location." });
                }

                Process.Start(new ProcessStartInfo
                {
                    FileName = dockerPath,
                    UseShellExecute = true
                });

                return Ok(new { message = "Docker starting..." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }
    }
}
