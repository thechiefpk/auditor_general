using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using ComplianceSecurityAuditor.Library;
using ComplianceSecurityAuditor.Models;
using ComplianceSecurityAuditor.Services;
using Microsoft.AspNetCore.Mvc;

namespace ComplianceSecurityAuditor.Controllers
{
    [ApiController]
    [Route("api")]
    public class ScanController : ControllerBase
    {
        private readonly ComplianceService _complianceService;

        public ScanController(ComplianceService complianceService)
        {
            _complianceService = complianceService;
        }

        [HttpPost("scanbyjson")]
        [Consumes("application/json")]
        public IActionResult ScanJson([FromBody] ScanRequest request)
        {
            if (request is null || string.IsNullOrWhiteSpace(request.Path))
                return BadRequest(new { error = "Request body must contain a non-empty 'path' field." });

            var path = Utility.NormalizePath(request.Path, out var normalizeError);
            if (normalizeError is not null)
                return BadRequest(new { error = normalizeError });

            if (!Directory.Exists(path) && !System.IO.File.Exists(path))
                return BadRequest(new { error = "Path does not exist.", path });

            // ComplianceService.Scan will now auto-save the report when a repository is configured.
            var summary = _complianceService.Scan(path);
            return Ok(summary);
        }

        [HttpGet("stats/{id}")]
        public IActionResult GetStats(Guid id)
        {
            try
            {
                var stats = _complianceService.GetStatistics(id);
                return Ok(stats);
            }
            catch (InvalidOperationException ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }
    }
}
