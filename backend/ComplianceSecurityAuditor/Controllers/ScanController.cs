using Microsoft.AspNetCore.Mvc;

namespace ComplianceAuditor.Controllers
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

        [HttpPost("scan")]
        [Consumes("application/json")]
		public IActionResult ScanJson([FromBody] ScanRequest request)
        {
            if (request is null || string.IsNullOrWhiteSpace(request.Path))
                return BadRequest(new { error = "Request body must contain a non-empty 'path' field." });

            var path = NormalizePath(request.Path, out var normalizeError);
            if (normalizeError is not null)
                return BadRequest(new { error = normalizeError });

            if (!Directory.Exists(path) && !System.IO.File.Exists(path))
                return BadRequest(new { error = "Path does not exist.", path });

            var summary = _complianceService.Scan(path);
            return Ok(summary);
        }

        private static string NormalizePath(string raw, out string? error)
        {
            error = null;
            if (string.IsNullOrWhiteSpace(raw))
            {
                error = "Path is empty.";
                return string.Empty;
            }

            try
            {
                // GetFullPath will resolve relative paths and will throw on invalid characters.
                return Path.GetFullPath(raw);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException)
            {
                error = $"Provided path is invalid: {ex.Message}";
                return string.Empty;
            }
        }
    }
}
