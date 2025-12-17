using ComplianceSecurityAuditor.Library;
using ComplianceSecurityAuditor.Models;
using ComplianceSecurityAuditor.Services;
using ComplianceSecurityAuditor.Data;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Claims;
using System.Linq;
using System.Threading.Tasks;
using Hangfire;

namespace ComplianceSecurityAuditor.Controllers
{
    [ApiController]
    [Route("api")]
    public class ScanController : ControllerBase
    {
        private readonly ComplianceService _complianceService;
        private readonly IScanProgressRepository _progressRepo;
        private readonly PdfReportService _pdfService;

        public ScanController(ComplianceService complianceService, IScanProgressRepository progressRepo, PdfReportService pdfService)
        {
            _complianceService = complianceService;
            _progressRepo = progressRepo;
            _pdfService = pdfService;
        }

        [HttpPost("scan")]
        public IActionResult ScanJson([FromBody] ScanRequest request)
        {
            if (request is null || string.IsNullOrWhiteSpace(request.Path))
                return BadRequest(new { error = "Request body must contain a non-empty 'path' field." });

            var path = Utility.NormalizePath(request.Path, out var normalizeError);
            if (normalizeError is not null)
                return BadRequest(new { error = normalizeError });

            if (!Directory.Exists(path) && !System.IO.File.Exists(path))
                return BadRequest(new { error = "Path does not exist.", path });

            Guid userId;
            try
            {
                userId = GetCurrentUserId();
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized(new { error = "Authentication required." });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { error = ex.Message });
            }

            var summary = _complianceService.Scan(userId, path);
            return Ok(summary);
        }

        [HttpPost("scan/local")]
        public IActionResult EnqueueLocalScan([FromBody] ScanRequest request)
        {
            if (request is null || string.IsNullOrWhiteSpace(request.Path))
                return BadRequest(new { error = "Request body must contain a non-empty 'path' field." });
            var path = Utility.NormalizePath(request.Path, out var normalizeError);
            if (normalizeError is not null)
                return BadRequest(new { error = normalizeError });
            if (!Directory.Exists(path) && !System.IO.File.Exists(path))
                return BadRequest(new { error = "Path does not exist.", path });
            Guid userId;
            try
            {
                userId = GetCurrentUserId();
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized(new { error = "Authentication required." });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { error = ex.Message });
            }
            var jobId = Guid.NewGuid().ToString("N");
            var hangId = BackgroundJob.Enqueue<ScanJobService>(svc => svc.RunLocalScan(jobId, userId, path));
            _progressRepo.StartAsync(jobId, userId, "Queued", hangId).Wait();
            return Ok(new { jobId });
        }

        [HttpGet("myreports")]
        public async Task<IActionResult> GetMyReports()
        {
            Guid userId;
            try
            {
                userId = GetCurrentUserId();
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized(new { error = "Authentication required." });
            }

            try
            {
                var reports = await _complianceService.GetReportsByUserAsync(userId);
                return Ok(reports);
            }
            catch (InvalidOperationException ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        private Guid GetCurrentUserId()
        {
            var user = HttpContext?.User;
            if (user?.Identity?.IsAuthenticated != true)
                throw new UnauthorizedAccessException();

            // Try common claim names in order of preference
            var idClaim = user.FindFirst(ClaimTypes.NameIdentifier)
                          ?? user.FindFirst("sub")
                          ?? user.FindFirst("user_id")
                          ?? user.FindFirst("userid");

            if (idClaim == null)
                throw new InvalidOperationException("User id claim not found.");

            if (!Guid.TryParse(idClaim.Value, out var guid))
                throw new InvalidOperationException("User id claim is not a valid GUID.");

            return guid;
        }

        [HttpGet("report/{id}")]
        public async Task<IActionResult> GetReport(Guid id)
        {
            try
            {
                var report = await _complianceService.GetReportAsync(id);
                return Ok(report);
            }
            catch (InvalidOperationException ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        [HttpGet("stats/{id}")]
        public async Task<IActionResult> GetStats(Guid id)
        {
            try
            {
                var stats = await _complianceService.GetStatisticsAsync(id);
                return Ok(stats);
            }
            catch (InvalidOperationException ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        [HttpGet("report/{id}/violations")]
        public async Task<IActionResult> GetReportViolations(Guid id, [FromQuery] int page = 1, [FromQuery] int pageSize = 25, [FromQuery] string? category = null, [FromQuery] string? q = null, [FromQuery] string sortBy = "filePath", [FromQuery] string sortDir = "asc")
        {
            if (page <= 0 || pageSize <= 0 || pageSize > 500)
                return BadRequest(new { error = "Invalid pagination parameters." });

            var allowedSort = new[] { "filePath", "lineNumber", "ruleName" };
            if (!System.Array.Exists(allowedSort, s => s == sortBy)) sortBy = "filePath";
            sortDir = (sortDir?.ToLowerInvariant() == "desc") ? "desc" : "asc";

            try
            {
                var paged = await _complianceService.GetReportViolationsPagedAsync(id, page, pageSize, category, q, sortBy, sortDir);
                return Ok(paged);
            }
            catch (InvalidOperationException ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        [HttpDelete("report/{id}")]
        public async Task<IActionResult> DeleteReport(Guid id)
        {
            Guid userId;
            try
            {
                userId = GetCurrentUserId();
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized(new { error = "Authentication required." });
            }

            var ok = await _complianceService.DeleteReportAsync(userId, id);
            if (!ok) return NotFound(new { error = "Report not found or not owned by user." });
            return Ok(new { deleted = true });
        }

        [HttpGet("report/{id}/export/csv")]
        public async Task<IActionResult> ExportReportCsv(Guid id)
        {
            // No auth required to download? Enforce ownership
            Guid userId;
            try
            {
                userId = GetCurrentUserId();
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized(new { error = "Authentication required." });
            }

            // Verify the report exists and belongs to the user
            var summaries = await _complianceService.GetReportsByUserAsync(userId);
            if (!summaries.Any(s => s.ReportId == id))
                return NotFound(new { error = "Report not found or not owned by user." });

            var summary = await _complianceService.GetReportAsync(id);
            var violations = await _complianceService.GetViolationsAllAsync(id);

            var sb = new System.Text.StringBuilder();
            // Header for summary
            sb.AppendLine("ReportId,Path,FilesScanned,ViolationsFound,CreatedAt");
            sb.AppendLine($"{summary.ReportId},{EscapeCsv(summary.ScanPath)},{summary.FilesScanned},{summary.ViolationsFound},{summary.ScanDate:O}");
            sb.AppendLine();
            // Header for violations
            sb.AppendLine("FilePath,LineNumber,MatchedText,RuleId,RuleName,Category");
            foreach (var v in violations)
            {
                sb.AppendLine($"{EscapeCsv(v.FilePath)},{v.LineNumber},{EscapeCsv(v.MatchedText ?? string.Empty)},{EscapeCsv(v.ViolatedRule.RuleId)},{EscapeCsv(v.ViolatedRule.Name)},{EscapeCsv(v.ViolatedRule.Category)}");
            }

            var bytes = System.Text.Encoding.UTF8.GetBytes(sb.ToString());
            var fileName = $"report_{id}.csv";
            return File(bytes, "text/csv", fileName);
        }

        [HttpGet("report/{id}/export/pdf")]
        public async Task<IActionResult> ExportReportPdf(Guid id)
        {
            Guid userId;
            try
            {
                userId = GetCurrentUserId();
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized(new { error = "Authentication required." });
            }

            try
            {
                // Verify ownership
                var summaries = await _complianceService.GetReportsByUserAsync(userId);
                if (!summaries.Any(s => s.ReportId == id))
                    return NotFound(new { error = "Report not found or not owned by user." });

                var stats = await _complianceService.GetStatisticsAsync(id);
                var pdfBytes = _pdfService.GenerateReport(stats);
                var fileName = $"ComplianceReport_{id}.pdf";
                return File(pdfBytes, "application/pdf", fileName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error exporting PDF: {ex}");
                return StatusCode(500, new { error = ex.ToString() });
            }
        }

        private static string EscapeCsv(string input)
        {
            if (input == null) return "";
            var needsQuotes = input.Contains(",") || input.Contains("\"") || input.Contains("\n") || input.Contains("\r");
            var escaped = input.Replace("\"", "\"\"");
            return needsQuotes ? $"\"{escaped}\"" : escaped;
        }

        /// <summary>
        /// Scans a Git repository by cloning it temporarily and running compliance checks.
        /// </summary>
        /// <param name="request">Git repository scan request containing URL and optional authentication</param>
        /// <returns>Scan summary with violations found</returns>
        [HttpPost("scan/git")]
        public IActionResult ScanGitRepository([FromBody] GitScanRequest request)
        {
            if (request is null || string.IsNullOrWhiteSpace(request.RepositoryUrl))
                return BadRequest(new { error = "Request body must contain a non-empty 'repositoryUrl' field." });

            // Validate Git URL format
            if (!IsValidGitUrl(request.RepositoryUrl))
                return BadRequest(new { error = "Invalid Git repository URL format." });

            Guid userId;
            try
            {
                userId = GetCurrentUserId();
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized(new { error = "Authentication required." });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { error = ex.Message });
            }
            var jobId = Guid.NewGuid().ToString("N");
            var hangId = BackgroundJob.Enqueue<ScanJobService>(svc => svc.RunGitScan(jobId, userId, request.RepositoryUrl, request.Branch, request.AccessToken));
            _progressRepo.StartAsync(jobId, userId, "Queued", hangId).Wait();
            return Ok(new { jobId });
        }

        [HttpGet("scan/progress/{jobId}")]
        public async Task<IActionResult> GetProgress(string jobId)
        {
            var progress = await _progressRepo.GetAsync(jobId);
            if (progress == null) return NotFound();
            return Ok(progress);
        }

        [HttpGet("scan/activecount")]
        public async Task<IActionResult> GetActiveCount()
        {
            Guid userId;
            try
            {
                userId = GetCurrentUserId();
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized(new { error = "Authentication required." });
            }
            var count = await _progressRepo.GetActiveCountAsync(userId);
            return Ok(new { count });
        }

        [HttpPost("scan/{jobId}/cancel")]
        public async Task<IActionResult> Cancel(string jobId)
        {
            Guid userId;
            try
            {
                userId = GetCurrentUserId();
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized(new { error = "Authentication required." });
            }
            await _progressRepo.RequestCancelAsync(jobId);
            return Ok(new { cancelled = true });
        }

        /// <summary>
        /// Validates if the provided string is a valid Git repository URL
        /// </summary>
        private bool IsValidGitUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return false;

            // Check for common Git URL patterns
            var validPatterns = new[]
            {
                @"^https?://github\.com/[\w-]+/[\w.-]+(?:\.git)?$",
                @"^https?://gitlab\.com/[\w-]+/[\w.-]+(?:\.git)?$",
                @"^https?://bitbucket\.org/[\w-]+/[\w.-]+(?:\.git)?$",
                @"^git@github\.com:[\w-]+/[\w.-]+\.git$",
                @"^git@gitlab\.com:[\w-]+/[\w.-]+\.git$",
                @"^git@bitbucket\.org:[\w-]+/[\w.-]+\.git$"
            };

            foreach (var pattern in validPatterns)
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(url, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Clones a Git repository to a temporary directory using git command
        /// </summary>
        private async Task<bool> CloneRepositoryAsync(string repoUrl, string targetPath, string? branch = null, string? accessToken = null)
        {
            try
            {
                // Inject access token into URL if provided (for HTTPS URLs)
                var cloneUrl = repoUrl;
                if (!string.IsNullOrWhiteSpace(accessToken) && repoUrl.StartsWith("https://"))
                {
                    var uri = new Uri(repoUrl);
                    cloneUrl = $"https://{accessToken}@{uri.Host}{uri.PathAndQuery}";
                }

                // Build git clone command
                var arguments = $"clone --depth 1 --single-branch";
                if (!string.IsNullOrWhiteSpace(branch))
                    arguments += $" --branch {branch}";
                arguments += $" \"{cloneUrl}\" \"{targetPath}\"";

                var processStartInfo = new ProcessStartInfo
                {
                    FileName = "git",
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = new Process { StartInfo = processStartInfo };
                process.Start();

                // Set timeout for clone operation (5 minutes)
                var completed = await Task.Run(() => process.WaitForExit(300000));

                if (!completed)
                {
                    process.Kill();
                    return false;
                }

                return process.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Request model for scanning Git repositories
    /// </summary>
    public class GitScanRequest
    {
        /// <summary>
        /// Git repository URL (HTTPS or SSH)
        /// </summary>
        public string RepositoryUrl { get; set; } = string.Empty;

        /// <summary>
        /// Optional: Branch name to scan (default: main/master)
        /// </summary>
        public string? Branch { get; set; }

        /// <summary>
        /// Optional: Access token for private repositories
        /// </summary>
        public string? AccessToken { get; set; }
    }
}
