using ComplianceSecurityAuditor.Library;
using ComplianceSecurityAuditor.Models;
using ComplianceSecurityAuditor.Services;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Claims;
using System.Threading.Tasks;

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

        /// <summary>
        /// Scans a Git repository by cloning it temporarily and running compliance checks.
        /// </summary>
        /// <param name="request">Git repository scan request containing URL and optional authentication</param>
        /// <returns>Scan summary with violations found</returns>
        [HttpPost("scan/git")]
        public async Task<IActionResult> ScanGitRepository([FromBody] GitScanRequest request)
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

            string? tempDirectory = null;
            try
            {
                // Create temporary directory for cloning
                tempDirectory = Path.Combine(Path.GetTempPath(), $"securesoft_scan_{Guid.NewGuid()}");
                Directory.CreateDirectory(tempDirectory);

                // Clone the repository
                var cloneSuccess = await CloneRepositoryAsync(
                    request.RepositoryUrl,
                    tempDirectory,
                    request.Branch,
                    request.AccessToken
                );

                if (!cloneSuccess)
                    return BadRequest(new { error = "Failed to clone repository. Check URL and credentials." });

                // Scan the cloned repository
                var summary = _complianceService.Scan(userId, tempDirectory);

                // Add repository metadata to summary
                summary.RepositoryUrl = request.RepositoryUrl;
                summary.Branch = request.Branch ?? "default";

                return Ok(summary);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "An error occurred during Git repository scan.", details = ex.Message });
            }
            finally
            {
                // Cleanup: Delete temporary directory
                if (tempDirectory != null && Directory.Exists(tempDirectory))
                {
                    try
                    {
                        Directory.Delete(tempDirectory, recursive: true);
                    }
                    catch
                    {
                        // Log cleanup failure but don't throw
                    }
                }
            }
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
