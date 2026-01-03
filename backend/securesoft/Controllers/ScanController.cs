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
        public async Task<IActionResult> EnqueueLocalScan([FromBody] ScanRequest request)
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

            if (request.IsAdvanced)
            {
                var isDockerRunning = await Utility.IsDockerRunningAsync();
                if (!isDockerRunning)
                {
                     return BadRequest(new { error = "Advanced scan requires Docker to be running. Please start Docker Desktop." });
                }
            }

            var jobId = Guid.NewGuid().ToString("N");
            var hangId = BackgroundJob.Enqueue<ScanJobService>(svc => svc.RunLocalScan(jobId, userId, path, request.IsAdvanced, null));
            await _progressRepo.StartAsync(jobId, userId, "Queued", hangId);
            return Ok(new { jobId });
        }

        [HttpPost("scan/upload")]
        [RequestSizeLimit(100 * 1024 * 1024)] // 100 MB limit
        public async Task<IActionResult> UploadAndScan([FromForm] bool isAdvanced)
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

            var files = Request.Form.Files;
            if (files == null || files.Count == 0)
            {
                return BadRequest(new { error = "No files uploaded." });
            }

            // Create a temporary directory for this scan
            var tempPath = Path.Combine(Path.GetTempPath(), "SecureSoftScans", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempPath);

            try
            {
                foreach (var file in files)
                {
                    // Use relative path if available (webkitRelativePath), otherwise just filename
                    // Note: file.FileName usually contains the relative path for directory uploads in some browsers,
                    // but we need to handle it carefully to prevent directory traversal.
                    var relativePath = file.FileName.Replace("/", Path.DirectorySeparatorChar.ToString())
                                                    .Replace("\\", Path.DirectorySeparatorChar.ToString());
                    
                    // Simple sanitization
                    if (relativePath.StartsWith(Path.DirectorySeparatorChar.ToString())) relativePath = relativePath.Substring(1);
                    if (relativePath.Contains("..")) relativePath = Path.GetFileName(relativePath); // Fallback to flat if suspicious

                    var fullPath = Path.Combine(tempPath, relativePath);
                    var dir = Path.GetDirectoryName(fullPath);
                    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

                    using (var stream = new FileStream(fullPath, FileMode.Create))
                    {
                        await file.CopyToAsync(stream);
                    }
                }

                if (isAdvanced)
                {
                    var isDockerRunning = await Utility.IsDockerRunningAsync();
                    if (!isDockerRunning)
                    {
                        return BadRequest(new { error = "Advanced scan requires Docker to be running. Please start Docker Desktop." });
                    }
                }

                var jobId = Guid.NewGuid().ToString("N");
                var hangId = BackgroundJob.Enqueue<ScanJobService>(svc => svc.RunLocalScan(jobId, userId, tempPath, isAdvanced, null));
                await _progressRepo.StartAsync(jobId, userId, "Queued", hangId);
                
                return Ok(new { jobId });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = $"Upload failed: {ex.Message}" });
            }
        }

        [HttpPost("scan/sql")]
        public async Task<IActionResult> EnqueueSqlScan([FromBody] ScanRequest request)
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
            var hangId = BackgroundJob.Enqueue<ScanJobService>(svc => svc.RunSqlScan(jobId, userId, path, null));
            await _progressRepo.StartAsync(jobId, userId, "Queued", hangId);
            return Ok(new { jobId });
        }


        [HttpPost("scan/network")]
        public async Task<IActionResult> EnqueueNetworkScan([FromBody] NetworkScanRequest request)
        {
            if (request is null || string.IsNullOrWhiteSpace(request.Url))
                return BadRequest(new { error = "Request body must contain a non-empty 'url' field." });
            
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
            var hangId = BackgroundJob.Enqueue<ScanJobService>(svc => svc.RunNetworkScan(jobId, userId, request.Url, null));
            await _progressRepo.StartAsync(jobId, userId, "Queued", hangId);
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
                var codeReports = await _complianceService.GetReportsByUserAsync(userId);
                var networkReports = await _complianceService.GetNetworkAuditsByUserAsync(userId);
                
                return Ok(new { 
                    codeScans = codeReports, 
                    networkScans = networkReports 
                });
            }
            catch (InvalidOperationException ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        private Guid GetCurrentUserId()
        {
            var user = HttpContext?.User;
            Console.WriteLine($"[ScanController] IsAuthenticated: {user?.Identity?.IsAuthenticated}");
            Console.WriteLine($"[ScanController] Identity Name: {user?.Identity?.Name}");
            Console.WriteLine($"[ScanController] Claims: {string.Join(", ", user?.Claims.Select(c => $"{c.Type}={c.Value}") ?? Array.Empty<string>())}");
            
            // Log Headers
            foreach (var h in HttpContext.Request.Headers)
            {
                Console.WriteLine($"[ScanController] Header: {h.Key} = {h.Value}");
            }

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

        [HttpGet("network-report/{id}")]
        public async Task<IActionResult> GetNetworkReport(Guid id)
        {
            try
            {
                var report = await _complianceService.GetNetworkAuditByIdAsync(id);
                if (report == null) return NotFound(new { error = "Report not found." });
                return Ok(report);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        [HttpGet("network-report/{id}/export/csv")]
        public async Task<IActionResult> ExportNetworkReportCsv(Guid id)
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

            var report = await _complianceService.GetNetworkAuditByIdAsync(id);
            if (report == null) return NotFound(new { error = "Report not found." });

            // Verify ownership
            var userReports = await _complianceService.GetNetworkAuditsByUserAsync(userId);
            if (!userReports.Any(r => r.Id == report.Id))
                return NotFound(new { error = "Report not found or not owned by user." });

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Id,Url,StatusCode,StatusReason,SecurityScore,CreatedAt");
            sb.AppendLine($"{report.Id},{EscapeCsv(report.Url)},{report.StatusCode},{EscapeCsv(report.StatusReason)},{report.SecurityScore},{report.CreatedAt:O}");

            var bytes = System.Text.Encoding.UTF8.GetBytes(sb.ToString());
            var fileName = $"network_report_{id}.csv";
            return File(bytes, "text/csv", fileName);
        }

        private static string EscapeCsv(string input)
        {
            if (input == null) return "";
            var needsQuotes = input.Contains(",") || input.Contains("\"") || input.Contains("\n") || input.Contains("\r");
            var escaped = input.Replace("\"", "\"\"");
            return needsQuotes ? $"\"{escaped}\"" : escaped;
        }

        [HttpPost("scan/git/validate")]
        public IActionResult ValidateGitRepo([FromBody] GitScanRequest request)
        {
            if (request is null || string.IsNullOrWhiteSpace(request.RepositoryUrl))
                return BadRequest(new { error = "Repository URL is required." });

            // Enforce Public Only - Ignore or Warn if Token provided?
            // We just validate WITHOUT token to ensure it is public.
            var result = ValidateGitAccess(request.RepositoryUrl, null); // Pass null for token to force public check

            if (result.Success)
            {
                return Ok(new { valid = true });
            }
            else
            {
                // If it failed, it might be private or invalid.
                // We can't distinguish easily without parsing specific git errors, but for our purpose:
                return Ok(new { valid = false, error = "Repository is not accessible. Ensure it is public and the URL is correct." });
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

            // Verify Git access/credentials - FORCE PUBLIC (Pass null token)
            var validationResult = ValidateGitAccess(request.RepositoryUrl, null);
            if (!validationResult.Success)
            {
                return BadRequest(new { error = $"Git validation failed: {validationResult.Message}. Only PUBLIC repositories are supported." });
            }

            if (request.IsAdvanced)
            {
                var isDockerRunning = await Utility.IsDockerRunningAsync();
                if (!isDockerRunning)
                {
                     return BadRequest(new { error = "Advanced scan requires Docker to be running. Please start Docker Desktop." });
                }
            }

            var jobId = Guid.NewGuid().ToString("N");
            // Pass null for accessToken to ScanJobService as well
            var hangId = BackgroundJob.Enqueue<ScanJobService>(svc => svc.RunGitScan(jobId, userId, request.RepositoryUrl, request.Branch, null, request.IsAdvanced, null));
            await _progressRepo.StartAsync(jobId, userId, "Queued", hangId);
            return Ok(new { jobId });
        }

        [HttpGet("scan/progress/{jobId}")]
        public async Task<IActionResult> GetProgress(string jobId)
        {
            var progress = await _progressRepo.GetAsync(jobId);
            if (progress == null) return NotFound();

            // Security check: Ensure the job belongs to the current user
            try
            {
                var userId = GetCurrentUserId();
                if (progress.UserId != userId)
                {
                     return Forbid();
                }
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }

            // Self-healing: Check for stale jobs (no update for > 2 minutes while in active state)
            if ((progress.Status == "Cloning" || progress.Status == "Scanning") && 
                DateTime.UtcNow.Subtract(progress.UpdatedAt).TotalMinutes > 2)
            {
                await _progressRepo.FailAsync(jobId, "Scan timed out (no activity detected).");
                progress.Status = "Failed";
                progress.Error = "Scan timed out (no activity detected).";
            }

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
            
            // 1. Request logical cancellation
            await _progressRepo.RequestCancelAsync(jobId);

            // 2. Attempt hard kill of external process if it exists
            try 
            {
                var processId = await _progressRepo.GetProcessIdAsync(jobId);
                if (processId.HasValue)
                {
                    try 
                    {
                        var proc = System.Diagnostics.Process.GetProcessById(processId.Value);
                        // Security check: Verify process name to avoid killing random system processes
                        // Privado CLI or Docker
                        var procName = proc.ProcessName.ToLower();
                        if (procName.Contains("privado") || procName.Contains("docker") || procName.Contains("git"))
                        {
                            proc.Kill(true); // Kill entire process tree
                            Console.WriteLine($"[ScanController] Hard killed process {processId.Value} ({procName}) for job {jobId}");
                        }
                    }
                    catch (ArgumentException)
                    {
                        // Process already exited
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[ScanController] Failed to kill process {processId.Value}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ScanController] Error during hard cancellation: {ex.Message}");
            }

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
        /// Validates Git repository access using git ls-remote
        /// </summary>
        private (bool Success, string Message) ValidateGitAccess(string repoUrl, string? accessToken)
        {
            try
            {
                var checkUrl = repoUrl;
                if (!string.IsNullOrWhiteSpace(accessToken) && repoUrl.StartsWith("https://"))
                {
                    var uri = new Uri(repoUrl);
                    checkUrl = $"https://{accessToken}@{uri.Host}{uri.PathAndQuery}";
                }

                var processStartInfo = new ProcessStartInfo
                {
                    FileName = "git",
                    Arguments = $"ls-remote \"{checkUrl}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                // Disable interactive prompts and credential helpers
                processStartInfo.EnvironmentVariables["GIT_TERMINAL_PROMPT"] = "0";
                processStartInfo.EnvironmentVariables["GCM_INTERACTIVE"] = "never";

                // Ensure we don't use global/system config that might have helpers configured
                // Note: -c credential.helper= overrides any helpers to be empty for this command
                processStartInfo.Arguments = $"-c credential.helper= ls-remote \"{checkUrl}\"";

                using var process = new Process { StartInfo = processStartInfo };
                process.Start();
                
                // Wait up to 15 seconds for validation
                var completed = process.WaitForExit(15000);
                
                if (!completed)
                {
                    process.Kill();
                    return (false, "Connection timed out");
                }

                var error = process.StandardError.ReadToEnd();
                if (process.ExitCode != 0)
                {
                    // Clean up error message to avoid exposing tokens if any (though git usually masks them)
                    // But we constructed the URL with token, so we should be careful.
                    // The error from git usually says "Authentication failed" or "Repository not found".
                    return (false, "Access denied or repository not found");
                }

                return (true, "OK");
            }
            catch (Exception ex)
            {
                return (false, ex.Message);
            }
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
        /// Optional: Personal Access Token for private repositories
        /// </summary>
        public string? AccessToken { get; set; }

        public bool IsAdvanced { get; set; }
    }
}
