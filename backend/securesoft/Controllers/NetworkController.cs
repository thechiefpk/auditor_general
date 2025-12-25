using Microsoft.AspNetCore.Mvc;
using ComplianceSecurityAuditor.Services;
using SecureSoftAPI.Models;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace SecureSoftAPI.Controllers
{
    [ApiController]
    [Route("api/network")]
    [Authorize]
    public class NetworkController : ControllerBase
    {
        private readonly NetworkAuditService _networkService;
        private readonly PdfReportService _pdfService;

        public NetworkController(NetworkAuditService networkService, PdfReportService pdfService)
        {
            _networkService = networkService;
            _pdfService = pdfService;
        }

        [HttpPost("scan")]
        public async Task<IActionResult> Scan([FromBody] NetworkScanRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Url))
            {
                return BadRequest(new { error = "URL is required" });
            }

            var userIdStr = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdStr) || !Guid.TryParse(userIdStr, out var userId))
            {
                 // Fallback for dev/test without auth if needed, but Authorize attribute prevents this
                 return Unauthorized();
            }

            var result = await _networkService.ScanWebsiteAsync(request.Url);
            
            // Save the result for history/reporting
            await _networkService.SaveScanResultAsync(userId, result);

            return Ok(result);
        }

        [HttpGet("history")]
        public async Task<IActionResult> GetHistory()
        {
            var userIdStr = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdStr) || !Guid.TryParse(userIdStr, out var userId))
                return Unauthorized();

            var history = await _networkService.GetUserScanResultsAsync(userId);
            return Ok(history);
        }

        [HttpGet("report/{id}/pdf")]
        public async Task<IActionResult> DownloadPdf(Guid id)
        {
            var userIdStr = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdStr) || !Guid.TryParse(userIdStr, out var userId))
                return Unauthorized();

            var history = await _networkService.GetUserScanResultsAsync(userId);
            var result = history.FirstOrDefault(r => r.Id == id);
            
            if (result == null) return NotFound(new { error = "Report not found" });

            var pdfBytes = _pdfService.GenerateNetworkReport(result);
            return File(pdfBytes, "application/pdf", $"NetworkScan_{result.Url}_{result.CreatedAt:yyyyMMdd}.pdf");
        }
    }
}
