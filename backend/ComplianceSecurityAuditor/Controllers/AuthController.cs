using ComplianceSecurityAuditor.Models;
using ComplianceSecurityAuditor.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace ComplianceSecurityAuditor.Controllers
{
	[ApiController]
	[Route("api/auth")]
	public class AuthController : ControllerBase
	{
		private readonly AuthService _auth;
		public AuthController(AuthService auth) { _auth = auth; }

		[HttpPost("login")]
		[AllowAnonymous]
		public async Task<IActionResult> Login([FromBody] LoginRequest req)
		{
			if (req == null || string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password)) return BadRequest(new { error = "Username and password required" });
			try
			{
				var (token, refresh) = await _auth.AuthenticateAsync(req.Username, req.Password, HttpContext.Connection.RemoteIpAddress?.ToString());
				return Ok(new { token, refresh });
			}
			catch (UnauthorizedAccessException)
			{
				return Unauthorized(new { error = "Invalid credentials" });
			}
		}

		[HttpPost("register")]
		[AllowAnonymous]
		public async Task<IActionResult> Register([FromBody] RegisterRequest req)
		{
			if (req == null || string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password) || string.IsNullOrWhiteSpace(req.Email)) return BadRequest(new { error = "username,email,password required" });
			try
			{
				var id = await _auth.RegisterAsync(req.Username, req.Email, req.Password);
				return Ok(new { id });
			}
			catch (InvalidOperationException ex)
			{
				return Conflict(new { error = ex.Message });
			}
		}

		[HttpPost("refresh")]
		[AllowAnonymous]
		public async Task<IActionResult> Refresh([FromBody] RefreshRequest req)
		{
			if (req == null || string.IsNullOrWhiteSpace(req.RefreshToken)) return BadRequest(new { error = "refreshToken required" });
			try
			{
				var (token, refresh) = await _auth.RefreshAsync(req.RefreshToken, HttpContext.Connection.RemoteIpAddress?.ToString());
				return Ok(new { token, refresh });
			}
			catch (UnauthorizedAccessException)
			{
				return Unauthorized(new { error = "Invalid refresh token" });
			}
		}

		[HttpPost("revoke")]
		[AllowAnonymous]
		public async Task<IActionResult> Revoke([FromBody] RevokeRequest req)
		{
			if (req == null || string.IsNullOrWhiteSpace(req.RefreshToken)) return BadRequest(new { error = "refreshToken required" });
			var ok = await _auth.RevokeAsync(req.RefreshToken, HttpContext.Connection.RemoteIpAddress?.ToString());
			return Ok(new { revoked = ok });
		}
	}
}
