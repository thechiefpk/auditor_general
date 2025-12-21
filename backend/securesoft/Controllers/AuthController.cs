using FluentValidation;
using ComplianceSecurityAuditor.Models;
using ComplianceSecurityAuditor.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace ComplianceSecurityAuditor.Controllers
{
	[ApiController]
	[Route("api/auth")]
	public class AuthController : ControllerBase
	{
		private readonly AuthService _auth;
		private readonly IValidator<LoginRequest> _loginValidator;
		private readonly IValidator<RegisterRequest> _registerValidator;

		public AuthController(AuthService auth, IValidator<LoginRequest> loginValidator, IValidator<RegisterRequest> registerValidator) 
		{ 
			_auth = auth;
			_loginValidator = loginValidator;
			_registerValidator = registerValidator;
		}

		[HttpPost("login")]
		[AllowAnonymous]
		public async Task<IActionResult> Login([FromBody] LoginRequest req)
		{
			if (req == null) return BadRequest(new { message = "Request body is required" });
			
			var validation = await _loginValidator.ValidateAsync(req);
			if (!validation.IsValid) return BadRequest(new { message = validation.Errors[0].ErrorMessage });

			try
			{
				var (token, refresh) = await _auth.AuthenticateAsync(req.Username, req.Password, HttpContext.Connection.RemoteIpAddress?.ToString());
				return Ok(new { token, refresh });
			}
			catch (UnauthorizedAccessException)
			{
				return Unauthorized(new { message = "Invalid credentials" });
			}
		}

		[HttpPost("register")]
		[AllowAnonymous]
		public async Task<IActionResult> Register([FromBody] RegisterRequest req)
		{
			if (req == null) return BadRequest(new { message = "Request body is required" });

			var validation = await _registerValidator.ValidateAsync(req);
			if (!validation.IsValid) return BadRequest(new { message = validation.Errors[0].ErrorMessage });

			try
			{
				var id = await _auth.RegisterAsync(req.Username, req.Email, req.Password);
				// Auto-login
				var (token, refresh) = await _auth.AuthenticateAsync(req.Username, req.Password, HttpContext.Connection.RemoteIpAddress?.ToString());
				return Ok(new { token, refresh });
			}
			catch (InvalidOperationException ex)
			{
				return Conflict(new { message = ex.Message });
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

		[HttpGet("profile")]
		[Authorize]
		public async Task<IActionResult> GetProfile()
		{
			var idStr = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
			if (!Guid.TryParse(idStr, out var id)) return Unauthorized();
			var user = await _auth.GetUserByIdAsync(id);
			if (user == null) return NotFound();
			return Ok(user);
		}

		[HttpPut("profile")]
		[Authorize]
		public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest req)
		{
			var idStr = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
			if (!Guid.TryParse(idStr, out var id)) return Unauthorized();
			if (req == null) return BadRequest();
			var ok = await _auth.UpdateUserAsync(id, req.Username, req.Email, req.NewPassword);
			if (!ok) return BadRequest(new { error = "Update failed" });
			return Ok(new { success = true });
		}
	}

	public class UpdateProfileRequest { public string Username { get; set; } = ""; public string Email { get; set; } = ""; public string? NewPassword { get; set; } }
}
