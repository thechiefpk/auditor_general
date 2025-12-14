using ComplianceSecurityAuditor.Data;
using ComplianceSecurityAuditor.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ComplianceSecurityAuditor.Services
{
	public class AuthService
	{
		private readonly IAuthRepository _repo;
		private readonly IConfiguration _config;

		public AuthService(IAuthRepository repo, IConfiguration config)
		{
			_repo = repo;
			_config = config;
		}

		public async Task<(string token, string refreshToken)> AuthenticateAsync(string username, string password, string ip)
		{
			var secret = _config["JWT_SECRET"];
			var hash = SHA256.HashData(Encoding.UTF8.GetBytes(password + secret));
			var user = await _repo.ValidateUserCredentialsAsync(username, hash);
			if (user == null) throw new UnauthorizedAccessException("Invalid credentials");

			var roles = await _repo.GetRolesForUserAsync(user.Id);
			var jwt = CreateJwt(user.Id, user.Username, secret, roles);

			var refresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
			var rhash = SHA256.HashData(Encoding.UTF8.GetBytes(refresh));
			await _repo.AddRefreshTokenAsync(user.Id, rhash, DateTime.UtcNow.AddDays(30), ip);

			return (jwt, refresh);
		}

		public async Task<Guid> RegisterAsync(string username, string email, string password)
		{
			// basic uniqueness check
			var existing = await _repo.GetUserByUsernameAsync(username);
			if (existing != null) throw new InvalidOperationException("User already exists");

			var secret = _config["JWT_SECRET"];
			var hash = SHA256.HashData(Encoding.UTF8.GetBytes(password + secret));
			var salt = Array.Empty<byte>();

			var user = new User { Username = username, Email = email, CreatedAt = DateTime.UtcNow };
			var id = await _repo.CreateUserAsync(user, hash, salt);
			return id;
		}

		public async Task<(string token, string refreshToken)> RefreshAsync(string refreshToken, string ip)
		{
			var secret = _config["JWT_SECRET"];
			var rhash = SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken));
			var userId = await _repo.GetUserIdByRefreshTokenHashAsync(rhash);
			if (userId == null) throw new UnauthorizedAccessException("Invalid refresh token");

			var user = await _repo.GetUserByIdAsync(userId.Value);
			if (user == null) throw new UnauthorizedAccessException("Invalid refresh token");

			var roles = await _repo.GetRolesForUserAsync(user.Id);
			// rotate
			await _repo.RevokeRefreshTokenAsync(rhash, ip);
			var newRefresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
			var newRhash = SHA256.HashData(Encoding.UTF8.GetBytes(newRefresh));
			await _repo.AddRefreshTokenAsync(user.Id, newRhash, DateTime.UtcNow.AddDays(30), ip);

			var jwt = CreateJwt(user.Id, user.Username, secret, roles);
			return (jwt, newRefresh);
		}

		public async Task<bool> RevokeAsync(string refreshToken, string ip)
		{
			var rhash = SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken));
			return await _repo.RevokeRefreshTokenAsync(rhash, ip);
		}

		private string CreateJwt(Guid userId, string username, string secret, List<string> roles)
		{
			var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret));
			var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
			var claims = new List<Claim> { new Claim(ClaimTypes.NameIdentifier, userId.ToString()), new Claim(ClaimTypes.Name, username) };
			foreach (var r in roles) claims.Add(new Claim(ClaimTypes.Role, r));
			var token = new JwtSecurityToken(claims: claims, expires: DateTime.UtcNow.AddMinutes(30), signingCredentials: creds);
			return new JwtSecurityTokenHandler().WriteToken(token);
		}
	}
}
