using ComplianceSecurityAuditor.Models;

namespace ComplianceSecurityAuditor.Data
{
	public interface IAuthRepository
	{
		Task<User?> GetUserByUsernameAsync(string username);
		Task<User?> GetUserByIdAsync(Guid id);
		Task<Guid> CreateUserAsync(User user, byte[] passwordHash, byte[] passwordSalt, string? roleName = "User");
		Task<bool> AddRefreshTokenAsync(Guid userId, byte[] tokenHash, DateTime expiresAt, string? createdByIp);
		Task<User?> ValidateUserCredentialsAsync(string username, byte[] passwordHash);
		Task<bool> RevokeRefreshTokenAsync(byte[] tokenHash, string? revokedByIp);
		Task<Guid?> GetUserIdByRefreshTokenHashAsync(byte[] tokenHash);
		Task<List<string>> GetRolesForUserAsync(Guid userId);
		Task<bool> UpdateUserAsync(User user, byte[]? newPasswordHash = null);
	}
}
