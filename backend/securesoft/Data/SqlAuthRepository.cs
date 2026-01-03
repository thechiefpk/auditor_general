using ComplianceSecurityAuditor.Data;
using ComplianceSecurityAuditor.Models;
using Microsoft.Data.SqlClient;
using System.Data;

namespace ComplianceSecurityAuditor.Data
{
	public class SqlAuthRepository : IAuthRepository
	{
		private readonly string _conn;
		public SqlAuthRepository(string conn) { _conn = conn; }

		public async Task<User?> GetUserByUsernameAsync(string username)
		{
			using var c = new SqlConnection(_conn);
			await c.OpenAsync();
			var cmd = new SqlCommand("SELECT Id, Username, Email, IsEmailConfirmed, CreatedAt FROM Users WHERE Username = @u", c);
			cmd.Parameters.AddWithValue("@u", username);
			using var r = await cmd.ExecuteReaderAsync();
			if (await r.ReadAsync()) return new User { Id = r.GetGuid(0), Username = r.GetString(1), Email = r.GetString(2), IsEmailConfirmed = r.GetBoolean(3), CreatedAt = r.GetDateTime(4) };
			return null;
		}

		public async Task<User?> GetUserByIdAsync(Guid id)
		{
			using var c = new SqlConnection(_conn);
			await c.OpenAsync();
			var cmd = new SqlCommand("SELECT Id, Username, Email, IsEmailConfirmed, CreatedAt FROM Users WHERE Id = @id", c);
			cmd.Parameters.AddWithValue("@id", id);
			using var r = await cmd.ExecuteReaderAsync();
			if (await r.ReadAsync()) return new User { Id = r.GetGuid(0), Username = r.GetString(1), Email = r.GetString(2), IsEmailConfirmed = r.GetBoolean(3), CreatedAt = r.GetDateTime(4) };
			return null;
		}

		public async Task<Guid> CreateUserAsync(User user, byte[] passwordHash, byte[] passwordSalt, string? roleName = "User")
		{
			using var c = new SqlConnection(_conn);
			await c.OpenAsync();

			using var cmd = new SqlCommand("dbo.sp_CreateUser", c)
			{
				CommandType = CommandType.StoredProcedure
			};

			cmd.Parameters.Add("@Username", SqlDbType.NVarChar, 100).Value = user.Username;
			cmd.Parameters.Add("@Email", SqlDbType.NVarChar, 256).Value = user.Email;
			cmd.Parameters.Add("@PasswordHash", SqlDbType.VarBinary, -1).Value = (object)passwordHash ?? DBNull.Value;
			cmd.Parameters.Add("@PasswordSalt", SqlDbType.VarBinary, -1).Value = (object)passwordSalt ?? DBNull.Value;
			cmd.Parameters.Add("@CreatedAt", SqlDbType.DateTime).Value = DateTime.UtcNow;
			cmd.Parameters.Add("@RoleName", SqlDbType.NVarChar, 100).Value = roleName;

			var result = await cmd.ExecuteScalarAsync().ConfigureAwait(false);

			if (result == null || result == DBNull.Value)
				throw new InvalidOperationException("Stored procedure did not return the new UserId.");

			return (Guid)result;
		}

		public async Task<bool> AddRefreshTokenAsync(Guid userId, byte[] tokenHash, DateTime expiresAt, string? createdByIp)
		{
			using var c = new SqlConnection(_conn);
			await c.OpenAsync();
			var cmd = new SqlCommand(@"INSERT INTO RefreshTokens(UserId, TokenHash, ExpiresAt, CreatedAt, CreatedByIp) VALUES(@uid,@th,@ex,@ca,@ip)", c);
			cmd.Parameters.AddWithValue("@uid", userId);
			cmd.Parameters.AddWithValue("@th", tokenHash);
			cmd.Parameters.AddWithValue("@ex", expiresAt);
			cmd.Parameters.AddWithValue("@ca", DateTime.UtcNow);
			cmd.Parameters.AddWithValue("@ip", createdByIp ?? (object)DBNull.Value);
			var res = await cmd.ExecuteNonQueryAsync();
			return res >0;
		}

		public async Task<User?> ValidateUserCredentialsAsync(string username, byte[] passwordHash)
		{
			using var c = new SqlConnection(_conn);
			await c.OpenAsync();
			var cmd = new SqlCommand("SELECT Id, Username, Email, IsEmailConfirmed, CreatedAt FROM Users WHERE (Username = @u OR Email = @u) AND PasswordHash = @h", c);
			cmd.Parameters.AddWithValue("@u", username);
			cmd.Parameters.AddWithValue("@h", passwordHash);
			using var r = await cmd.ExecuteReaderAsync();
			if (await r.ReadAsync()) return new User { Id = r.GetGuid(0), Username = r.GetString(1), Email = r.GetString(2), IsEmailConfirmed = r.GetBoolean(3), CreatedAt = r.GetDateTime(4) };
			return null;
		}

		public async Task<bool> RevokeRefreshTokenAsync(byte[] tokenHash, string? revokedByIp)
		{
			using var c = new SqlConnection(_conn);
			await c.OpenAsync();
			var cmd = new SqlCommand("UPDATE RefreshTokens SET RevokedAt = @ra, RevokedByIp = @ip WHERE TokenHash = @th", c);
			cmd.Parameters.AddWithValue("@ra", DateTime.UtcNow);
			cmd.Parameters.AddWithValue("@ip", revokedByIp ?? (object)DBNull.Value);
			cmd.Parameters.AddWithValue("@th", tokenHash);
			var res = await cmd.ExecuteNonQueryAsync();
			return res >0;
		}

		public async Task<Guid?> GetUserIdByRefreshTokenHashAsync(byte[] tokenHash)
		{
			using var c = new SqlConnection(_conn);
			await c.OpenAsync();
			var cmd = new SqlCommand("SELECT UserId FROM RefreshTokens WHERE TokenHash = @th AND RevokedAt IS NULL AND ExpiresAt > SYSUTCDATETIME()", c);
			cmd.Parameters.AddWithValue("@th", tokenHash);
			var res = await cmd.ExecuteScalarAsync();
			if (res == null || res == DBNull.Value) return null;
			return (Guid)res;
		}

		public async Task<List<string>> GetRolesForUserAsync(Guid userId)
		{
			var list = new List<string>();
			using var c = new SqlConnection(_conn);
			await c.OpenAsync();
			var cmd = new SqlCommand("SELECT RO.Name AS RoleName FROM UserRoles UR INNER JOIN Roles RO ON UR.RoleId = RO.Id WHERE UR.UserId = @id", c);
			cmd.Parameters.AddWithValue("@id", userId);
			using var r = await cmd.ExecuteReaderAsync();
			while (await r.ReadAsync())
			{
				if (!r.IsDBNull(0))
				{
					var role = r.GetString(0);
					if (!string.IsNullOrWhiteSpace(role)) list.Add(role);
				}
			}
			return list;
		}

		public async Task<bool> UpdateUserAsync(User user, byte[]? newPasswordHash = null)
		{
			using var c = new SqlConnection(_conn);
			await c.OpenAsync();
			
			string sql = "UPDATE Users SET Username = @u, Email = @e";
			if (newPasswordHash != null)
			{
				sql += ", PasswordHash = @ph";
			}
			sql += " WHERE Id = @id";

			var cmd = new SqlCommand(sql, c);
			cmd.Parameters.AddWithValue("@u", user.Username);
			cmd.Parameters.AddWithValue("@e", user.Email);
			cmd.Parameters.AddWithValue("@id", user.Id);
			
			if (newPasswordHash != null)
			{
				cmd.Parameters.AddWithValue("@ph", newPasswordHash);
			}

			var rows = await cmd.ExecuteNonQueryAsync();
			return rows > 0;
		}
	}
}
