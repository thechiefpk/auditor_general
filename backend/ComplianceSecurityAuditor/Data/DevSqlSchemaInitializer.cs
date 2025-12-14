using Microsoft.Data.SqlClient;
using System.Data;

namespace ComplianceSecurityAuditor.Data
{
	public static class DevSqlSchemaInitializer
	{
		public static async Task EnsureAsync(string connectionString)
		{
			try
			{
				var sb = new SqlConnectionStringBuilder(connectionString);
				var dbName = sb.InitialCatalog;
				if (string.IsNullOrWhiteSpace(dbName)) return;

				// ensure database exists
				var masterSb = new SqlConnectionStringBuilder(connectionString) { InitialCatalog = "master" };
				await using (var master = new SqlConnection(masterSb.ConnectionString))
				{
					await master.OpenAsync();
					var createDbSql = "IF DB_ID(@db) IS NULL CREATE DATABASE [" + dbName + "]";
					await using var cmd = new SqlCommand(createDbSql, master);
					cmd.Parameters.Add(new SqlParameter("@db", SqlDbType.NVarChar, 128) { Value = dbName });
					await cmd.ExecuteNonQueryAsync();
				}

				await using var c = new SqlConnection(connectionString);
				await c.OpenAsync();

				var createUsers = @"
IF NOT EXISTS (SELECT1 FROM sys.tables WHERE name = 'Users' AND type = 'U')
BEGIN
 CREATE TABLE dbo.Users (
 Id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID() PRIMARY KEY,
 Username NVARCHAR(100) NOT NULL UNIQUE,
 Email NVARCHAR(256) NOT NULL,
 PasswordHash VARBINARY(256) NOT NULL,
 PasswordSalt VARBINARY(256) NULL,
 IsEmailConfirmed BIT NOT NULL DEFAULT(0),
 CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
 );
END
";
				await using (var cmd = new SqlCommand(createUsers, c)) { await cmd.ExecuteNonQueryAsync(); }

				var createUserRoles = @"
IF NOT EXISTS (SELECT1 FROM sys.tables WHERE name = 'UserRoles' AND type = 'U')
BEGIN
 CREATE TABLE dbo.UserRoles (
 Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
 UserId UNIQUEIDENTIFIER NOT NULL,
 RoleName NVARCHAR(64) NOT NULL,
 CONSTRAINT FK_UserRoles_Users FOREIGN KEY (UserId) REFERENCES dbo.Users(Id) ON DELETE CASCADE
 );
 CREATE INDEX IX_UserRoles_UserId ON dbo.UserRoles(UserId);
END
";
				await using (var cmd = new SqlCommand(createUserRoles, c)) { await cmd.ExecuteNonQueryAsync(); }

				var createTokens = @"
IF NOT EXISTS (SELECT1 FROM sys.tables WHERE name = 'RefreshTokens' AND type = 'U')
BEGIN
 CREATE TABLE dbo.RefreshTokens (
 Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
 UserId UNIQUEIDENTIFIER NOT NULL,
 TokenHash VARBINARY(256) NOT NULL,
 ExpiresAt DATETIME2 NOT NULL,
 CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
 CreatedByIp NVARCHAR(64) NULL,
 RevokedAt DATETIME2 NULL,
 RevokedByIp NVARCHAR(64) NULL,
 CONSTRAINT FK_RefreshTokens_Users FOREIGN KEY (UserId) REFERENCES dbo.Users(Id) ON DELETE CASCADE,
 CONSTRAINT UQ_RefreshTokens_TokenHash UNIQUE (TokenHash)
 );
 CREATE INDEX IX_RefreshTokens_UserId ON dbo.RefreshTokens(UserId);
END
";
				await using (var cmd = new SqlCommand(createTokens, c)) { await cmd.ExecuteNonQueryAsync(); }

				var createReports = @"
					IF NOT EXISTS (SELECT1 FROM sys.tables WHERE name = 'Reports' AND type = 'U')
						BEGIN
							CREATE TABLE dbo.Reports (
							Id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID() PRIMARY KEY,
							Path NVARCHAR(500) NOT NULL,
							FilesScanned INT NOT NULL,
							ViolationsFound INT NOT NULL,
							CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
						);
						END";

				await using (var cmd = new SqlCommand(createReports, c)) { await cmd.ExecuteNonQueryAsync(); }

				var createViolations = @"
					IF NOT EXISTS (SELECT1 FROM sys.tables WHERE name = 'Violations' AND type = 'U')
					BEGIN
						CREATE TABLE dbo.Violations (
							Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
							ReportId UNIQUEIDENTIFIER NOT NULL,
							FilePath NVARCHAR(4000) NOT NULL,
							LineNumber INT NOT NULL,
							MatchedText NVARCHAR(MAX) NULL,
							RuleId NVARCHAR(128) NOT NULL,
							RuleName NVARCHAR(256) NOT NULL,
							Category NVARCHAR(128) NOT NULL,
						CONSTRAINT FK_Violations_Reports FOREIGN KEY (ReportId) REFERENCES dbo.Reports(Id) ON DELETE CASCADE
					);
					CREATE INDEX IX_Violations_Report ON dbo.Violations(ReportId);
				END";
				await using (var cmd = new SqlCommand(createViolations, c)) { await cmd.ExecuteNonQueryAsync(); }

				// no view creation; roles are read from UserRoles table
			}
			catch
			{
				// dev helper only
			}
		}
	}
}
