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
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'Users' AND type = 'U')
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

				var createRoles = @"
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'Roles' AND type = 'U')
BEGIN
 CREATE TABLE dbo.Roles (
  Id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
  Name NVARCHAR(100) NOT NULL UNIQUE,
  Description NVARCHAR(400) NULL
 );
END
";
				await using (var cmd = new SqlCommand(createRoles, c)) { await cmd.ExecuteNonQueryAsync(); }

				var seedRoles = @"
IF NOT EXISTS (SELECT 1 FROM dbo.Roles WHERE Name = 'Admin')
BEGIN
 INSERT INTO dbo.Roles (Name) VALUES ('Admin');
END
IF NOT EXISTS (SELECT 1 FROM dbo.Roles WHERE Name = 'User')
BEGIN
 INSERT INTO dbo.Roles (Name) VALUES ('User');
END
";
				await using (var cmd = new SqlCommand(seedRoles, c)) { await cmd.ExecuteNonQueryAsync(); }

				var createUserRoles = @"
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'UserRoles' AND type = 'U')
BEGIN
 CREATE TABLE dbo.UserRoles (
  UserId UNIQUEIDENTIFIER NOT NULL,
  RoleId UNIQUEIDENTIFIER NOT NULL,
  AssignedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
  CONSTRAINT PK_UserRoles PRIMARY KEY (UserId, RoleId),
  CONSTRAINT FK_UserRoles_Users FOREIGN KEY (UserId) REFERENCES dbo.Users(Id) ON DELETE CASCADE,
  CONSTRAINT FK_UserRoles_Roles FOREIGN KEY (RoleId) REFERENCES dbo.Roles(Id) ON DELETE CASCADE
 );
END
";
				await using (var cmd = new SqlCommand(createUserRoles, c)) { await cmd.ExecuteNonQueryAsync(); }

				var createTokens = @"
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'RefreshTokens' AND type = 'U')
BEGIN
 CREATE TABLE dbo.RefreshTokens (
 Id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
 UserId UNIQUEIDENTIFIER NOT NULL,
 TokenHash VARBINARY(64) NOT NULL,
 ExpiresAt DATETIME2 NOT NULL,
 CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
 CreatedByIp NVARCHAR(45) NULL,
 RevokedAt DATETIME2 NULL,
 RevokedByIp NVARCHAR(45) NULL,
 ReplacedByTokenHash VARBINARY(64) NULL,
 ReasonRevoked NVARCHAR(200) NULL,
 CONSTRAINT FK_RefreshTokens_Users FOREIGN KEY (UserId) REFERENCES dbo.Users(Id) ON DELETE CASCADE,
 CONSTRAINT UQ_RefreshTokens_TokenHash UNIQUE (TokenHash)
 );
 CREATE INDEX IX_RefreshTokens_UserId ON dbo.RefreshTokens(UserId);
 CREATE INDEX IX_RefreshTokens_TokenHash ON dbo.RefreshTokens(TokenHash);
END
";
				await using (var cmd = new SqlCommand(createTokens, c)) { await cmd.ExecuteNonQueryAsync(); }

				var createReports = @"
					IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'Reports' AND type = 'U')
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
					IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'Violations' AND type = 'U')
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

				var createProc = @"
IF OBJECT_ID('dbo.sp_CreateUser', 'P') IS NULL
BEGIN
 EXEC('CREATE PROCEDURE dbo.sp_CreateUser
 @Username NVARCHAR(100),
 @Email NVARCHAR(256),
 @PasswordHash VARBINARY(MAX),
 @PasswordSalt VARBINARY(MAX),
 @CreatedAt DATETIME2,
 @RoleName NVARCHAR(100)
 AS
 BEGIN
  SET NOCOUNT ON;
  DECLARE @Inserted TABLE (Id UNIQUEIDENTIFIER);
  INSERT INTO dbo.Users (Username, Email, PasswordHash, PasswordSalt, CreatedAt)
  OUTPUT inserted.Id INTO @Inserted
  VALUES (@Username, @Email, @PasswordHash, @PasswordSalt, @CreatedAt);
  DECLARE @UserId UNIQUEIDENTIFIER = (SELECT TOP 1 Id FROM @Inserted);
  DECLARE @RoleId UNIQUEIDENTIFIER = (SELECT TOP 1 Id FROM dbo.Roles WHERE Name = @RoleName);
  IF @RoleId IS NOT NULL
  BEGIN
   INSERT INTO dbo.UserRoles (UserId, RoleId) VALUES (@UserId, @RoleId);
  END
  SELECT @UserId;
 END');
END
";
				await using (var cmd = new SqlCommand(createProc, c)) { await cmd.ExecuteNonQueryAsync(); }
			}
			catch
			{
				
			}
		}
	}
}
