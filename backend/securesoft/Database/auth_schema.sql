
USE secureSoft;

-- Authentication schema for SecureSoft API (SQL Server)
-- Run this script in your secureSoft database.


SET NOCOUNT ON;

-- Users table
IF OBJECT_ID('dbo.Users', 'U') IS NULL
BEGIN
 CREATE TABLE dbo.Users (
 Id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
 Username NVARCHAR(100) NOT NULL UNIQUE,
 Email NVARCHAR(256) NOT NULL UNIQUE,
 PasswordHash VARBINARY(512) NULL,
 PasswordSalt VARBINARY(128) NULL,
 IsEmailConfirmed BIT NOT NULL DEFAULT 0,
 CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
 LastLoginAt DATETIME2 NULL,
 FailedLoginCount INT NOT NULL DEFAULT 0,
 LockoutEndAt DATETIME2 NULL,
 IsDisabled BIT NOT NULL DEFAULT 0
 );
 CREATE INDEX IX_Users_Username ON dbo.Users(Username);
 CREATE INDEX IX_Users_Email ON dbo.Users(Email);
END

-- Roles table
IF OBJECT_ID('dbo.Roles', 'U') IS NULL
BEGIN
 CREATE TABLE dbo.Roles (
 Id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
 Name NVARCHAR(100) NOT NULL UNIQUE,
 Description NVARCHAR(400) NULL
 );
INSERT INTO dbo.Roles (Name)
SELECT v FROM (VALUES ('Admin'), ('User')) AS t(v);
END

-- UserRoles (many-to-many)
IF OBJECT_ID('dbo.UserRoles', 'U') IS NULL
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

-- Refresh tokens for issuing/rotating refresh tokens (store hashed token)
IF OBJECT_ID('dbo.RefreshTokens', 'U') IS NULL
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
 CONSTRAINT FK_RefreshTokens_Users FOREIGN KEY (UserId) REFERENCES dbo.Users(Id) ON DELETE CASCADE
 );
 CREATE INDEX IX_RefreshTokens_UserId ON dbo.RefreshTokens(UserId);
 CREATE INDEX IX_RefreshTokens_TokenHash ON dbo.RefreshTokens(TokenHash);
END

-- Optional: Audit table for login events
IF OBJECT_ID('dbo.AuthAudit', 'U') IS NULL
BEGIN
 CREATE TABLE dbo.AuthAudit (
 Id BIGINT IDENTITY(1,1) PRIMARY KEY,
 UserId UNIQUEIDENTIFIER NULL,
 EventType NVARCHAR(50) NOT NULL,
 EventAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
 IpAddress NVARCHAR(45) NULL,
 Details NVARCHAR(1000) NULL
 );
 CREATE INDEX IX_AuthAudit_UserId ON dbo.AuthAudit(UserId);
END

-- Helpful view: users with roles
IF OBJECT_ID('dbo.vw_UserRoles', 'V') IS NULL
BEGIN
 EXEC('CREATE VIEW dbo.vw_UserRoles AS
 SELECT u.Id AS UserId, u.Username, u.Email, r.Id AS RoleId, r.Name AS RoleName
 FROM dbo.Users u
 LEFT JOIN dbo.UserRoles ur ON ur.UserId = u.Id
 LEFT JOIN dbo.Roles r ON r.Id = ur.RoleId');
END

-- NOTES:
--1) Password hashing should be done on the server side using a strong algorithm (e.g. bcrypt/Argon2). Store the resulting hash in PasswordHash and any salt if used in PasswordSalt.
--2) Refresh token values should be stored hashed (e.g. SHA256 of the token) and the plaintext token returned only once to the client.
--3) Create appropriate indexes based on your query patterns. Consider adding an index on (ReportId) in Violations table if not present.

PRINT 'Auth schema created/verified.';
