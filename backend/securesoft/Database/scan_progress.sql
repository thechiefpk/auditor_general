IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'ScanProgress' AND type = 'U')
BEGIN
 CREATE TABLE dbo.ScanProgress (
  JobId NVARCHAR(64) NOT NULL PRIMARY KEY,
  UserId UNIQUEIDENTIFIER NOT NULL,
  Status NVARCHAR(32) NOT NULL,
  Stage NVARCHAR(32) NULL,
  TotalFiles INT NOT NULL DEFAULT 0,
  ProcessedFiles INT NOT NULL DEFAULT 0,
  ViolationsFound INT NOT NULL DEFAULT 0,
  Percentage INT NOT NULL DEFAULT 0,
  ReportId UNIQUEIDENTIFIER NULL,
  StartedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
  CompletedAt DATETIME2 NULL,
  UpdatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
  Error NVARCHAR(1000) NULL
 );
 CREATE INDEX IX_ScanProgress_Status ON dbo.ScanProgress(Status);
 CREATE INDEX IX_ScanProgress_User ON dbo.ScanProgress(UserId);
END

IF COL_LENGTH('dbo.ScanProgress','HangfireId') IS NULL
BEGIN
 ALTER TABLE dbo.ScanProgress ADD HangfireId NVARCHAR(64) NULL;
END

IF COL_LENGTH('dbo.ScanProgress','CancelRequested') IS NULL
BEGIN
 ALTER TABLE dbo.ScanProgress ADD CancelRequested BIT NOT NULL DEFAULT(0);
END
