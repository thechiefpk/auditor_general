IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='NetworkAudits' AND xtype='U')
CREATE TABLE NetworkAudits (
    Id UNIQUEIDENTIFIER PRIMARY KEY,
    UserId UNIQUEIDENTIFIER NOT NULL,
    Url NVARCHAR(2048) NOT NULL,
    StatusCode INT NOT NULL,
    StatusReason NVARCHAR(255) NULL,
    SecurityScore INT NOT NULL,
    CreatedAt DATETIME2 NOT NULL,
    JsonResult NVARCHAR(MAX) NOT NULL -- Stores headers, SSL info, ports, PII, etc.
);
