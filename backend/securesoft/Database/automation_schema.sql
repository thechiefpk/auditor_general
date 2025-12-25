IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'ScanSchedules')
BEGIN
    CREATE TABLE ScanSchedules (
        Id UNIQUEIDENTIFIER PRIMARY KEY,
        UserId UNIQUEIDENTIFIER NOT NULL,
        Frequency NVARCHAR(50) NOT NULL,
        StartDate DATETIME NOT NULL,
        EndDate DATETIME NOT NULL,
        ScanType NVARCHAR(50) NOT NULL,
        ConfigJson NVARCHAR(MAX) NOT NULL,
        LastRun DATETIME NULL,
        NextRun DATETIME NOT NULL,
        IsActive BIT NOT NULL DEFAULT 1,
        CreatedAt DATETIME NOT NULL DEFAULT GETDATE()
    );
END

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'ScanExecutionHistory')
BEGIN
    CREATE TABLE ScanExecutionHistory (
        Id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        ScheduleId UNIQUEIDENTIFIER NOT NULL,
        ExecutedAt DATETIME NOT NULL DEFAULT GETDATE(),
        Status NVARCHAR(50) NOT NULL, -- 'Success', 'Failed'
        ResultSummary NVARCHAR(MAX) NULL, -- Could be report ID or text
        ErrorMessage NVARCHAR(MAX) NULL,
        FOREIGN KEY (ScheduleId) REFERENCES ScanSchedules(Id) ON DELETE CASCADE
    );
END
