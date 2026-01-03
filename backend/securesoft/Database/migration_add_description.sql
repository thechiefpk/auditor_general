IF COL_LENGTH('dbo.Violations','Description') IS NULL
BEGIN
    ALTER TABLE dbo.Violations ADD Description NVARCHAR(MAX) NULL;
    PRINT 'Column Description added.'
END

IF COL_LENGTH('dbo.Violations','Remediation') IS NULL
BEGIN
    ALTER TABLE dbo.Violations ADD Remediation NVARCHAR(MAX) NULL;
    PRINT 'Column Remediation added.'
END

IF COL_LENGTH('dbo.Violations','Severity') IS NULL
BEGIN
    ALTER TABLE dbo.Violations ADD Severity NVARCHAR(50) NULL;
    PRINT 'Column Severity added.'
END

IF COL_LENGTH('dbo.Violations','ReferenceUrl') IS NULL
BEGIN
    ALTER TABLE dbo.Violations ADD ReferenceUrl NVARCHAR(500) NULL;
    PRINT 'Column ReferenceUrl added.'
END