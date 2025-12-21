USE secureSoft;
GO

-- Migration script to add Severity, Remediation, and ReferenceUrl to Violations table

BEGIN TRANSACTION;

BEGIN TRY
    -- Add Severity column if it doesn't exist
    IF COL_LENGTH('dbo.Violations', 'Severity') IS NULL
    BEGIN
        ALTER TABLE dbo.Violations ADD Severity NVARCHAR(50) NULL;
        PRINT 'Added Severity column to Violations table.';
    END

    -- Add Remediation column if it doesn't exist
    IF COL_LENGTH('dbo.Violations', 'Remediation') IS NULL
    BEGIN
        ALTER TABLE dbo.Violations ADD Remediation NVARCHAR(MAX) NULL;
        PRINT 'Added Remediation column to Violations table.';
    END

    -- Add ReferenceUrl column if it doesn't exist
    IF COL_LENGTH('dbo.Violations', 'ReferenceUrl') IS NULL
    BEGIN
        ALTER TABLE dbo.Violations ADD ReferenceUrl NVARCHAR(2048) NULL;
        PRINT 'Added ReferenceUrl column to Violations table.';
    END

    -- Optional: Update existing records with default values if needed
    -- For example, set Severity to 'Medium' where it is NULL
    -- UPDATE dbo.Violations SET Severity = 'Medium' WHERE Severity IS NULL;

    COMMIT TRANSACTION;
    PRINT 'Migration completed successfully.';
END TRY
BEGIN CATCH
    ROLLBACK TRANSACTION;
    PRINT 'Error occurred during migration: ' + ERROR_MESSAGE();
END CATCH;
GO
