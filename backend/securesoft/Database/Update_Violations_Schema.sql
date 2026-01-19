USE secureSoft;
GO

-- Expand columns to handle long Semgrep rule IDs and names
ALTER TABLE dbo.Violations ALTER COLUMN RuleId NVARCHAR(512) NOT NULL;
ALTER TABLE dbo.Violations ALTER COLUMN RuleName NVARCHAR(512) NOT NULL;
GO
