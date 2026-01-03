IF COL_LENGTH('dbo.ScanProgress','ProcessId') IS NULL
BEGIN
 ALTER TABLE dbo.ScanProgress ADD ProcessId INT NULL;
END
