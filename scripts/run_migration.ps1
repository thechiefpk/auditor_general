$connString = "Server=DESKTOP-1AG89BB;Database=secureSoft;Trusted_Connection=True;Encrypt=True;TrustServerCertificate=True;"
$query = @"
IF COL_LENGTH('dbo.ScanProgress','ProcessId') IS NULL
BEGIN
 ALTER TABLE dbo.ScanProgress ADD ProcessId INT NULL;
 PRINT 'Column ProcessId added.'
END
ELSE
BEGIN
 PRINT 'Column ProcessId already exists.'
END
"@

Invoke-Sqlcmd -ConnectionString $connString -Query $query