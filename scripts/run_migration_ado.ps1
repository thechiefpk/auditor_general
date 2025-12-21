$connString = "Server=DESKTOP-1AG89BB;Database=secureSoft;Trusted_Connection=True;Encrypt=True;TrustServerCertificate=True;"
$query = @"
IF COL_LENGTH('dbo.ScanProgress','ProcessId') IS NULL
BEGIN
 ALTER TABLE dbo.ScanProgress ADD ProcessId INT NULL;
 SELECT 'Column ProcessId added.'
END
ELSE
BEGIN
 SELECT 'Column ProcessId already exists.'
END
"@

$conn = New-Object System.Data.SqlClient.SqlConnection
$conn.ConnectionString = $connString
$conn.Open()
$cmd = $conn.CreateCommand()
$cmd.CommandText = $query
$result = $cmd.ExecuteScalar()
Write-Host $result
$conn.Close()