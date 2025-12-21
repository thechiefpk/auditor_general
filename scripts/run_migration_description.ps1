$connString = "Server=DESKTOP-1AG89BB;Database=secureSoft;Trusted_Connection=True;Encrypt=True;TrustServerCertificate=True;"
$query = Get-Content "c:\Users\sover\Desktop\Auditor_General\backend\ComplianceSecurityAuditor\Database\migration_add_description.sql" -Raw

Invoke-Sqlcmd -ConnectionString $connString -Query $query