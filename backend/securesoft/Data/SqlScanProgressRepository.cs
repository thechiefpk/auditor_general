using ComplianceSecurityAuditor.Models;
using Microsoft.Data.SqlClient;
using System.Data;

namespace ComplianceSecurityAuditor.Data
{
    public class SqlScanProgressRepository : IScanProgressRepository
    {
        private readonly string _connectionString;
        public SqlScanProgressRepository(string connectionString)
        {
            _connectionString = connectionString;
        }

        public async Task StartAsync(string jobId, Guid userId, string stage, string hangfireId)
        {
            await using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            var q = @"MERGE dbo.ScanProgress AS t
USING (SELECT @JobId AS JobId) AS s ON s.JobId = t.JobId
WHEN MATCHED THEN
 UPDATE SET Status = @Status, Stage = @Stage, TotalFiles = 0, ProcessedFiles = 0, ViolationsFound = 0, Percentage = 0, ReportId = NULL, StartedAt = COALESCE(t.StartedAt, SYSUTCDATETIME()), UpdatedAt = SYSUTCDATETIME(), CompletedAt = NULL, Error = NULL, UserId = @UserId, HangfireId = @HangfireId, CancelRequested = 0
WHEN NOT MATCHED THEN
 INSERT (JobId, UserId, Status, Stage, TotalFiles, ProcessedFiles, ViolationsFound, Percentage, ReportId, StartedAt, UpdatedAt, CompletedAt, Error, HangfireId, CancelRequested)
 VALUES (@JobId, @UserId, @Status, @Stage, 0, 0, 0, 0, NULL, SYSUTCDATETIME(), SYSUTCDATETIME(), NULL, NULL, @HangfireId, 0);";
            await using var cmd = new SqlCommand(q, conn);
            cmd.Parameters.Add(new SqlParameter("@JobId", SqlDbType.NVarChar, 64) { Value = jobId });
            cmd.Parameters.Add(new SqlParameter("@UserId", SqlDbType.UniqueIdentifier) { Value = userId });
            cmd.Parameters.Add(new SqlParameter("@Status", SqlDbType.NVarChar, 32) { Value = "Queued" });
            cmd.Parameters.Add(new SqlParameter("@Stage", SqlDbType.NVarChar, 32) { Value = stage });
            cmd.Parameters.Add(new SqlParameter("@HangfireId", SqlDbType.NVarChar, 64) { Value = hangfireId });
            await cmd.ExecuteNonQueryAsync();
        }

        public async Task UpdateAsync(string jobId, string status, string stage, int totalFiles, int processedFiles, int violationsFound, int percentage)
        {
            await using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            var q = @"UPDATE dbo.ScanProgress SET Status=@Status, Stage=@Stage, TotalFiles=@TotalFiles, ProcessedFiles=@ProcessedFiles, ViolationsFound=@ViolationsFound, Percentage=@Percentage, UpdatedAt=SYSUTCDATETIME() WHERE JobId=@JobId";
            await using var cmd = new SqlCommand(q, conn);
            cmd.Parameters.Add(new SqlParameter("@JobId", SqlDbType.NVarChar, 64) { Value = jobId });
            cmd.Parameters.Add(new SqlParameter("@Status", SqlDbType.NVarChar, 32) { Value = status });
            cmd.Parameters.Add(new SqlParameter("@Stage", SqlDbType.NVarChar, 32) { Value = stage });
            cmd.Parameters.Add(new SqlParameter("@TotalFiles", SqlDbType.Int) { Value = totalFiles });
            cmd.Parameters.Add(new SqlParameter("@ProcessedFiles", SqlDbType.Int) { Value = processedFiles });
            cmd.Parameters.Add(new SqlParameter("@ViolationsFound", SqlDbType.Int) { Value = violationsFound });
            cmd.Parameters.Add(new SqlParameter("@Percentage", SqlDbType.Int) { Value = percentage });
            await cmd.ExecuteNonQueryAsync();
        }

        public async Task CompleteAsync(string jobId, Guid reportId)
        {
            await using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            var q = @"UPDATE dbo.ScanProgress SET Status='Completed', Stage='Completed', Percentage=100, ReportId=@ReportId, CompletedAt=SYSUTCDATETIME(), UpdatedAt=SYSUTCDATETIME() WHERE JobId=@JobId";
            await using var cmd = new SqlCommand(q, conn);
            cmd.Parameters.Add(new SqlParameter("@JobId", SqlDbType.NVarChar, 64) { Value = jobId });
            cmd.Parameters.Add(new SqlParameter("@ReportId", SqlDbType.UniqueIdentifier) { Value = reportId });
            await cmd.ExecuteNonQueryAsync();
        }

        public async Task FailAsync(string jobId, string error)
        {
            await using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            var q = @"UPDATE dbo.ScanProgress SET Status='Failed', Stage='Failed', Error=@Error, UpdatedAt=SYSUTCDATETIME() WHERE JobId=@JobId";
            await using var cmd = new SqlCommand(q, conn);
            cmd.Parameters.Add(new SqlParameter("@JobId", SqlDbType.NVarChar, 64) { Value = jobId });
            cmd.Parameters.Add(new SqlParameter("@Error", SqlDbType.NVarChar, 1000) { Value = error });
            await cmd.ExecuteNonQueryAsync();
        }

        public async Task<ScanProgress?> GetAsync(string jobId)
        {
            await using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            var q = @"SELECT JobId, UserId, Status, Stage, TotalFiles, ProcessedFiles, ViolationsFound, Percentage, ReportId, StartedAt, CompletedAt, UpdatedAt, Error FROM dbo.ScanProgress WHERE JobId=@JobId";
            await using var cmd = new SqlCommand(q, conn);
            cmd.Parameters.Add(new SqlParameter("@JobId", SqlDbType.NVarChar, 64) { Value = jobId });
            await using var reader = await cmd.ExecuteReaderAsync();
            if (!await reader.ReadAsync()) return null;
            var sp = new ScanProgress
            {
                JobId = reader.GetString(0),
                UserId = reader.GetGuid(1),
                Status = reader.GetString(2),
                Stage = reader.GetString(3),
                TotalFiles = reader.GetInt32(4),
                ProcessedFiles = reader.GetInt32(5),
                ViolationsFound = reader.GetInt32(6),
                Percentage = reader.GetInt32(7),
                ReportId = reader.IsDBNull(8) ? null : reader.GetGuid(8),
                StartedAt = reader.GetDateTime(9),
                CompletedAt = reader.IsDBNull(10) ? null : reader.GetDateTime(10),
                UpdatedAt = reader.GetDateTime(11),
                Error = reader.IsDBNull(12) ? null : reader.GetString(12)
            };
            return sp;
        }

        public async Task RequestCancelAsync(string jobId)
        {
            await using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            var q = @"UPDATE dbo.ScanProgress SET CancelRequested = 1, UpdatedAt = SYSUTCDATETIME() WHERE JobId=@JobId";
            await using var cmd = new SqlCommand(q, conn);
            cmd.Parameters.Add(new SqlParameter("@JobId", SqlDbType.NVarChar, 64) { Value = jobId });
            await cmd.ExecuteNonQueryAsync();
        }

        public async Task<bool> IsCancelRequestedAsync(string jobId)
        {
            await using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            var q = @"SELECT CancelRequested FROM dbo.ScanProgress WHERE JobId=@JobId";
            await using var cmd = new SqlCommand(q, conn);
            cmd.Parameters.Add(new SqlParameter("@JobId", SqlDbType.NVarChar, 64) { Value = jobId });
            var result = await cmd.ExecuteScalarAsync();
            return result is bool b && b;
        }

        public async Task UpdateProcessIdAsync(string jobId, int processId)
        {
            await using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            var q = @"UPDATE dbo.ScanProgress SET ProcessId = @ProcessId WHERE JobId=@JobId";
            await using var cmd = new SqlCommand(q, conn);
            cmd.Parameters.Add(new SqlParameter("@JobId", SqlDbType.NVarChar, 64) { Value = jobId });
            cmd.Parameters.Add(new SqlParameter("@ProcessId", SqlDbType.Int) { Value = processId });
            await cmd.ExecuteNonQueryAsync();
        }

        public async Task<int?> GetProcessIdAsync(string jobId)
        {
            await using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            var q = @"SELECT ProcessId FROM dbo.ScanProgress WHERE JobId=@JobId";
            await using var cmd = new SqlCommand(q, conn);
            cmd.Parameters.Add(new SqlParameter("@JobId", SqlDbType.NVarChar, 64) { Value = jobId });
            var result = await cmd.ExecuteScalarAsync();
            if (result == null || result == DBNull.Value) return null;
            return (int)result;
        }

        public async Task<int> GetActiveCountAsync(Guid userId)
        {
            await using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            var q = @"SELECT COUNT(*) FROM dbo.ScanProgress WHERE UserId=@UserId AND Status IN ('Queued','Cloning','Scanning','Saving')";
            await using var cmd = new SqlCommand(q, conn);
            cmd.Parameters.Add(new SqlParameter("@UserId", SqlDbType.UniqueIdentifier) { Value = userId });
            var result = await cmd.ExecuteScalarAsync();
            return (result is int i) ? i : Convert.ToInt32(result);
        }

        public async Task MarkCancelledAsync(string jobId, Guid reportId)
        {
            await using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            var q = @"UPDATE dbo.ScanProgress SET Status='Cancelled', Stage='Cancelled', ReportId=@ReportId, CompletedAt=SYSUTCDATETIME(), UpdatedAt=SYSUTCDATETIME() WHERE JobId=@JobId";
            await using var cmd = new SqlCommand(q, conn);
            cmd.Parameters.Add(new SqlParameter("@JobId", SqlDbType.NVarChar, 64) { Value = jobId });
            cmd.Parameters.Add(new SqlParameter("@ReportId", SqlDbType.UniqueIdentifier) { Value = reportId });
            await cmd.ExecuteNonQueryAsync();
        }
    }
}
