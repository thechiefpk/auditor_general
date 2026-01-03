using System;
using System.Collections.Generic;
using System.Data;
using Microsoft.Data.SqlClient;
using System.Threading.Tasks;
using ComplianceSecurityAuditor.Models;
using Dapper;

namespace ComplianceSecurityAuditor.Data
{
    public class SqlScheduleRepository : IScheduleRepository
    {
        private readonly string _connectionString;

        public SqlScheduleRepository(string connectionString)
        {
            _connectionString = connectionString;
            EnsureTableExists();
        }

        private void EnsureTableExists()
        {
            using var conn = new SqlConnection(_connectionString);
            conn.Open();
            var sql = @"
                IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='ScanSchedules' AND xtype='U')
                CREATE TABLE ScanSchedules (
                    Id UNIQUEIDENTIFIER PRIMARY KEY,
                    UserId UNIQUEIDENTIFIER NOT NULL,
                    Frequency NVARCHAR(50) NOT NULL,
                    StartDate DATETIME2 NOT NULL,
                    EndDate DATETIME2 NOT NULL,
                    ScanType NVARCHAR(50) NOT NULL,
                    ConfigJson NVARCHAR(MAX) NOT NULL,
                    LastRun DATETIME2 NULL,
                    NextRun DATETIME2 NOT NULL,
                    IsActive BIT NOT NULL,
                    CreatedAt DATETIME2 NOT NULL
                )";
            conn.Execute(sql);

            var historySql = @"
                IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='ScanExecutionHistory' AND xtype='U')
                CREATE TABLE ScanExecutionHistory (
                    Id UNIQUEIDENTIFIER PRIMARY KEY,
                    ScheduleId UNIQUEIDENTIFIER NOT NULL,
                    ExecutedAt DATETIME2 NOT NULL,
                    Status NVARCHAR(50) NOT NULL,
                    ResultSummary NVARCHAR(MAX) NULL,
                    ErrorMessage NVARCHAR(MAX) NULL,
                    FOREIGN KEY (ScheduleId) REFERENCES ScanSchedules(Id) ON DELETE CASCADE
                )";
            conn.Execute(historySql);
        }

        public async Task<ScanSchedule> CreateAsync(ScanSchedule schedule)
        {
            using var conn = new SqlConnection(_connectionString);
            var sql = @"
                INSERT INTO ScanSchedules (Id, UserId, Frequency, StartDate, EndDate, ScanType, ConfigJson, LastRun, NextRun, IsActive, CreatedAt)
                VALUES (@Id, @UserId, @Frequency, @StartDate, @EndDate, @ScanType, @ConfigJson, @LastRun, @NextRun, @IsActive, @CreatedAt)";
            await conn.ExecuteAsync(sql, schedule);
            return schedule;
        }

        public async Task<IEnumerable<ScanSchedule>> GetByUserIdAsync(Guid userId)
        {
            using var conn = new SqlConnection(_connectionString);
            return await conn.QueryAsync<ScanSchedule>("SELECT * FROM ScanSchedules WHERE UserId = @UserId ORDER BY CreatedAt DESC", new { UserId = userId });
        }

        public async Task<ScanSchedule?> GetByIdAsync(Guid id)
        {
            using var conn = new SqlConnection(_connectionString);
            return await conn.QuerySingleOrDefaultAsync<ScanSchedule>("SELECT * FROM ScanSchedules WHERE Id = @Id", new { Id = id });
        }

        public async Task DeleteAsync(Guid id)
        {
            using var conn = new SqlConnection(_connectionString);
            await conn.ExecuteAsync("DELETE FROM ScanSchedules WHERE Id = @Id", new { Id = id });
        }

        public async Task UpdateAsync(ScanSchedule schedule)
        {
            using var conn = new SqlConnection(_connectionString);
            var sql = @"
                UPDATE ScanSchedules 
                SET Frequency = @Frequency, 
                    StartDate = @StartDate, 
                    EndDate = @EndDate, 
                    ScanType = @ScanType, 
                    ConfigJson = @ConfigJson, 
                    IsActive = @IsActive
                WHERE Id = @Id";
            await conn.ExecuteAsync(sql, schedule);
        }

        public async Task<IEnumerable<ScanSchedule>> GetDueSchedulesAsync()
        {
            using var conn = new SqlConnection(_connectionString);
            // Get active schedules where NextRun is in the past or now, and within the date range
            var sql = @"
                SELECT * FROM ScanSchedules 
                WHERE IsActive = 1 
                AND NextRun <= @Now 
                AND NextRun >= StartDate 
                AND NextRun <= EndDate";
            return await conn.QueryAsync<ScanSchedule>(sql, new { Now = DateTime.UtcNow });
        }

        public async Task UpdateExecutionAsync(Guid id, DateTime lastRun, DateTime nextRun)
        {
            using var conn = new SqlConnection(_connectionString);
            await conn.ExecuteAsync("UPDATE ScanSchedules SET LastRun = @LastRun, NextRun = @NextRun WHERE Id = @Id", new { Id = id, LastRun = lastRun, NextRun = nextRun });
        }

        public async Task UpdateLastRunAsync(Guid id, DateTime lastRun)
        {
            using var conn = new SqlConnection(_connectionString);
            await conn.ExecuteAsync("UPDATE ScanSchedules SET LastRun = @LastRun WHERE Id = @Id", new { Id = id, LastRun = lastRun });
        }

        public async Task AddExecutionHistoryAsync(ScanExecutionHistory history)
        {
            using var conn = new SqlConnection(_connectionString);
            var sql = @"
                INSERT INTO ScanExecutionHistory (Id, ScheduleId, ExecutedAt, Status, ResultSummary, ErrorMessage)
                VALUES (@Id, @ScheduleId, @ExecutedAt, @Status, @ResultSummary, @ErrorMessage)";
            await conn.ExecuteAsync(sql, history);
        }

        public async Task<IEnumerable<ScanExecutionHistory>> GetHistoryAsync(Guid scheduleId)
        {
            using var conn = new SqlConnection(_connectionString);
            return await conn.QueryAsync<ScanExecutionHistory>("SELECT * FROM ScanExecutionHistory WHERE ScheduleId = @ScheduleId ORDER BY ExecutedAt DESC", new { ScheduleId = scheduleId });
        }
    }
}
