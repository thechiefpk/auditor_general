using ComplianceSecurityAuditor.Data;
using ComplianceSecurityAuditor.Models;
using ComplianceSecurityAuditor.Library;
using Microsoft.Data.SqlClient;
using static ComplianceSecurityAuditor.Models.Audit;
using System.Linq;
using System.Collections.Generic;

namespace SecureSoftAPI.Data
{
	public class SqlReportRepository : ISqlReportRepository
	{
		private readonly string _connectionString;

		public SqlReportRepository(string connectionString)
		{
			_connectionString = connectionString;
		}

		//		public async Task<Guid> SaveReportAsync(string path, ScanSummary summary)
		//		{
		//			using var conn = new SqlConnection(_connectionString);
		//			await conn.OpenAsync();
		//			using var tran = conn.BeginTransaction();
		//			try
		//			{
		//				// Insert into Reports table
		//				var cmd = new SqlCommand(@"INSERT INTO Reports(Path, FilesScanned, ViolationsFound, CreatedAt)
		//OUTPUT INSERTED.Id
		//VALUES(@Path, @FilesScanned, @ViolationsFound, @CreatedAt)", conn, tran);
		//				cmd.Parameters.AddWithValue("@Path", path);
		//				cmd.Parameters.AddWithValue("@FilesScanned", summary.FilesScanned);
		//				cmd.Parameters.AddWithValue("@ViolationsFound", summary.ViolationsFound);
		//				cmd.Parameters.AddWithValue("@CreatedAt", DateTime.UtcNow);

		//				var id = (Guid)await cmd.ExecuteScalarAsync();

		//				// Insert violations
		//				foreach (var v in summary.Violations)
		//				{
		//					var vcmd = new SqlCommand(@"INSERT INTO Violations(ReportId, FilePath, LineNumber, MatchedText, RuleId, RuleName, Category)
		//VALUES(@ReportId, @FilePath, @LineNumber, @MatchedText, @RuleId, @RuleName, @Category)", conn, tran);
		//					vcmd.Parameters.AddWithValue("@ReportId", id);
		//					vcmd.Parameters.AddWithValue("@FilePath", v.FilePath);
		//					vcmd.Parameters.AddWithValue("@LineNumber", v.LineNumber);
		//					vcmd.Parameters.AddWithValue("@MatchedText", v.MatchedText ?? (object)DBNull.Value);
		//					vcmd.Parameters.AddWithValue("@RuleId", v.ViolatedRule.RuleId);
		//					vcmd.Parameters.AddWithValue("@RuleName", v.ViolatedRule.Name);
		//					vcmd.Parameters.AddWithValue("@Category", v.ViolatedRule.Category);
		//					await vcmd.ExecuteNonQueryAsync();
		//				}

		//				tran.Commit();
		//				return id;
		//			}
		//			catch
		//			{
		//				tran.Rollback();
		//				throw;
		//			}
		//		}

		// CHANGED: Added 'Guid userId' parameter
		public async Task<Guid> SaveReportAsync(Guid userId, string path, ScanSummary summary)
		{
			using var conn = new SqlConnection(_connectionString);
			await conn.OpenAsync();
			using var tran = conn.BeginTransaction();
			try
			{
				// CHANGED: Added UserId to the INSERT statement
				var cmd = new SqlCommand(@"INSERT INTO Reports(UserId, Path, FilesScanned, ViolationsFound, CreatedAt)
OUTPUT INSERTED.Id
VALUES(@UserId, @Path, @FilesScanned, @ViolationsFound, @CreatedAt)", conn, tran);

				// CHANGED: Add the new @UserId parameter
				cmd.Parameters.AddWithValue("@UserId", userId);

				// --- Existing parameters ---
				cmd.Parameters.AddWithValue("@Path", path);
				cmd.Parameters.AddWithValue("@FilesScanned", summary.FilesScanned);
				cmd.Parameters.AddWithValue("@ViolationsFound", summary.ViolationsFound);
				cmd.Parameters.AddWithValue("@CreatedAt", DateTime.UtcNow);

				var id = (Guid)await cmd.ExecuteScalarAsync();

				// --- No changes needed for violations ---
				foreach (var v in summary.Violations)
				{
					var vcmd = new SqlCommand(@"INSERT INTO Violations(ReportId, FilePath, LineNumber, MatchedText, RuleId, RuleName, Category)
VALUES(@ReportId, @FilePath, @LineNumber, @MatchedText, @RuleId, @RuleName, @Category)", conn, tran);
					vcmd.Parameters.AddWithValue("@ReportId", id);
					vcmd.Parameters.AddWithValue("@FilePath", v.FilePath);
					vcmd.Parameters.AddWithValue("@LineNumber", v.LineNumber);
					vcmd.Parameters.AddWithValue("@MatchedText", v.MatchedText ?? (object)DBNull.Value);
					vcmd.Parameters.AddWithValue("@RuleId", v.ViolatedRule.RuleId);
					vcmd.Parameters.AddWithValue("@RuleName", v.ViolatedRule.Name);
					vcmd.Parameters.AddWithValue("@Category", v.ViolatedRule.Category);
					await vcmd.ExecuteNonQueryAsync();
				}

				tran.Commit();
				return id;
			}
			catch
			{
				tran.Rollback();
				throw;
			}
		}

		public async Task<ScanStatistics> GetStatisticsAsync(Guid reportId)
		{
			using var conn = new SqlConnection(_connectionString);
			await conn.OpenAsync();

			var stats = new ScanStatistics();

			// Basic report info
			var cmd = new SqlCommand("SELECT Path, FilesScanned, ViolationsFound, CreatedAt FROM Reports WHERE Id = @Id", conn);
			cmd.Parameters.AddWithValue("@Id", reportId);
			using var reader = await cmd.ExecuteReaderAsync();
			if (await reader.ReadAsync())
			{
				stats.ReportId = reportId;
				stats.Path = reader.GetString(0);
				stats.FilesScanned = reader.GetInt32(1);
				stats.ViolationsFound = reader.GetInt32(2);
				stats.CreatedAt = reader.GetDateTime(3);
			}
			await reader.CloseAsync();

            // Calculate duration from ScanProgress
            var dcmd = new SqlCommand("SELECT DATEDIFF(SECOND, StartedAt, CompletedAt) FROM ScanProgress WHERE ReportId = @Id", conn);
            dcmd.Parameters.AddWithValue("@Id", reportId);
            var durationObj = await dcmd.ExecuteScalarAsync();
            if (durationObj != null && durationObj != DBNull.Value)
            {
                stats.ScanDuration = Convert.ToDouble(durationObj);
            }

			// Violations by category
			var vcmd = new SqlCommand("SELECT Category, COUNT(*) FROM Violations WHERE ReportId = @Id GROUP BY Category", conn);
			vcmd.Parameters.AddWithValue("@Id", reportId);
			using var vreader = await vcmd.ExecuteReaderAsync();
			while (await vreader.ReadAsync())
			{
				var cat = vreader.GetString(0);
				var count = vreader.GetInt32(1);
				stats.ViolationsByCategory.Add(cat, count);

                // Infer severity from category for now
                var sev = cat switch {
                    "HIPAA" => "critical",
                    "Financial" => "critical",
                    "GDPR" => "high",
                    "Security" => "high",
                    "Database" => "medium",
                    _ => "low"
                };
                if (stats.ViolationsBySeverity.ContainsKey(sev))
                    stats.ViolationsBySeverity[sev] += count;
                else
                    stats.ViolationsBySeverity[sev] = count;
			}
			await vreader.CloseAsync();

            // Violations by File Type (Extension)
            // Extract extension using SQL if possible, or simple string manipulation.
            // Since FilePath is standard, we can use RIGHT/CHARINDEX/REVERSE logic or just grab all file paths and process in memory if dataset is small, 
            // but SQL is better.
            // SQL Server: REVERSE(LEFT(REVERSE(FilePath), CHARINDEX('.', REVERSE(FilePath)) - 1)) gets 'cs' from 'file.cs'
            // But let's be safer and just get counts by FilePath ending
            var fcmd = new SqlCommand(@"
                SELECT 
                    CASE 
                        WHEN CHARINDEX('.', REVERSE(FilePath)) > 0 
                        THEN RIGHT(FilePath, CHARINDEX('.', REVERSE(FilePath)) - 1)
                        ELSE 'unknown'
                    END as Extension,
                    COUNT(*) 
                FROM Violations 
                WHERE ReportId = @Id 
                GROUP BY 
                    CASE 
                        WHEN CHARINDEX('.', REVERSE(FilePath)) > 0 
                        THEN RIGHT(FilePath, CHARINDEX('.', REVERSE(FilePath)) - 1)
                        ELSE 'unknown'
                    END", conn);
            fcmd.Parameters.AddWithValue("@Id", reportId);
            using var freader = await fcmd.ExecuteReaderAsync();
            while (await freader.ReadAsync())
            {
                var ext = freader.GetString(0).ToLowerInvariant();
                var count = freader.GetInt32(1);
                if (!ext.StartsWith(".")) ext = "." + ext; // Ensure dot prefix
                
                stats.ViolationsByFileType[ext] = count;
            }
            await freader.CloseAsync();

            // Top Violations with Recommendations
            var tcmd = new SqlCommand(@"
                SELECT TOP 5 RuleId, RuleName, Category, COUNT(*) as Count 
                FROM Violations 
                WHERE ReportId = @Id 
                GROUP BY RuleId, RuleName, Category 
                ORDER BY Count DESC", conn);
            tcmd.Parameters.AddWithValue("@Id", reportId);
            
            using var treader = await tcmd.ExecuteReaderAsync();
            while (await treader.ReadAsync())
            {
                var ruleId = treader.GetString(0);
                var ruleName = treader.GetString(1);
                var cat = treader.GetString(2);
                var count = treader.GetInt32(3);

                var (solution, reference) = RemediationHelper.GetRemediation(ruleId, cat);

                stats.TopViolations.Add(new TopViolation
                {
                    RuleId = ruleId,
                    RuleName = ruleName,
                    Category = cat,
                    Count = count,
                    SuggestiveSolution = solution,
                    ReferenceUrl = reference
                });
            }

			return stats;
		}

		public async Task<ScanSummary> GetReportAsync(Guid reportId)
		{
			using var conn = new SqlConnection(_connectionString);
			await conn.OpenAsync();

			var summary = new ScanSummary { Violations = new List<Violation>() };

			// Read report
			var cmd = new SqlCommand("SELECT Path, FilesScanned, ViolationsFound, CreatedAt FROM Reports WHERE Id = @Id", conn);
			cmd.Parameters.AddWithValue("@Id", reportId);
			using var reader = await cmd.ExecuteReaderAsync();
			if (await reader.ReadAsync())
			{
				summary.ScanPath = reader.GetString(0);
				summary.FilesScanned = reader.GetInt32(1);
				summary.ViolationsFound = reader.GetInt32(2);
				summary.ScanDate = reader.GetDateTime(3);
				summary.ReportId = reportId;
			}
			await reader.CloseAsync();

			// Read violations
			var vcmd = new SqlCommand("SELECT FilePath, LineNumber, MatchedText, RuleId, RuleName, Category FROM Violations WHERE ReportId = @Id ORDER BY FilePath, LineNumber", conn);
			vcmd.Parameters.AddWithValue("@Id", reportId);
			using var vreader = await vcmd.ExecuteReaderAsync();
			while (await vreader.ReadAsync())
			{
				var file = vreader.GetString(0);
				var line = vreader.GetInt32(1);
				var matched = vreader.IsDBNull(2) ? string.Empty : vreader.GetString(2);
				var ruleId = vreader.GetString(3);
				var ruleName = vreader.GetString(4);
				var category = vreader.GetString(5);

				var rule = new AuditRule(ruleId, ruleName, category, string.Empty, null!);
				var violation = new Violation(file, line, matched, rule);
				summary.Violations.Add(violation);
			}

			return summary;
		}

		public async Task<PagedResult<Violation>> GetViolationsPagedAsync(Guid reportId, int page, int pageSize, string? category = null, string? q = null, string sortBy = "filePath", string sortDir = "asc")
		{
			using var conn = new SqlConnection(_connectionString);
			await conn.OpenAsync();

			var offset = (page -1) * pageSize;
			var result = new PagedResult<Violation>();

			// Build base WHERE clause and parameters
			var where = "WHERE ReportId = @Id";
			var cmd = new SqlCommand();
			cmd.Connection = conn;
			cmd.Parameters.AddWithValue("@Id", reportId);

			if (!string.IsNullOrWhiteSpace(category))
			{
				where += " AND LOWER(Category) = LOWER(@Category)";
				cmd.Parameters.AddWithValue("@Category", category);
			}

			if (!string.IsNullOrWhiteSpace(q))
			{
			 where += " AND (LOWER(FilePath) LIKE @Q OR LOWER(RuleName) LIKE @Q OR LOWER(MatchedText) LIKE @Q)";
				cmd.Parameters.AddWithValue("@Q", $"%{q.ToLowerInvariant()}%");
			}

			// total count
			var countCmd = new SqlCommand($"SELECT COUNT(*) FROM Violations {where}", conn);
			foreach (SqlParameter p in cmd.Parameters) countCmd.Parameters.Add(p.ParameterName, p.SqlDbType).Value = p.Value;
			result.Total = (int)await countCmd.ExecuteScalarAsync();

			// map safe sort columns
			var safeSort = sortBy switch
			{
				"filePath" => "FilePath",
				"lineNumber" => "LineNumber",
				"ruleName" => "RuleName",
				_ => "FilePath"
			};
			var dir = sortDir?.ToLowerInvariant() == "desc" ? "DESC" : "ASC";

			var qText = $@"SELECT FilePath, LineNumber, MatchedText, RuleId, RuleName, Category FROM Violations {where} ORDER BY {safeSort} {dir} OFFSET @Offset ROWS FETCH NEXT @PageSize ROWS ONLY";
			var fetchCmd = new SqlCommand(qText, conn);
			foreach (SqlParameter p in cmd.Parameters) fetchCmd.Parameters.Add(p.ParameterName, p.SqlDbType).Value = p.Value;
			fetchCmd.Parameters.AddWithValue("@Offset", offset);
			fetchCmd.Parameters.AddWithValue("@PageSize", pageSize);

			using var reader = await fetchCmd.ExecuteReaderAsync();
			while (await reader.ReadAsync())
			{
				var file = reader.GetString(0);
				var line = reader.GetInt32(1);
				var matched = reader.IsDBNull(2) ? string.Empty : reader.GetString(2);
				var ruleId = reader.GetString(3);
				var ruleName = reader.GetString(4);
				var fileCategory = reader.GetString(5);

				var rule = new AuditRule(ruleId, ruleName, fileCategory, string.Empty, null!);
				var violation = new Violation(file, line, matched, rule);
				result.Items.Add(violation);
			}

			return result;
		}

		public async Task<List<TopFile>> GetTopFilesAsync(Guid reportId, int limit =10)
		{
			using var conn = new SqlConnection(_connectionString);
			await conn.OpenAsync();

			var q = @"SELECT TOP(@Limit) FilePath, COUNT(*) AS Violations FROM Violations WHERE ReportId = @Id GROUP BY FilePath ORDER BY Violations DESC";
			var cmd = new SqlCommand(q, conn);
			cmd.Parameters.AddWithValue("@Id", reportId);
			cmd.Parameters.AddWithValue("@Limit", limit);

			var list = new List<TopFile>();
			using var reader = await cmd.ExecuteReaderAsync();
			while (await reader.ReadAsync())
			{
				list.Add(new TopFile { FilePath = reader.GetString(0), Violations = reader.GetInt32(1) });
			}
			return list;
		}

		public async Task<List<ScanSummary>> GetReportsByUserAsync(Guid userId)
		{
			using var conn = new SqlConnection(_connectionString);
			await conn.OpenAsync();

			var list = new List<ScanSummary>();

			// First get basic report info
			var cmd = new SqlCommand("SELECT Id, Path, FilesScanned, ViolationsFound, CreatedAt FROM Reports WHERE UserId = @UserId ORDER BY CreatedAt DESC", conn);
			cmd.Parameters.AddWithValue("@UserId", userId);

			using var reader = await cmd.ExecuteReaderAsync();
			var reportIds = new List<Guid>();
			var meta = new Dictionary<Guid, (string Path, int FilesScanned, int ViolationsFound, DateTime CreatedAt)>();
			while (await reader.ReadAsync())
			{
				var id = reader.GetGuid(0);
				reportIds.Add(id);
				meta[id] = (reader.GetString(1), reader.GetInt32(2), reader.GetInt32(3), reader.GetDateTime(4));
			}
			await reader.CloseAsync();

			if (reportIds.Count == 0) return list;

			// Fetch violations for all reportIds in one query
			var idsParam = string.Join(",", reportIds.Select((_, idx) => "@id" + idx));
			var vcmdText = $@"SELECT ReportId, FilePath, LineNumber, MatchedText, RuleId, RuleName, Category
							  FROM Violations
							  WHERE ReportId IN ({idsParam})
							  ORDER BY ReportId, FilePath, LineNumber";

			var vcmd = new SqlCommand(vcmdText, conn);
			for (int i = 0; i < reportIds.Count; i++)
			{
				vcmd.Parameters.AddWithValue("@id" + i, reportIds[i]);
			}

			var violationsByReport = new Dictionary<Guid, List<Violation>>();
			using var vreader = await vcmd.ExecuteReaderAsync();
			while (await vreader.ReadAsync())
			{
				var rid = vreader.GetGuid(0);
				var file = vreader.GetString(1);
				var line = vreader.GetInt32(2);
				var matched = vreader.IsDBNull(3) ? string.Empty : vreader.GetString(3);
				var ruleId = vreader.GetString(4);
				var ruleName = vreader.GetString(5);
				var category = vreader.GetString(6);

				var rule = new AuditRule(ruleId, ruleName, category, string.Empty, null!);
				var violation = new Violation(file, line, matched, rule);

				if (!violationsByReport.TryGetValue(rid, out var listFor))
				{
					listFor = new List<Violation>();
					violationsByReport[rid] = listFor;
				}
				listFor.Add(violation);
			}

			// Build ScanSummary objects
			foreach (var rid in reportIds)
			{
				var m = meta[rid];
				var summary = new ScanSummary
				{
					FilesScanned = m.FilesScanned,
					ViolationsFound = m.ViolationsFound,
					Violations = violationsByReport.TryGetValue(rid, out var vlist) ? vlist : new List<Violation>(),
					ReportId = rid,
					ScanDate = m.CreatedAt,
					ScanPath = m.Path
				};
				list.Add(summary);
			}

			return list;
		}

		public async Task<bool> DeleteReportAsync(Guid userId, Guid reportId)
		{
			using var conn = new SqlConnection(_connectionString);
			await conn.OpenAsync();

			// Ensure only the owner can delete the report
			var cmd = new SqlCommand("DELETE FROM Reports WHERE Id = @Id AND UserId = @UserId", conn);
			cmd.Parameters.AddWithValue("@Id", reportId);
			cmd.Parameters.AddWithValue("@UserId", userId);
			var affected = await cmd.ExecuteNonQueryAsync();
			return affected > 0;
		}

		public async Task<List<Violation>> GetViolationsAllAsync(Guid reportId)
		{
			using var conn = new SqlConnection(_connectionString);
			await conn.OpenAsync();

			var list = new List<Violation>();
			var q = @"SELECT FilePath, LineNumber, MatchedText, RuleId, RuleName, Category 
					  FROM Violations 
					  WHERE ReportId = @Id 
					  ORDER BY FilePath, LineNumber";
			var cmd = new SqlCommand(q, conn);
			cmd.Parameters.AddWithValue("@Id", reportId);

			using var reader = await cmd.ExecuteReaderAsync();
			while (await reader.ReadAsync())
			{
				var file = reader.GetString(0);
				var line = reader.GetInt32(1);
				var matched = reader.IsDBNull(2) ? string.Empty : reader.GetString(2);
				var ruleId = reader.GetString(3);
				var ruleName = reader.GetString(4);
				var category = reader.GetString(5);
				var rule = new AuditRule(ruleId, ruleName, category, string.Empty, null!);
				list.Add(new Violation(file, line, matched, rule));
			}

			return list;
		}
	}
}
