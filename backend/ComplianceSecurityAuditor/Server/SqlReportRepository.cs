using ComplianceSecurityAuditor.Models;
using ComplianceSecurityAuditor.Server;
using Microsoft.Data.SqlClient;

namespace ComplianceSecurityAuditor.Data
{
	public class SqlReportRepository : ISqlReportRepository
	{
		private readonly string _connectionString;

		public SqlReportRepository(string connectionString)
		{
			_connectionString = connectionString;
		}

		public Guid SaveReport(string path, ScanSummary summary)
		{
			using var conn = new SqlConnection(_connectionString);
			conn.Open();

			using var tran = conn.BeginTransaction();
			try
			{
				// Insert into Reports table
				var cmd = new SqlCommand(@"INSERT INTO Reports(Path, FilesScanned, ViolationsFound, CreatedAt)
OUTPUT INSERTED.Id
VALUES(@Path, @FilesScanned, @ViolationsFound, @CreatedAt)", conn, tran);
				cmd.Parameters.AddWithValue("@Path", path);
				cmd.Parameters.AddWithValue("@FilesScanned", summary.FilesScanned);
				cmd.Parameters.AddWithValue("@ViolationsFound", summary.ViolationsFound);
				cmd.Parameters.AddWithValue("@CreatedAt", DateTime.UtcNow);

				var id = (Guid)cmd.ExecuteScalar();

				// Insert violations
				foreach (var v in summary.Violations)
				{
					var vcmd = new SqlCommand(@"INSERT INTO Violations(ReportId, FilePath, LineNumber, MatchedText, RuleId, RuleName, Category)
VALUES(@ReportId, @FilePath, @LineNumber, @MatchedText, @RuleId, @RuleName, @Category)", conn, tran);
					vcmd.Parameters.AddWithValue("@ReportId", id);
					vcmd.Parameters.AddWithValue("@FilePath", v.FilePath);
					vcmd.Parameters.AddWithValue("@LineNumber", v.LineNumber);
					vcmd.Parameters.AddWithValue("@MatchedText", v.MatchedText ?? (object)DBNull.Value);
					// AuditRule properties are positional in a record; use property names from AuditRule definition
					vcmd.Parameters.AddWithValue("@RuleId", v.ViolatedRule.RuleId);
					vcmd.Parameters.AddWithValue("@RuleName", v.ViolatedRule.Name);
					vcmd.Parameters.AddWithValue("@Category", v.ViolatedRule.Category);
					vcmd.ExecuteNonQuery();
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

		public ScanStatistics GetStatistics(Guid reportId)
		{
			using var conn = new SqlConnection(_connectionString);
			conn.Open();

			var stats = new ScanStatistics();

			// Basic report info
			var cmd = new SqlCommand("SELECT Path, FilesScanned, ViolationsFound, CreatedAt FROM Reports WHERE Id = @Id", conn);
			cmd.Parameters.AddWithValue("@Id", reportId);
			using var reader = cmd.ExecuteReader();
			if (reader.Read())
			{
				stats.ReportId = reportId;
				stats.Path = reader.GetString(0);
				stats.FilesScanned = reader.GetInt32(1);
				stats.ViolationsFound = reader.GetInt32(2);
				stats.CreatedAt = reader.GetDateTime(3);
			}
			reader.Close();

			// Violations by category
			var vcmd = new SqlCommand("SELECT Category, COUNT(*) FROM Violations WHERE ReportId = @Id GROUP BY Category", conn);
			vcmd.Parameters.AddWithValue("@Id", reportId);
			using var vreader = vcmd.ExecuteReader();
			while (vreader.Read())
			{
				stats.ViolationsByCategory.Add(vreader.GetString(0), vreader.GetInt32(1));
			}

			return stats;
		}
	}
}
