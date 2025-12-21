using System.Text.RegularExpressions;
using System.Text.Json.Serialization;

namespace ComplianceSecurityAuditor.Models
{
	public class Audit
	{
		public enum AuditSeverity
		{
			Low,
			Medium,
			High,
			Critical
		}

		/// <summary>
		/// Represents a single compliance rule for the scanner.
		/// </summary>
		public record AuditRule(
			string RuleId,
			string Name,
			string Category, // e.g., "GDPR", "HIPAA", "Security"
			string Description,
			AuditSeverity Severity,
			string Remediation,
			string? ReferenceUrl,
			[property: JsonIgnore] Regex Pattern,
			[property: JsonIgnore] HashSet<string>? TargetExtensions = null, // Optional: specific extensions to scan
			[property: JsonIgnore] Func<string, bool>? CustomValidator = null // Optional: Extra validation logic (returns true if violation is valid)
		);
	}
}
