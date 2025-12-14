using System.Text.RegularExpressions;
using System.Text.Json.Serialization;

namespace ComplianceSecurityAuditor.Models
{
	public class Audit
	{
		/// <summary>
		/// Represents a single compliance rule for the scanner.
		/// </summary>
		public record AuditRule(
			string RuleId,
			string Name,
			string Category, // e.g., "GDPR", "HIPAA", "Security"
			string Description,
			[property: JsonIgnore] Regex Pattern
		);
	}
}
