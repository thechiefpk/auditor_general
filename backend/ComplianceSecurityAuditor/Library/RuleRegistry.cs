using System.Text.RegularExpressions;
using static ComplianceSecurityAuditor.Models.Audit;

namespace ComplianceSecurityAuditor.Library;

/// <summary>
/// Contains the master list of all compliance rules used by the scanner.
/// This is a comprehensive library covering GDPR, HIPAA, ISO 27001, and general security best practices.
/// </summary>
public static partial class RuleRegistry
{
	public static List<AuditRule> GetRules()
	{
		// Using RegexOptions.Compiled for performance on repeated use.
		// Using RegexOptions.IgnoreCase for case-insensitive matching where appropriate.
		const RegexOptions options = RegexOptions.Compiled | RegexOptions.IgnoreCase;

		return new List<AuditRule>
		{
            #region GDPR & General PII (Personally Identifiable Information)
            new("GDPR-001", "Email Address", "GDPR", "Finds common email address formats.",
				new Regex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", options)),
			new("GDPR-002", "Indian Phone Number", "GDPR", "Finds Indian mobile numbers.",
				new Regex(@"(?:\+91[\s-]?)?[6-9]\d{9}\b", options)),
			new("GDPR-003", "Credit Card Number", "GDPR", "Finds common credit card number patterns.",
				new Regex(@"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b", options)),
			new("GDPR-004", "IPv4 Address", "GDPR", "Finds IPv4 addresses, which can be personal data.",
				new Regex(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", options)),
			new("GDPR-005", "Aadhar Number", "GDPR", "Finds Indian Aadhar numbers (12 digits).",
				new Regex(@"\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b", options)),
			new("GDPR-006", "PAN Card", "GDPR", "Finds Indian PAN card numbers.",
				new Regex(@"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", options)),
			new("GDPR-007", "MAC Address", "GDPR", "Finds MAC addresses, an online identifier.",
				new Regex(@"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b", options)),
			new("GDPR-008", "International Passport Number", "GDPR", "Finds common patterns for international passport numbers.",
				new Regex(@"\b(?!0{5,})(?!1{5,})[A-Z0-9]{6,20}\b", options)),
			new("GDPR-009", "Date of Birth", "GDPR", "Finds common date of birth formats.",
				new Regex(@"\b(0?[1-9]|[12][0-9]|3[01])[-/.](0?[1-9]|1[012])[-/.](19|20)\d\d\b", options)),
            #endregion

            #region HIPAA (Health Insurance Portability and Accountability Act)
            new("HIPAA-001", "SSN (Social Security Number)", "HIPAA", "Finds U.S. Social Security Numbers.",
				new Regex(@"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", options)),
			new("HIPAA-002", "PHI Keywords", "HIPAA", "Finds keywords suggesting Protected Health Information.",
				new Regex(@"\b(patient|client)_(name|id|dob)|ssn|social_security|medical_record|diagnosis|mrn|prescription|blood_type|health_insurance\b", options)),
			new("HIPAA-003", "DEA Number", "HIPAA", "Finds U.S. Drug Enforcement Administration numbers.",
				new Regex(@"\b[A-Z]{2}\d{7}\b", options)),
            #endregion

            #region Financial & PCI-DSS
            new("FIN-001", "IBAN (International Bank Account Number)", "Financial", "Finds International Bank Account Numbers.",
				new Regex(@"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b", options)),
			new("FIN-002", "SWIFT/BIC Code", "Financial", "Finds SWIFT/BIC codes for international bank transfers.",
				new Regex(@"\b[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?\b", options)),
            #endregion
            
            #region ISO 27001 & Credentials/Secrets Exposure
            new("SEC-001", "AWS Access Key ID", "Security", "Finds hardcoded AWS access key IDs.",
				new Regex(@"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", options)),
			new("SEC-002", "AWS Secret Access Key", "Security", "Finds hardcoded AWS secret access keys.",
				new Regex(@"aws(.{0,20})?(key|secret|token).{0,20}?['""]([0-9A-Za-z\/+]{40})['""]", options)),
			new("SEC-003", "Google Cloud API Key", "Security", "Finds hardcoded Google Cloud Platform API keys.",
				new Regex(@"AIza[0-9A-Za-z\-_]{35}", options)),
			new("SEC-004", "GitHub Personal Access Token", "Security", "Finds hardcoded GitHub personal access tokens.",
				new Regex(@"ghp_[0-9a-zA-Z]{36}", options)),
			new("SEC-005", "Stripe API Key", "Security", "Finds hardcoded Stripe API keys.",
				new Regex(@"stripe.{0,20}?['""](sk|pk)_(test|live)_[0-9a-zA-Z]{24,99}['""]", options)),
			new("SEC-006", "Slack Token", "Security", "Finds hardcoded Slack tokens (bot, user, webhook).",
				new Regex(@"(xox[p|b|a|o|s|r]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})", options)),
			new("SEC-007", "Twilio API Key", "Security", "Finds hardcoded Twilio API keys and SIDs.",
				new Regex(@"SK[0-9a-fA-F]{32}", options)),
			new("SEC-008", "Hardcoded Private Key", "Security", "Finds headers for common private key formats.",
				new Regex(@"-----BEGIN (RSA|EC|PGP|DSA|OPENSSH) PRIVATE KEY-----", options)),
			new("SEC-009", "Generic API Key", "Security", "Finds generic keywords for secrets and keys.",
				new Regex(@"(key|secret|token|password|apikey|auth_token|access_token|client_secret)[\s:=]+['""]([a-zA-Z0-9\-_/.+@]{16,})['""]", options)),
			new("SEC-010", "JWT Token", "Security", "Finds potential JSON Web Tokens.",
				new Regex(@"ey[a-zA-Z0-9_-]{40,}\.ey[a-zA-Z0-9_-]{40,}(\.[a-zA-Z0-9_-]{40,})?", options)),
            #endregion

            #region Insecure Coding Practices (OWASP)
            new("CODE-001", "Weak Hashing Algorithm", "Security", "Finds usage of outdated hashing functions like MD5 or SHA1.",
				new Regex(@"\b(md5|sha1)\s*\(", options)),
			new("CODE-002", "PII in Log Statement", "Security", "Finds logging statements that may contain sensitive data.",
				new Regex(@"(?i)(log|print|console)\.[\w]+\(.*(email|password|ssn|credit_card|auth_token|apikey).*\)", options)),
			new("CODE-003", "Potential SQL Injection", "Security", "Finds classic string concatenation in SQL queries. High chance of false positives, needs manual review.",
				new Regex(@"(?i)(""|')\s*\+\s*\w+\s*\+\s*(""|')\s*;", options)),
			new("CODE-004", "Debug Mode Enabled", "Security", "Detects if a debug or testing flag is hardcoded to true.",
				new Regex(@"(?i)(DEBUG|TESTING)\s*=\s*True", options)),
			new("CODE-005", "Disabled Certificate Validation", "Security", "Finds code that might disable SSL/TLS certificate validation.",
				new Regex(@"(?i)verify\s*=\s*False|setHostnameVerifier\s*\(\s*ALLOW_ALL_HOSTNAME_VERIFIER", options)),
			new("CODE-006", "Hardcoded Credentials in Comment", "Security", "Finds credentials exposed in code comments.",
				new Regex(@"(?i)//.*(password|secret|key)\s*[:=]\s*[\w.-]+", options)),
            #endregion	
                
            #region SQL and Database Schema Validation
            new("SQL-001", "Plaintext PII Column", "Database", "In a .sql file, finds CREATE TABLE statements with unencrypted PII columns.",
				new Regex(@"(?i)CREATE\s+TABLE\s+\w+\s*\(.*(email|ssn|password|credit_card|pan_card|aadhar)\s+(VARCHAR|TEXT|CHAR)", options)),
			new("SQL-002", "Plaintext Password in INSERT", "Database", "Finds INSERT statements that appear to contain plaintext passwords.",
				new Regex(@"(?i)INSERT\s+INTO\s+\w+\s*\(.*password.*\)\s+VALUES\s*\(.*['""](.{6,})['""]", options)),
			new("SQL-003", "Grant All Privileges", "Database", "Finds overly permissive GRANT ALL statements in SQL scripts.",
				new Regex(@"(?i)GRANT\s+ALL\s+PRIVILEGES\s+ON\s+.+\s+TO", options)),
			new("SQL-004", "Auto-Incrementing User ID", "Database", "Detects auto-incrementing primary keys on user tables, which can lead to IDOR vulnerabilities.",
				new Regex(@"(?i)CREATE\s+TABLE\s+(users|customers|accounts)\s*\(.*(id\s+INT\s+AUTO_INCREMENT|SERIAL)\s+PRIMARY\s+KEY", options)),
			new("SQL-005", "User Creation with Plaintext Password", "Database", "Finds CREATE USER statements with a plaintext password.",
				new Regex(@"(?i)CREATE\s+USER\s+\S+\s+IDENTIFIED\s+BY\s+\S+", options)),
            #endregion
        };
	}
}