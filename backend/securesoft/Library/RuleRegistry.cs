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
            new("GDPR-001", "Email Address Exposure", "GDPR", "Finds potential email address leaks in code or comments.",
                AuditSeverity.Medium,
                "Remove hardcoded email addresses. Use configuration files or environment variables.",
                "https://gdpr-info.eu/art-6-gdpr/",
                new Regex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", options)),

            new("GDPR-002", "Indian Phone Number", "GDPR", "Finds Indian mobile numbers.",
                AuditSeverity.Low,
                "Ensure phone numbers are not hardcoded or logged without masking.",
                "https://gdpr-info.eu/art-6-gdpr/",
                new Regex(@"(?:\+91[\s-]?)?[6-9]\d{9}\b", options)),

            new("GDPR-003", "Credit Card Number", "GDPR", "Finds potential credit card numbers.",
                AuditSeverity.Critical,
                "Never store or log full credit card numbers. Use tokenization or masking (PCI-DSS requirement).",
                "https://www.pcisecuritystandards.org/",
                new Regex(@"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b", options),
                null,
                IsValidCreditCard), // Custom Validator

            new("GDPR-004", "IPv4 Address", "GDPR", "Finds IPv4 addresses, which can be personal data.",
                AuditSeverity.Low,
                "Avoid hardcoding IP addresses. Use DNS names or configuration.",
                "https://gdpr-info.eu/issues/personal-data/",
                new Regex(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", options)),

            new("GDPR-005", "Aadhar Number", "GDPR", "Finds Indian Aadhar numbers (12 digits).",
                AuditSeverity.High,
                "Aadhar numbers are highly sensitive PII. Mask or encrypt immediately.",
                "https://uidai.gov.in/",
                new Regex(@"\b[2-9]{1}[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b", options),
                null,
                IsValidAadhar), // Custom Validator (Verhoeff algo is complex, simple length check for now)

            new("GDPR-006", "PAN Card", "GDPR", "Finds Indian PAN card numbers.",
                AuditSeverity.High,
                "Store PAN numbers encrypted. Do not log them.",
                null,
                new Regex(@"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", options)),
			
			new("GDPR-008", "International Passport Number", "GDPR", "Finds common patterns for international passport numbers.",
                AuditSeverity.High,
                "Passport numbers are sensitive PII. Ensure they are encrypted at rest.",
                null,
                new Regex(@"\b(?:passport|passport_number|passport_id)[\s:=]+['""]?([A-Z]{1,2}[0-9]{6,9})['""]?\b", options)),

            new("GDPR-009", "Date of Birth", "GDPR", "Finds common date of birth formats.",
                AuditSeverity.Medium,
                "Date of Birth is PII. Ensure it is processed lawfully.",
                null,
                new Regex(@"\b(0?[1-9]|[12][0-9]|3[01])[-/.](0?[1-9]|1[012])[-/.](19|20)\d\d\b", options)),
            #endregion

            #region HIPAA (Health Insurance Portability and Accountability Act)
            new("HIPAA-001", "SSN (Social Security Number)", "HIPAA", "Finds U.S. Social Security Numbers.",
                AuditSeverity.Critical,
                "SSNs must be encrypted. Never log or hardcode them.",
                "https://www.hhs.gov/hipaa/index.html",
                new Regex(@"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", options)),

            new("HIPAA-002", "PHI Keywords", "HIPAA", "Finds keywords suggesting Protected Health Information.",
                AuditSeverity.Medium,
                "Review usage of PHI variables. Ensure access controls and audit logging are in place.",
                "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html",
                new Regex(@"\b(patient|client)_(name|id|dob|ssn|social_security|medical_record|diagnosis|mrn|prescription|blood_type|health_insurance)[\s:=]+['""]?[\w.-]+['""]?\b", options)),

            new("HIPAA-003", "DEA Number", "HIPAA", "Finds U.S. Drug Enforcement Administration numbers.",
                AuditSeverity.High,
                "DEA numbers are sensitive provider identifiers.",
                null,
                new Regex(@"\b[A-Z]{2}\d{7}\b", options)),
            #endregion

            #region Financial & PCI-DSS
            new("FIN-001", "Stripe API Key", "Financial", "Finds hardcoded Stripe API keys.",
                AuditSeverity.Critical,
                "Revoke the exposed key immediately and rotate secrets. Use environment variables.",
                "https://stripe.com/docs/keys",
                new Regex(@"\bstripe(.{0,20})?['""](sk|pk)_(test|live)_[0-9a-zA-Z]{24,99}['""]", options)),

            new("FIN-002", "SWIFT/BIC Code", "Financial", "Finds SWIFT/BIC codes for international bank transfers.",
                AuditSeverity.Low,
                "Verify if SWIFT codes are public or sensitive context.",
                null,
                new Regex(@"\b(swift|bic|swift_code|bic_code|bank_code)[\s:=]+['""]?([A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?)['""]?\b", options)),
            
            new("PCI-001", "Magnetic Stripe Data", "PCI-DSS", "Finds potential magnetic stripe track data.",
                AuditSeverity.Critical,
                "Do not store magnetic stripe data (Track 1/2) after authorization.",
                "https://www.pcisecuritystandards.org/",
                new Regex(@"\b%B\d{1,19}\^[A-Z\s/]{2,26}\^\d{4}\d{3}\b", options)), // Track 1
            #endregion
            
            #region ISO 27001 & Credentials/Secrets Exposure
            new("SEC-001", "AWS Access Key ID", "Security", "Finds hardcoded AWS access key IDs.",
                AuditSeverity.Critical,
                "Rotate keys immediately. Use IAM roles or AWS Secrets Manager.",
                "https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html",
                new Regex(@"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b", options)),

            new("SEC-002", "AWS Secret Access Key", "Security", "Finds hardcoded AWS secret access keys.",
                AuditSeverity.Critical,
                "Rotate keys immediately. Never commit secrets to version control.",
                "https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html",
                new Regex(@"\baws(.{0,20})?(key|secret|token)(.{0,20})?['""]([0-9A-Za-z\/+]{40})['""]", options)),

            new("SEC-003", "Google Cloud API Key", "Security", "Finds hardcoded Google Cloud Platform API keys.",
                AuditSeverity.Critical,
                "Restrict key usage and rotate immediately.",
                "https://cloud.google.com/docs/authentication/api-keys",
                new Regex(@"\bAIza[0-9A-Za-z\-_]{35}\b", options)),

            new("SEC-004", "GitHub Personal Access Token", "Security", "Finds hardcoded GitHub personal access tokens.",
                AuditSeverity.Critical,
                "Revoke token immediately. Use GitHub Secrets.",
                null,
                new Regex(@"\bghp_[0-9a-zA-Z]{36}\b", options)),

            new("SEC-006", "Slack Token", "Security", "Finds hardcoded Slack tokens (bot, user, webhook).",
                AuditSeverity.Critical,
                "Revoke token. Use environment variables.",
                null,
                new Regex(@"\b(xox[p|b|a|o|s|r]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})\b", options)),

            new("SEC-008", "Hardcoded Private Key", "Security", "Finds headers for common private key formats.",
                AuditSeverity.Critical,
                "Private keys must never be committed. Use a key management system.",
                null,
                new Regex(@"-----BEGIN (RSA|EC|PGP|DSA|OPENSSH) PRIVATE KEY-----", options)),

            new("SEC-010", "JWT Token", "Security", "Finds potential JSON Web Tokens.",
                AuditSeverity.Medium,
                "Ensure JWTs are not hardcoded. Check expiration and signature verification.",
                "https://jwt.io/",
                new Regex(@"\bey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b", options)),
            #endregion

            #region Insecure Coding Practices (OWASP)
            new("CODE-001", "Weak Hashing Algorithm", "Security", "Finds usage of outdated hashing functions like MD5 or SHA1.",
                AuditSeverity.High,
                "Use strong hashing algorithms like SHA-256 or bcrypt/Argon2 for passwords.",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
                new Regex(@"\b(MD5|SHA1)\s*\(", options)),

            new("CODE-002", "PII in Log Statement", "Security", "Finds logging statements that may contain sensitive data.",
                AuditSeverity.Medium,
                "Remove PII from logs to prevent data leaks via log aggregation systems.",
                null,
                new Regex(@"\b(log|Log|logger|Logger|console|Console)\.(Debug|Info|Warn|Error|WriteLine|Write|log)\s*\([^)]*\b(email|password|ssn|credit_card|auth_token|apikey|social_security)\b", options)),

            new("CODE-003", "Potential SQL Injection", "Security", "Finds classic string concatenation in SQL queries.",
                AuditSeverity.High,
                "Use parameterized queries (Prepared Statements) to prevent SQL injection.",
                "https://owasp.org/www-community/attacks/SQL_Injection",
                new Regex(@"(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+.+\s*\+\s*\w+\s*\+", options)),

            new("CODE-004", "Debug Mode Enabled", "Security", "Detects if a debug or testing flag is hardcoded to true.",
                AuditSeverity.Medium,
                "Ensure debug mode is disabled in production.",
                null,
                new Regex(@"\b(DEBUG|TESTING|IsDebug|EnableDebug)\s*=\s*(true|True|TRUE)\b", options)),

            new("CODE-005", "Disabled Certificate Validation", "Security", "Finds code that might disable SSL/TLS certificate validation.",
                AuditSeverity.Critical,
                "Do not disable certificate validation in production. It enables MITM attacks.",
                null,
                new Regex(@"\b(ServerCertificateValidationCallback|verify)\s*=\s*(False|false|null|\(\s*_\s*,\s*_\s*,\s*_\s*,\s*_\s*\)\s*=>\s*(true|True))", options),
                new HashSet<string>{".cs"}), // Targeted for C#

            new("CODE-006", "Hardcoded Credentials in Comment", "Security", "Finds credentials exposed in code comments.",
                AuditSeverity.Medium,
                "Remove credentials from comments.",
                null,
                new Regex(@"//\s*(password|secret|key|token)\s*[:=]\s*['""]?[\w.-]{8,}['""]?", options)),

            new("CODE-007", "Dangerous Function Use (eval)", "Security", "Finds usage of 'eval()' which is a security risk.",
                AuditSeverity.High,
                "Avoid using eval(). It allows execution of arbitrary code.",
                "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval",
                new Regex(@"\beval\s*\(", options),
                new HashSet<string>{".js", ".ts", ".jsx", ".tsx", ".py", ".php"}),
            
            new("CODE-008", "Hardcoded IP Address", "Security", "Finds hardcoded IPv4 addresses.",
                AuditSeverity.Low,
                "Avoid hardcoding IPs. Use DNS or config.",
                null,
                new Regex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", options)),

            new("REACT-001", "DangerouslySetInnerHTML", "Security", "Finds usage of dangerouslySetInnerHTML in React.",
                AuditSeverity.High,
                "Ensure content is sanitized before using dangerouslySetInnerHTML to prevent XSS.",
                "https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml",
                new Regex(@"dangerouslySetInnerHTML", options),
                new HashSet<string>{".jsx", ".tsx", ".js", ".ts"}),
            
            #endregion

            #region Cloud & Infrastructure Secrets
            new("CLOUD-001", "Azure Storage Account Key", "Security", "Finds Azure Storage Account Keys.",
                AuditSeverity.Critical,
                "Rotate key immediately. Use Managed Identities.",
                "https://docs.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage",
                new Regex(@"\b[a-zA-Z0-9+/]{86}==\b", options)),

            new("CLOUD-002", "Heroku API Key", "Security", "Finds Heroku API keys.",
                AuditSeverity.Critical,
                "Revoke key immediately.",
                null,
                new Regex(@"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", options)),
            
            new("CLOUD-003", "Generic API Key", "Security", "Finds generic high-entropy strings that look like API keys.",
                AuditSeverity.High,
                "Investigate if this is a real secret. Store secrets securely.",
                null,
                new Regex(@"(?i)(api_key|apikey|secret|token)[\s=:'""]+([a-zA-Z0-9]{32,45})\b", options)),
            #endregion	
                
            #region SQL and Database Schema Validation
            new("SQL-001", "Plaintext PII Column", "Database", "In a .sql file, finds CREATE TABLE statements with unencrypted PII columns.",
                AuditSeverity.High,
                "Encrypt sensitive columns (email, ssn, etc.) at rest.",
                null,
                new Regex(@"\bCREATE\s+TABLE\s+\w+\s*\([^)]*\b(email|ssn|password|credit_card|pan_card|aadhar|phone|address)\s+(VARCHAR|TEXT|CHAR|NVARCHAR)", options),
                new HashSet<string>{".sql"}),

            new("SQL-002", "Plaintext Password in INSERT", "Database", "Finds INSERT statements that appear to contain plaintext passwords.",
                AuditSeverity.Critical,
                "Do not insert plaintext passwords. Hash them first.",
                null,
                new Regex(@"\bINSERT\s+INTO\s+\w+\s*\([^)]*password[^)]*\)\s+VALUES\s*\([^)]*['""](.{6,})['""]", options),
                new HashSet<string>{".sql"}),

            new("SQL-003", "Grant All Privileges", "Database", "Finds overly permissive GRANT ALL statements in SQL scripts.",
                AuditSeverity.High,
                "Follow the Principle of Least Privilege. Grant only necessary permissions.",
                null,
                new Regex(@"\bGRANT\s+ALL\s+PRIVILEGES\s+ON\s+.+\s+TO\s+", options),
                new HashSet<string>{".sql"}),
            #endregion
        };
    }

    // --- Validation Helpers ---

    /// <summary>
    /// Validates a potential credit card number using the Luhn Algorithm.
    /// </summary>
    private static bool IsValidCreditCard(string input)
    {
        // Remove non-digit characters
        var digits = new string(input.Where(char.IsDigit).ToArray());
        
        if (digits.Length < 13 || digits.Length > 19) return false;

        int sum = 0;
        bool alternate = false;
        for (int i = digits.Length - 1; i >= 0; i--)
        {
            int n = int.Parse(digits[i].ToString());
            if (alternate)
            {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return (sum % 10 == 0);
    }

    private static bool IsValidAadhar(string input)
    {
        // Aadhar is 12 digits. Regex already checks format, but let's double check simple constraints
        // Aadhar cannot start with 0 or 1.
        var clean = new string(input.Where(char.IsDigit).ToArray());
        if (clean.Length != 12) return false;
        if (clean[0] == '0' || clean[0] == '1') return false;
        return true;
    }
}