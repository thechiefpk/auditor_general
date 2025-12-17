using System.Collections.Generic;

namespace ComplianceSecurityAuditor.Library
{
    public static class RemediationHelper
    {
        private static readonly Dictionary<string, (string Solution, string Reference)> RuleRemediations = new()
        {
            // GDPR
            { "GDPR-001", ("Ensure email addresses are not logged or hardcoded. Use environment variables or configuration files. If logging is necessary, mask the data.", "https://gdpr-info.eu/art-32-gdpr/") },
            { "GDPR-002", ("Indian phone numbers are PII. Ensure they are stored securely and not exposed in logs or code.", "https://gdpr-info.eu/issues/personal-data/") },
            { "GDPR-003", ("Credit card numbers must never be stored in plain text. Use a PCI-DSS compliant payment gateway and tokenization.", "https://www.pcisecuritystandards.org/") },
            { "GDPR-004", ("IPv4 addresses can be considered PII. Anonymize IP addresses in logs and analytics.", "https://ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/key-definitions/what-is-personal-data/") },
            { "GDPR-008", ("Passport numbers are highly sensitive PII. Ensure strict access controls and encryption.", "https://gdpr-info.eu/") },
            
            // HIPAA
            { "HIPAA-001", ("Social Security Numbers are strictly regulated. Encrypt at rest and in transit. Never hardcode.", "https://www.hhs.gov/hipaa/index.html") },
            { "HIPAA-002", ("PHI keywords found. Verify that no actual patient data is hardcoded or logged.", "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html") },
            
            // Security / Secrets
            { "SEC-001", ("AWS Access Keys detected. Revoke these keys immediately. Use IAM roles or environment variables.", "https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html") },
            { "SEC-002", ("AWS Secret Keys detected. Revoke immediately. Never commit secrets to version control.", "https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html") },
            { "SEC-008", ("Private Keys detected. Remove immediately. Store keys in a secure vault like HashiCorp Vault or Azure Key Vault.", "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_cryptographic_key") },
            { "SEC-009", ("Generic API Key detected. Ensure keys are not hardcoded. Use environment variables.", "https://12factor.net/config") },
            
            // Code Quality
            { "CODE-001", ("Weak hashing algorithm (MD5/SHA1) detected. specific Use SHA-256 or better (e.g., bcrypt/Argon2 for passwords).", "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html") },
            { "CODE-002", ("PII in logs detected. Remove sensitive data from logging statements to prevent leakage.", "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html") },
            { "CODE-003", ("Potential SQL Injection. Use parameterized queries or an ORM instead of string concatenation.", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html") },
            { "CODE-004", ("Debug mode enabled. Ensure this is disabled in production builds.", "https://cwe.mitre.org/data/definitions/489.html") },
            { "CODE-006", ("Hardcoded credentials in comments. Remove these comments to prevent accidental exposure.", "https://cwe.mitre.org/data/definitions/615.html") }
        };

        private static readonly Dictionary<string, (string Solution, string Reference)> CategoryRemediations = new()
        {
            { "GDPR", ("Review data handling practices to ensure compliance with GDPR. Minimize PII collection and storage.", "https://gdpr.eu/") },
            { "HIPAA", ("Ensure all PHI is encrypted and access is audited. Follow HIPAA Security Rule.", "https://www.hhs.gov/hipaa/") },
            { "Financial", ("Adhere to PCI-DSS standards for financial data. Encrypt all cardholder data.", "https://www.pcisecuritystandards.org/") },
            { "Security", ("Follow OWASP Top 10 guidelines. Remove hardcoded secrets and fix injection vulnerabilities.", "https://owasp.org/www-project-top-ten/") },
            { "Database", ("Ensure database schemas follow security best practices. Encrypt sensitive columns.", "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html") }
        };

        public static (string Solution, string Reference) GetRemediation(string ruleId, string category)
        {
            if (RuleRemediations.TryGetValue(ruleId, out var ruleRemediation))
            {
                return ruleRemediation;
            }

            if (CategoryRemediations.TryGetValue(category, out var catRemediation))
            {
                return catRemediation;
            }

            return ("Review this finding and ensure it complies with your organization's security policy.", "https://owasp.org/");
        }
    }
}
