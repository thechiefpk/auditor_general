using System.Text.RegularExpressions;
using ComplianceSecurityAuditor.Models;

namespace ComplianceSecurityAuditor.Services
{
    public class SqlScanner
    {
        private readonly List<SqlRule> _rules;

        public SqlScanner()
        {
            _rules = new List<SqlRule>
            {
                new SqlRule("SQL001", "Unencrypted Sensitive Data", @"(CREATE TABLE|ALTER TABLE).*?(password|ssn|credit_card|email).*?(VARCHAR|TEXT|CHAR)", "Sensitive columns should be encrypted or hashed."),
                new SqlRule("SQL002", "Dangerous Drop Command", @"\bDROP\s+(TABLE|DATABASE)\b", "Avoid using DROP commands in production scripts."),
                new SqlRule("SQL003", "Grant All Privileges", @"\bGRANT\s+ALL\b", "Least privilege principle violation. Do not GRANT ALL."),
                new SqlRule("SQL004", "Hardcoded Credentials", @"(password|secret|key)\s*=\s*['""][^'""]+['""]", "Hardcoded credentials detected."),
                new SqlRule("SQL005", "Use of xp_cmdshell", @"\b xp_cmdshell \b", "xp_cmdshell allows OS command execution and should be disabled."),
                new SqlRule("SQL006", "Weak Password Hash", @"\b(MD5|SHA1)\(", "Use stronger hashing algorithms like SHA256 or bcrypt."),
                new SqlRule("SQL007", "Select * Usage", @"\bSELECT\s+\*\b", "Avoid SELECT *; specify columns explicitly for performance and security.")
            };
        }

        public async Task<List<Violation>> ScanPathAsync(string path)
        {
            var violations = new List<Violation>();

            if (Directory.Exists(path))
            {
                var files = Directory.GetFiles(path, "*.sql", SearchOption.AllDirectories);
                foreach (var file in files)
                {
                    violations.AddRange(await ScanFileAsync(file));
                }
            }
            else if (File.Exists(path) && Path.GetExtension(path).Equals(".sql", StringComparison.OrdinalIgnoreCase))
            {
                violations.AddRange(await ScanFileAsync(path));
            }

            return violations;
        }

        private async Task<List<Violation>> ScanFileAsync(string filePath)
        {
            var violations = new List<Violation>();
            var lines = await File.ReadAllLinesAsync(filePath);

            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                foreach (var rule in _rules)
                {
                    if (Regex.IsMatch(line, rule.Pattern, RegexOptions.IgnoreCase))
                    {
                        violations.Add(new Violation
                        {
                            FilePath = filePath,
                            LineNumber = i + 1,
                            MatchedText = line.Trim(),
                            ViolatedRule = new Audit.AuditRule(
                                rule.Id,
                                rule.Name,
                                "SQL Security",
                                rule.Description,
                                Audit.AuditSeverity.Medium,
                                "Review and fix the SQL statement.",
                                null,
                                new Regex(rule.Pattern, RegexOptions.IgnoreCase)
                            )
                        });
                    }
                }
            }

            return violations;
        }
    }

    public class SqlRule
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Pattern { get; set; }
        public string Description { get; set; }

        public SqlRule(string id, string name, string pattern, string description)
        {
            Id = id;
            Name = name;
            Pattern = pattern;
            Description = description;
        }
    }
}
