using ComplianceSecurityAuditor.Models;
using static ComplianceSecurityAuditor.Models.Audit;

namespace ComplianceSecurityAuditor.Library
﻿{
﻿    /// <summary>
﻿    /// The core engine that scans file content against a set of compliance rules.
﻿    /// </summary>
﻿    public class ValidationEngine
﻿    {
﻿        private readonly List<AuditRule> _rules;
﻿
﻿        public ValidationEngine(List<AuditRule> rules)
﻿        {
﻿            _rules = rules;
﻿        }
﻿
﻿        /// <summary>
﻿        /// Scans a single file for violations.
﻿        /// </summary>
﻿        /// <param name="filePath">The path to the file to scan.</param>
﻿        /// <returns>A list of violations found in the file.</returns>
﻿        public List<Violation> ScanFile(string filePath)
﻿        {
﻿            var violations = new List<Violation>();
﻿            var lines = File.ReadAllLines(filePath);
﻿
﻿            for (int i = 0; i < lines.Length; i++)
﻿            {
﻿                string currentLine = lines[i];
﻿                int lineNumber = i + 1;
﻿
﻿                foreach (var rule in _rules)
﻿                {
﻿                    var matches = rule.Pattern.Matches(currentLine);
﻿                    if (matches.Count > 0)
﻿                    {
﻿                        foreach (var match in matches)
﻿                        {
﻿                            var violation = new Violation(filePath, lineNumber, match.ToString(), rule);
﻿                            violations.Add(violation);
﻿                        }
﻿                    }
﻿                }
﻿            }
﻿            return violations;
﻿        }
﻿    }
﻿}
﻿
