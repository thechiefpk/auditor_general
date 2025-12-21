using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ComplianceSecurityAuditor.Models;
using static ComplianceSecurityAuditor.Models.Audit;

namespace ComplianceSecurityAuditor.Library
{
    /// <summary>
    /// The core engine that scans file content against a set of compliance rules.
    /// </summary>
    public class ValidationEngine
    {
        private readonly List<AuditRule> _rules;

        public ValidationEngine(List<AuditRule> rules)
        {
            _rules = rules;
        }

        /// <summary>
        /// Scans a single file for violations.
        /// </summary>
        /// <param name="filePath">The path to the file to scan.</param>
        /// <returns>A list of violations found in the file.</returns>
        public List<Violation> ScanFile(string filePath)
        {
            var violations = new List<Violation>();
            
            // Heuristic to skip binary files
            if (IsBinaryFile(filePath)) return violations;

            var extension = Path.GetExtension(filePath);
            
            // Filter rules relevant to this file
            var applicableRules = _rules.Where(r => 
                r.TargetExtensions == null || 
                r.TargetExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase)
            ).ToList();

            if (!applicableRules.Any()) return violations;

            // Use ReadLines for memory efficiency
            int lineNumber = 0;
            try 
            {
                foreach (var currentLine in File.ReadLines(filePath))
                {
                    lineNumber++;
                    
                    // Skip very long lines (minified code or binary data disguised as text)
                    if (currentLine.Length > 10000) continue; 

                    foreach (var rule in applicableRules)
                    {
                        var matches = rule.Pattern.Matches(currentLine);
                        if (matches.Count > 0)
                        {
                            foreach (var match in matches)
                            {
                                var matchText = match.ToString();
                                
                                // Run custom validator if exists (e.g. Luhn check)
                                if (rule.CustomValidator != null && !rule.CustomValidator(matchText))
                                    continue;

                                var violation = new Violation(filePath, lineNumber, matchText, rule);
                                violations.Add(violation);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Handle IO exceptions (e.g. file locked)
                Console.WriteLine($"Error reading {filePath}: {ex.Message}");
            }
            
            return violations;
        }

        private bool IsBinaryFile(string filePath)
        {
            try
            {
                using (var stream = File.OpenRead(filePath))
                {
                    var buffer = new byte[8000];
                    var bytesRead = stream.Read(buffer, 0, buffer.Length);
                    for (int i = 0; i < bytesRead; i++)
                    {
                        // Check for null byte, common indicator of binary files
                        if (buffer[i] == 0) return true;
                    }
                }
            }
            catch { return true; } // Treat unreadable files as binary/skippable

            return false;
        }
    }
}