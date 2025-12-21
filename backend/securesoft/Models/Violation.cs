using static ComplianceSecurityAuditor.Models.Audit;

namespace ComplianceSecurityAuditor.Models
{
    public class Violation
    {
        public string FilePath { get; set; }
        public int LineNumber { get; set; }
        public string MatchedText { get; set; }
        public AuditRule ViolatedRule { get; set; }

        public Violation() { }

        public Violation(string filePath, int lineNumber, string matchedText, AuditRule violatedRule)
        {
            FilePath = filePath;
            LineNumber = lineNumber;
            MatchedText = matchedText;
            ViolatedRule = violatedRule;
        }
    }
}
