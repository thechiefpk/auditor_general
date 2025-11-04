using static ComplianceSecurityAuditor.Models.Audit;

namespace ComplianceSecurityAuditor.Models
{
    public class Violation
    {
        public string FilePath { get; }
        public int LineNumber { get; }
        public string MatchedText { get; }
        public AuditRule ViolatedRule { get; }

        public Violation(string filePath, int lineNumber, string matchedText, AuditRule violatedRule)
        {
            FilePath = filePath;
            LineNumber = lineNumber;
            MatchedText = matchedText;
            ViolatedRule = violatedRule;
        }
    }
}
