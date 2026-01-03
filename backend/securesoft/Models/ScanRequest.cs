
namespace ComplianceSecurityAuditor.Models
{
    public class ScanRequest
    {
        public string Path { get; set; }
        public bool IsAdvanced { get; set; }
    }

    public class GitScanRequest
    {
        public string RepositoryUrl { get; set; }
        public string Branch { get; set; }
        public bool IsAdvanced { get; set; }
    }
}
