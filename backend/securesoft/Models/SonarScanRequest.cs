namespace ComplianceSecurityAuditor.Models
{
    public class SonarScanRequest
    {
        public string ProjectPath { get; set; }
        public string ProjectKey { get; set; }
        public string Token { get; set; }
        public string HostUrl { get; set; } = "http://localhost:9000";
    }
}
