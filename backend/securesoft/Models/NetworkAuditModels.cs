namespace ComplianceSecurityAuditor.Models
{
    public class NetworkScanRequest
    {
        public string Url { get; set; } = string.Empty;
    }

    public class NetworkScanResult
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public string Url { get; set; } = string.Empty;
        public int StatusCode { get; set; }
        public string StatusReason { get; set; } = string.Empty;
        public Dictionary<string, string> Headers { get; set; } = new();
        public SslInfo? SslInfo { get; set; }
        public List<string> MissingSecurityHeaders { get; set; } = new();
        public int SecurityScore { get; set; } = 0;
        public List<int> OpenPorts { get; set; } = new();
        public List<string> PiiFindings { get; set; } = new();
    }

    public class SslInfo
    {
        public string Issuer { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public bool IsValid { get; set; }
        public string Thumbprint { get; set; } = string.Empty;
    }
}
