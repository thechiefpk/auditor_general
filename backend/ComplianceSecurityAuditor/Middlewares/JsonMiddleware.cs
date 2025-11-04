using System.Text;
using System.Text.RegularExpressions;

namespace ComplianceSecurityAuditor.Middlewares
{
    public class JsonMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<JsonMiddleware> _logger;

        // Target only path property values (case-insensitive)
        private static readonly Regex PathPropertyRegex = new Regex(
            @"(?i)(""path""\s*:\s*"")(?<p>[^""]*)("")",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        public JsonMiddleware(RequestDelegate next, ILogger<JsonMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                var contentType = context.Request.ContentType;
                if (!string.IsNullOrEmpty(contentType) &&
                    contentType.IndexOf("application/json", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    // Make the body rewindable for multiple reads
                    context.Request.EnableBuffering();

                    using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
                    var body = await reader.ReadToEndAsync().ConfigureAwait(false);

                    // Rewind so downstream can read original if we don't replace
                    context.Request.Body.Position = 0;

                    if (!string.IsNullOrEmpty(body) && PathPropertyRegex.IsMatch(body))
                    {
                        var modified = PathPropertyRegex.Replace(body, m =>
                        {
                            var prefix = m.Groups[1].Value;   // "path":"
                            var val = m.Groups["p"].Value;    // value contents
                            var suffix = m.Groups[3].Value;   // closing quote

                            // Make escaping idempotent:
                            // 1) Temporarily hide already-escaped double backslashes.
                            const string token = "__BACKSLASH_TOKEN__";
                            var temp = val.Replace("\\\\", token);

                            // 2) Escape remaining single backslashes.
                            var escapedSingles = temp.Replace("\\", "\\\\");

                            // 3) Restore the double backslashes as \\ (no duplication)
                            var escaped = escapedSingles.Replace(token, "\\\\");

                            return prefix + escaped + suffix;
                        });

                        if (!string.Equals(modified, body, StringComparison.Ordinal))
                        {
                            _logger.LogDebug("JsonMiddleware: modified request body to fix path escaping.");

                            var bytes = Encoding.UTF8.GetBytes(modified);
                            var ms = new MemoryStream(bytes);
                            context.Request.Body = ms;
                            context.Request.ContentLength = bytes.Length;

                            // Also update header if present (helpful for some downstream consumers)
                            if (context.Request.Headers.ContainsKey("Content-Length"))
                                context.Request.Headers["Content-Length"] = bytes.Length.ToString();
                            else
                                context.Request.Headers.Add("Content-Length", bytes.Length.ToString());

                            ms.Position = 0;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Don't block the request if middleware fails — log and continue
                _logger?.LogWarning(ex, "JsonMiddleware failed; continuing without modification.");
            }

            await _next(context).ConfigureAwait(false);
        }
    }
}