namespace ComplianceSecurityAuditor.Library
{
	public class Utility
	{
		public static string NormalizePath(string raw, out string? error)
		{
			error = null;
			if (string.IsNullOrWhiteSpace(raw))
			{
				error = "Path is empty.";
				return string.Empty;
			}

			try
			{
				// GetFullPath will resolve relative paths and will throw on invalid characters.
				return Path.GetFullPath(raw);
			}
			catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException)
			{
				error = $"Provided path is invalid: {ex.Message}";
				return string.Empty;
			}
		}
	}
}
