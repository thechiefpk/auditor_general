using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

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

        public static async Task<bool> IsDockerRunningAsync()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "docker",
                    Arguments = "info",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = new Process { StartInfo = psi };
                process.Start();
                
                // Give it a short timeout
                var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                try 
                {
                    await process.WaitForExitAsync(cts.Token);
                    return process.ExitCode == 0;
                }
                catch (OperationCanceledException)
                {
                    process.Kill();
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }
	}
}
