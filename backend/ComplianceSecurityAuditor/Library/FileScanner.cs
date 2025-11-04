
namespace ComplianceSecurityAuditor.Library
{
	/// <summary>
	/// Handles the discovery and reading of files from a given directory.
	/// </summary>
	public class FileScanner
	{
		// Define directories and extensions to ignore during the scan.
		private static readonly HashSet<string> DirsToIgnore = new(StringComparer.OrdinalIgnoreCase)
			{ ".git", "node_modules", "bin", "obj" };

		private static readonly HashSet<string> ExtsToIgnore = new(StringComparer.OrdinalIgnoreCase)
			{ ".dll", ".exe", ".png", ".jpg", ".zip", ".pack" };

		/// <summary>
		/// Recursively finds all relevant files in a directory.
		/// </summary>
		/// <param name="rootPath">The starting directory path.</param>
		/// <returns>An enumerable of file paths.</returns>
		public IEnumerable<string> FindFiles(string rootPath)
		{
			if (!Directory.Exists(rootPath))
			{
				Console.WriteLine($"Error: Directory not found at '{rootPath}'");
				yield break;
			}

			var queue = new Queue<string>();
			queue.Enqueue(rootPath);

			while (queue.Count > 0)
			{
				var currentDir = queue.Dequeue();

				// Enqueue subdirectories for scanning
				string[] subDirs;
				try
				{
					subDirs = Directory.GetDirectories(currentDir);
				}
				catch (Exception ex)
				{
					Console.WriteLine($"Could not access directory {currentDir}: {ex.Message}");
					continue; // skip to next directory
				}

				foreach (var subDir in subDirs)
				{
					if (!DirsToIgnore.Contains(Path.GetFileName(subDir)))
						queue.Enqueue(subDir);
				}

				// Get files in current directory
				string[] files;
				try
				{
					files = Directory.GetFiles(currentDir);
				}
				catch (Exception ex)
				{
					Console.WriteLine($"Could not access files in {currentDir}: {ex.Message}");
					continue;
				}

				foreach (var file in files)
				{
					if (!ExtsToIgnore.Contains(Path.GetExtension(file)))
						yield return file;
				}
			}
		}
	}
}
