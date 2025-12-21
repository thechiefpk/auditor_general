
namespace ComplianceSecurityAuditor.Library
{
	/// <summary>
	/// Handles the discovery and reading of files from a given directory.
	/// </summary>
	public class FileScanner
	{
		// Whitelist of allowed high-level language extensions
		private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
		{
			".cs", ".java", ".py", ".go", ".rb", ".php", ".swift", 
			".kt", ".kts", ".rs", ".c", ".cpp", ".h", ".hpp", 
			".ts", ".tsx", ".jsx", ".sql", ".scala", ".pl", ".sh", ".bat", ".ps1" 
			// Note: .js is handled specially to exclude .min.js
		};

		// Directories to strictly ignore
		private static readonly HashSet<string> DirsToIgnore = new(StringComparer.OrdinalIgnoreCase)
		{ 
			".git", ".vs", ".idea", ".vscode",
			"node_modules", "bower_components", "jspm_packages",
			"bin", "obj", "debug", "release", "debugger",
			"dist", "build", "out", "target",
			"coverage", "test-results", "test", "tests", "spec", "specs", "tmp", "temp",
			"vendor", "plugins", "storage",
			"assets", "static", "images", "img", "fonts", "css", "scss", "less", "sass",
			"lib", "libs" // Often 3rd party
		};

		// Specific file names to ignore
		private static readonly HashSet<string> FilesToIgnore = new(StringComparer.OrdinalIgnoreCase)
		{
			"package-lock.json", "yarn.lock", "composer.lock", "Gemfile.lock",
			"jquery.js", "jquery.min.js", "angular.js", "react.js", "vue.js" // Common libs
		};

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
					var dirName = Path.GetFileName(subDir);
					if (!DirsToIgnore.Contains(dirName))
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
					if (IsAllowedFile(file))
						yield return file;
				}
			}
		}

		private bool IsAllowedFile(string filePath)
		{
			var fileName = Path.GetFileName(filePath);
			var extension = Path.GetExtension(filePath);

			// Check strict file name ignores
			if (FilesToIgnore.Contains(fileName)) return false;

			// Check for minified files
			if (fileName.EndsWith(".min.js", StringComparison.OrdinalIgnoreCase) || 
				fileName.EndsWith(".min.css", StringComparison.OrdinalIgnoreCase)) 
				return false;

			// Special handling for JS files (allow .js but not .min.js, which is handled above)
			if (string.Equals(extension, ".js", StringComparison.OrdinalIgnoreCase)) return true;

			// Check whitelist
			return AllowedExtensions.Contains(extension);
		}
	}
}
