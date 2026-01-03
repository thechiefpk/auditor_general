
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
			// Version Control
			".git", ".svn", ".hg", ".bzr", ".cvs",
			
			// IDEs & Editors
			".vs", ".idea", ".vscode", ".settings", ".project", ".classpath", ".metadata",

			// Dependencies
			"node_modules", "bower_components", "jspm_packages", "packages", "vendor", "3rdparty", "third_party",
			"venv", ".venv", "env", ".env", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox", ".eggs",

			// Build Artifacts (General)
			"bin", "obj", "debug", "release", "x64", "x86", "build", "dist", "out", "target", "output",
			
			// Web Frameworks (Next.js, Nuxt, etc.)
			".next", ".nuxt", ".output", ".vercel", ".netlify", ".cache", ".parcel-cache",
			"public", "static", "assets", // Often just static assets, though sometimes contain JS

			// Testing & Logs
			"coverage", "test-results", "test", "tests", "spec", "specs", "tmp", "temp", "logs", "log",

			// Java/Kotlin
			".gradle", "gradle",
			
			// Mobile
			".dart_tool", "Pods", "DerivedData"
		};

		// Specific file names to ignore
		private static readonly HashSet<string> FilesToIgnore = new(StringComparer.OrdinalIgnoreCase)
		{
			// Lock files
			"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "Gemfile.lock", "Podfile.lock", "Cargo.lock", "mix.lock",
			
			// Configs that might look like code or contain noise
			"tsconfig.json", "jsconfig.json", "angular.json", "firebase.json", "vercel.json",
			
			// Minified/Bundled Libs (specifics)
			"jquery.js", "jquery.min.js", "angular.js", "angular.min.js", "react.js", "react.min.js", "vue.js", "vue.min.js",
			"bootstrap.js", "bootstrap.min.js", "bundle.js", "main.js", "vendor.js", "common.js"
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

			// Check for minified files or map files
			if (fileName.EndsWith(".min.js", StringComparison.OrdinalIgnoreCase) || 
				fileName.EndsWith(".min.css", StringComparison.OrdinalIgnoreCase) ||
				fileName.EndsWith(".map", StringComparison.OrdinalIgnoreCase) ||
				fileName.EndsWith(".d.ts", StringComparison.OrdinalIgnoreCase) || // Typescript definition files
				fileName.Contains(".bundle.", StringComparison.OrdinalIgnoreCase) ||
				fileName.Contains(".chunk.", StringComparison.OrdinalIgnoreCase) ||
				fileName.Contains("node_modules", StringComparison.OrdinalIgnoreCase)) // Files like node_modules_c564ad58._.js
				return false;

			// Special handling for JS files (allow .js but not .min.js, which is handled above)
			if (string.Equals(extension, ".js", StringComparison.OrdinalIgnoreCase)) return true;

			// Special handling for appsettings.json and variants (e.g. appsettings.Development.json)
			if (fileName.StartsWith("appsettings", StringComparison.OrdinalIgnoreCase) && 
				string.Equals(extension, ".json", StringComparison.OrdinalIgnoreCase)) return true;

			// Check whitelist
			return AllowedExtensions.Contains(extension);
		}
	}
}
