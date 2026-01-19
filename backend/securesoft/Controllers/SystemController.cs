using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using ComplianceSecurityAuditor.Library;
using System.IO;
using System.Linq;

namespace ComplianceSecurityAuditor.Controllers
{
    [ApiController]
    [Route("api/system")]
    public class SystemController : ControllerBase
    {
        [HttpGet("env-check")]
        public async Task<IActionResult> GetEnvironmentStatus()
        {
            try
            {
                // Check for Python (prefer 3.12 via py launcher)
                var pythonOk = await TryRunAsync("py", "-3.12 --version");
                if (!pythonOk)
                {
                    pythonOk = await TryRunAsync("python", "--version");
                }

                // Check Presidio (prefer 3.12 via py launcher)
                var presidioOk = await TryRunAsync("py", "-3.12 -c \"import presidio_analyzer\"");
                if (!presidioOk)
                {
                    presidioOk = await TryRunAsync("python", "-c \"import presidio_analyzer\"");
                }

                var semgrepOk = await TryRunAsync("semgrep", "--version");
                if (!semgrepOk)
                {
                    var fallbackPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        "Python",
                        "Python314",
                        "Scripts",
                        "semgrep.exe");
                    if (System.IO.File.Exists(fallbackPath))
                    {
                        semgrepOk = await TryRunAsync(fallbackPath, "--version");
                    }
                }

                return Ok(new { python = pythonOk, presidio = presidioOk, semgrep = semgrepOk });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        [HttpPost("browse")]
        public IActionResult BrowseFileSystem([FromBody] BrowseRequest request)
        {
            try
            {
                string path = request?.Path;
                
                // If path is empty, return logical drives
                if (string.IsNullOrWhiteSpace(path))
                {
                    var drives = DriveInfo.GetDrives()
                        .Where(d => d.IsReady)
                        .Select(d => new FileSystemItem { Name = d.Name, Path = d.Name, Type = "drive" })
                        .ToList();
                    return Ok(new { currentPath = "", parent = "", items = drives });
                }

                if (!Directory.Exists(path))
                {
                    return BadRequest(new { error = "Directory does not exist" });
                }

                var items = new List<FileSystemItem>();
                
                // Get Directories
                try
                {
                    var dirs = Directory.GetDirectories(path);
                    foreach (var dir in dirs)
                    {
                        var dirInfo = new DirectoryInfo(dir);
                        if ((dirInfo.Attributes & FileAttributes.Hidden) != FileAttributes.Hidden)
                        {
                            items.Add(new FileSystemItem 
                            { 
                                Name = dirInfo.Name, 
                                Path = dir, 
                                Type = "directory" 
                            });
                        }
                    }
                }
                catch { /* Ignore access errors */ }

                // Get Files
                try 
                {
                    var files = Directory.GetFiles(path);
                    foreach (var file in files)
                    {
                        var fileInfo = new FileInfo(file);
                        if ((fileInfo.Attributes & FileAttributes.Hidden) != FileAttributes.Hidden)
                        {
                             items.Add(new FileSystemItem 
                            { 
                                Name = fileInfo.Name, 
                                Path = file, 
                                Type = "file" 
                            });
                        }
                    }
                }
                catch { /* Ignore access errors */ }

                var parent = Directory.GetParent(path)?.FullName ?? "";

                return Ok(new { currentPath = path, parent, items });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        [HttpGet("docker-status")]
        public async Task<IActionResult> GetDockerStatus()
        {
            try
            {
                var isRunning = await Utility.IsDockerRunningAsync();
                return Ok(new { isRunning });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        [HttpPost("start-docker")]
        public IActionResult StartDocker()
        {
            try
            {
                var dockerPath = @"C:\Program Files\Docker\Docker\Docker Desktop.exe";
                if (!System.IO.File.Exists(dockerPath))
                {
                    return NotFound(new { error = "Docker Desktop executable not found at default location." });
                }

                Process.Start(new ProcessStartInfo
                {
                    FileName = dockerPath,
                    UseShellExecute = true
                });

                return Ok(new { message = "Docker starting..." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        private static async Task<bool> TryRunAsync(string fileName, string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null) return false;
                await process.WaitForExitAsync();
                return process.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        public class BrowseRequest
        {
            public string Path { get; set; }
        }

        public class FileSystemItem
        {
            public string Name { get; set; }
            public string Path { get; set; }
            public string Type { get; set; }
        }
    }
}
