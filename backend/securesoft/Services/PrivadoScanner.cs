using System.Diagnostics;
using System.Text.Json;
using System.IO;
using System.Threading;
using ComplianceSecurityAuditor.Models;
using ComplianceSecurityAuditor.Data;
using static ComplianceSecurityAuditor.Models.Audit;

namespace ComplianceSecurityAuditor.Services
{
    public class PrivadoScanner
    {
        private readonly IScanProgressRepository _progressRepo;

        public PrivadoScanner(IScanProgressRepository progressRepo)
        {
            _progressRepo = progressRepo;
        }

        public async Task<List<Violation>> RunScanAsync(string path, string jobId)
        {
            path = path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var violations = new List<Violation>();
            try
            {
                // 1. Determine Privado Binary
                string privadoBinary = "privado";
                bool useDockerFallback = false;

                // Priority 1: Workspace Tools
                var workspaceTool = Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "tools", "privado.exe"));
                
                // Priority 2: Home Directory
                var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var homeBinary = Path.Combine(home, ".privado", "bin", "privado");
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                {
                    homeBinary += ".exe";
                }

                if (File.Exists(workspaceTool))
                {
                    privadoBinary = workspaceTool;
                    Console.WriteLine($"[PrivadoScanner] Using Workspace CLI: {privadoBinary}");
                }
                else if (File.Exists(homeBinary))
                {
                    privadoBinary = homeBinary;
                    Console.WriteLine($"[PrivadoScanner] Using Home CLI: {privadoBinary}");
                }
                else
                {
                    Console.WriteLine($"[PrivadoScanner] Using PATH CLI: {privadoBinary}");
                }

                try 
                {
                    await RunProcessAsync(privadoBinary, $"scan \"{path}\" --skip-upload --skip-dependency-download --overwrite", path, jobId);
                }
                catch (Exception ex)
                {
                    // Check if it's a Docker/Daemon error or CommandNotFound
                    if (ex is System.ComponentModel.Win32Exception || 
                        ex.Message.Contains("docker", StringComparison.OrdinalIgnoreCase) || 
                        ex.Message.Contains("daemon", StringComparison.OrdinalIgnoreCase) ||
                        ex.Message.Contains("client version", StringComparison.OrdinalIgnoreCase))
                    {
                         Console.WriteLine($"[PrivadoScanner] CLI failed with Docker-related error ({ex.Message}). Triggering Docker fallback...");
                         useDockerFallback = true;
                    }
                    else
                    {
                        violations.Add(CreateSystemViolation("Privado CLI Error", $"Privado CLI failed: {ex.Message}"));
                        return violations;
                    }
                }

                // 2. Fallback to Docker if CLI is missing
                if (useDockerFallback)
                {
                    Console.WriteLine("[PrivadoScanner] Attempting Docker fallback...");
                    // Check if Docker is available/running
                    try 
                    {
                        // Verify docker is reachable (e.g. docker info)
                        await RunProcessAsync("docker", "info", path, jobId, true);
                        
                        // Ensure .privado directory exists on host
                        var privadoDir = Path.Combine(path, ".privado");
                        if (!Directory.Exists(privadoDir))
                        {
                            Directory.CreateDirectory(privadoDir);
                        }

                        // Run Privado via Docker
                        // Mount the host path to /app/code in container
                        // Mount .privado folder for output
                        // Image: public.ecr.aws/privado/privado:latest
                        // NOTE: Entrypoint is [/usr/local/bin/core, scan], so we provide args for 'scan' command directly.
                        // We must provide source directory (/app/code) and options (-ic /app/rules/config --skip-upload).
                        // Do NOT include 'scan' in args, as it's already in entrypoint.
                        var dockerArgs = $"run --rm -v \"{path}:/app/code\" -v \"{privadoDir}:/app/code/.privado\" public.ecr.aws/privado/privado:latest /app/code -ic /app/rules/config --skip-upload";
                        
                        Console.WriteLine($"[PrivadoScanner] Executing Docker command: docker {dockerArgs}");
                        await RunProcessAsync("docker", dockerArgs, path, jobId);
                    }
                    catch (Exception ex)
                    {
                        // Docker failed or not running
                        Console.WriteLine($"[PrivadoScanner] Docker fallback failed: {ex.Message}");
                        
                        string userMessage = "Could not run Privado CLI or Docker. Please ensure 'privado' CLI is installed OR Docker Desktop is running.";
                        if (ex.Message.Contains("npipe") || ex.Message.Contains("dockerDesktopLinuxEngine") || ex.Message.Contains("daemon is not running"))
                        {
                            userMessage = "Docker Desktop is not running or not accessible. Please start Docker Desktop and try again.";
                        }

                        violations.Add(CreateSystemViolation("Advanced Scan Requirement Missing", 
                            $"{userMessage} Error: {ex.Message}"));
                        return violations;
                    }
                }

                // 3. Parse output
                var jsonPath = Path.Combine(path, ".privado", "privado.json");
                if (File.Exists(jsonPath))
                {
                    var jsonContent = await File.ReadAllTextAsync(jsonPath);
                    var privadoResult = JsonSerializer.Deserialize<PrivadoResult>(jsonContent);

                    if (privadoResult?.DataElements != null)
                    {
                        foreach (var element in privadoResult.DataElements)
                        {
                            var rule = new AuditRule(
                                "PRIVADO-DATA-" + element.Name.ToUpper().Replace(" ", "_"),
                                $"Privado: {element.Name} Found",
                                "Data Privacy",
                                $"Privado detected usage of {element.Name}",
                                AuditSeverity.High,
                                "Review data usage and ensure compliance (GDPR/CCPA).",
                                "https://docs.privado.ai/",
                                null! 
                            );

                            if (element.Collections != null)
                            {
                                foreach (var collection in element.Collections)
                                {
                                     var parts = collection.Split(':');
                                     var file = parts[0];
                                     // Fix file path if it comes from Docker container (e.g. starts with /app/code)
                                     if (file.StartsWith("/app/code"))
                                     {
                                         file = file.Replace("/app/code", "").TrimStart('/', '\\');
                                         // If we want absolute path matching the host
                                         file = Path.Combine(path, file);
                                     }

                                     int line = 1;
                                     if (parts.Length > 1 && int.TryParse(parts[1], out int l)) line = l;

                                     violations.Add(new Violation(file, line, $"Collection of {element.Name}", rule));
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Privado integration error: {ex.Message}");
                violations.Add(CreateSystemViolation("Advanced Scan Error", $"An unexpected error occurred during deep scan: {ex.Message}"));
            }

            return violations;
        }

        private async Task RunProcessAsync(string fileName, string arguments, string workingDir, string jobId, bool checkOnly = false)
        {
            Console.WriteLine($"[PrivadoScanner] Running command: {fileName} {arguments} in {workingDir}");
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = workingDir
            };

            using var process = new Process { StartInfo = psi };
            
            var outputBuilder = new System.Text.StringBuilder();
            var errorBuilder = new System.Text.StringBuilder();

            process.OutputDataReceived += (sender, e) => { 
                if (e.Data != null) {
                    Console.WriteLine($"[PrivadoScanner] STDOUT: {e.Data}"); 
                    outputBuilder.AppendLine(e.Data);
                }
            };
            process.ErrorDataReceived += (sender, e) => { 
                if (e.Data != null) {
                    Console.WriteLine($"[PrivadoScanner] STDERR: {e.Data}"); 
                    errorBuilder.AppendLine(e.Data);
                }
            };

            process.Start();
            
            // Store PID in database for cancellation
            if (!checkOnly && !string.IsNullOrEmpty(jobId))
            {
                try 
                {
                    await _progressRepo.UpdateProcessIdAsync(jobId, process.Id);
                    Console.WriteLine($"[PrivadoScanner] Process ID {process.Id} stored for Job {jobId}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[PrivadoScanner] Failed to store Process ID: {ex.Message}");
                }
            }

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            // shorter timeout for checkOnly
            var timeout = checkOnly ? TimeSpan.FromSeconds(5) : TimeSpan.FromMinutes(30);
            var cts = new CancellationTokenSource(timeout);

            try 
            {
                await process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                process.Kill();
                throw new Exception($"Command '{fileName}' timed out.");
            }

            if (process.ExitCode != 0)
            {
                var fullMessage = $"Exit Code: {process.ExitCode}\nError: {errorBuilder}\nOutput: {outputBuilder}";
                throw new Exception($"Command failed. {fullMessage}");
            }
        }

        private Violation CreateSystemViolation(string title, string message)
        {
             var rule = new AuditRule(
                "SYSTEM-ADV-SCAN-ERR",
                title,
                "System Configuration",
                message,
                AuditSeverity.Critical,
                "Install Privado CLI or start Docker Desktop.",
                "https://docs.privado.ai/",
                null!
            );
            return new Violation("System", 0, message, rule);
        }

        // Helper classes for Privado JSON deserialization
        private class PrivadoResult
        {
            public List<PrivadoDataElement>? DataElements { get; set; }
        }

        private class PrivadoDataElement
        {
            public string Name { get; set; } = "";
            public List<string>? Collections { get; set; }
        }
    }
}
