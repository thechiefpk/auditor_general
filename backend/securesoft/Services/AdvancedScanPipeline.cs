using ComplianceSecurityAuditor.Data;
using ComplianceSecurityAuditor.Models;
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace ComplianceSecurityAuditor.Services
{
    public class AdvancedScanPipeline
    {
        private readonly IScanProgressRepository _progressRepo;

        private const string PresidioScanScript = "import os,sys,json\nfrom presidio_analyzer import AnalyzerEngine\n\ndef is_text_file(path):\n    try:\n        with open(path,\"rb\") as f:\n            chunk = f.read(1024)\n        if b\"\\0\" in chunk:\n            return False\n        return True\n    except Exception:\n        return False\n\ndef main():\n    if len(sys.argv) < 3:\n        sys.exit(1)\n    root = sys.argv[1]\n    out_path = sys.argv[2]\n    analyzer = AnalyzerEngine()\n    results = []\n    for dirpath, dirnames, filenames in os.walk(root):\n        for name in filenames:\n            file_path = os.path.join(dirpath, name)\n            if not is_text_file(file_path):\n                continue\n            rel_path = os.path.relpath(file_path, root)\n            try:\n                with open(file_path, encoding=\"utf-8\", errors=\"ignore\") as f:\n                    for idx, line in enumerate(f, 1):\n                        line_strip = line.strip()\n                        if not line_strip:\n                            continue\n                        analyze_results = analyzer.analyze(text=line_strip, entities=None, language=\"en\")\n                        for r in analyze_results:\n                            results.append({\"entity_type\": r.entity_type, \"location\": {\"filename\": rel_path.replace(\"\\\\\", \"/\"), \"line\": idx}})\n            except Exception:\n                continue\n    with open(out_path, \"w\", encoding=\"utf-8\") as out_f:\n        json.dump(results, out_f)\n\nif __name__ == \"__main__\":\n    main()\n";

        public AdvancedScanPipeline(IScanProgressRepository progressRepo)
        {
            _progressRepo = progressRepo;
        }

        public async Task<ScanSummary> RunAsync(Guid userId, string path, string jobId, string? repositoryUrl = null, string? branch = null)
        {
            path = path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

            var violations = new List<Violation>();
            var tools = new List<Func<Task<List<Violation>>>>();

            tools.Add(() => RunPresidioAsync(path, jobId));
            tools.Add(() => RunSemgrepAsync(path, jobId));

            var toolNames = new[] { "Microsoft Presidio", "Semgrep" };

            for (int i = 0; i < tools.Count; i++)
            {
                var name = toolNames[i];
                var stageMessage = "Running " + name + "...";
                await _progressRepo.UpdateAsync(jobId, "Deep Scan", stageMessage, 0, i, violations.Count, (int)((i / (double)tools.Count) * 100));

                try
                {
                    var toolViolations = await tools[i]();
                    violations.AddRange(toolViolations);
                }
                catch (Exception ex)
                {
                    violations.Add(CreateSystemViolation(name + " Error", name + " failed: " + ex.Message));
                }
            }

            var deduped = violations
                .GroupBy(v => new { v.FilePath, v.LineNumber, RuleId = v.ViolatedRule.RuleId, v.Engine, v.MatchedText })
                .Select(g => g.First())
                .ToList();

            var summary = new ScanSummary
            {
                ScanPath = path,
                FilesScanned = 0,
                ViolationsFound = deduped.Count,
                Violations = deduped,
                ScanDate = DateTime.UtcNow,
                RepositoryUrl = repositoryUrl,
                Branch = branch
            };

            return summary;
        }

        private async Task<List<Violation>> RunPresidioAsync(string path, string jobId)
        {
            var violations = new List<Violation>();
            var resultPath = Path.Combine(path, ".adv-scan", "presidio.json");
            Directory.CreateDirectory(Path.GetDirectoryName(resultPath));

            var tempDir = Path.Combine(Path.GetTempPath(), "advscan");
            Directory.CreateDirectory(tempDir);
            var scriptPath = Path.Combine(tempDir, "presidio_scan.py");
            if (!File.Exists(scriptPath))
            {
                await File.WriteAllTextAsync(scriptPath, PresidioScanScript);
            }

            var args = Quote(scriptPath) + " " + Quote(path) + " " + Quote(resultPath);
            
            // Explicitly use Python 3.12 executable to avoid 'py' launcher ambiguity or system PATH issues.
            // This fixes the pydantic/spacy incompatibility in Python 3.14.
            var pythonExe = @"C:\Users\Price Kumar\AppData\Local\Programs\Python\Python312\python.exe";
            if (!File.Exists(pythonExe))
            {
                 // Fallback to py launcher if specific path not found (though less reliable)
                 pythonExe = "py";
                 args = "-3.12 " + args;
            }

            var output = await RunProcessAsync(pythonExe, args, path, jobId, TimeSpan.FromMinutes(10));

            if (File.Exists(resultPath))
            {
                var json = await File.ReadAllTextAsync(resultPath);
                using var doc = JsonDocument.Parse(json);
                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    var entityType = item.GetProperty("entity_type").GetString();
                    var location = item.GetProperty("location");
                    var file = location.TryGetProperty("filename", out var f) ? f.GetString() : "Unknown";
                    var line = location.TryGetProperty("line", out var l) ? l.GetInt32() : 0;

                    var rule = new Audit.AuditRule(
                        "ADV-PRESIDIO-" + (entityType ?? "UNKNOWN").ToUpperInvariant(),
                        "Presidio: " + entityType + " detected",
                        "PII",
                        "Microsoft Presidio detected " + entityType + " in content.",
                        Audit.AuditSeverity.High,
                        "Review and ensure compliant handling of this personal data.",
                        "https://github.com/microsoft/presidio",
                        null!
                    );

                    var violation = new Violation(file ?? "Unknown", line, "PII: " + entityType, rule);
                    violation.Engine = "Presidio";
                    violations.Add(violation);
                }
            }

            return violations;
        }

        private async Task<List<Violation>> RunSemgrepAsync(string path, string jobId)
        {
            var violations = new List<Violation>();
            var resultPath = Path.Combine(path, ".adv-scan", "semgrep.json");
            Directory.CreateDirectory(Path.GetDirectoryName(resultPath));

            var args = "scan --config auto --json --output " + Quote(resultPath) + " " + Quote(path);
            
            // Define fallback path for Semgrep if global command fails
            var fallbackPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Python", "Python314", "Scripts", "semgrep.exe");
            
            try
            {
                // Try global semgrep first
                var output = await RunProcessAsync("semgrep", args, path, jobId, TimeSpan.FromMinutes(10));
            }
            catch (Exception)
            {
                if (File.Exists(fallbackPath))
                {
                    // When running from fallback path, we MUST add the directory to PATH
                    // because semgrep.exe calls pysemgrep.exe which is in the same folder.
                    var scriptDir = Path.GetDirectoryName(fallbackPath);
                    var output = await RunProcessAsync(fallbackPath, args, path, jobId, TimeSpan.FromMinutes(10), scriptDir);
                }
                else
                {
                    throw;
                }
            }

            if (File.Exists(resultPath))
            {
                var json = await File.ReadAllTextAsync(resultPath);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("results", out var results))
                {
                    foreach (var item in results.EnumerateArray())
                    {
                        var checkId = item.GetProperty("check_id").GetString();
                        var pathProp = item.GetProperty("path").GetString();
                        var start = item.GetProperty("start");
                        var line = start.GetProperty("line").GetInt32();
                        var message = item.GetProperty("extra").GetProperty("message").GetString();

                        var rule = new Audit.AuditRule(
                            "ADV-SEMGRP-" + (checkId ?? "UNKNOWN").ToUpperInvariant(),
                            "Semgrep: " + checkId,
                            "Static Analysis",
                            message ?? "Semgrep rule triggered.",
                            Audit.AuditSeverity.Medium,
                            "Review this pattern and apply the recommended remediation.",
                            "https://semgrep.dev/",
                            null!
                        );

                        var violation = new Violation(pathProp ?? "Unknown", line, message ?? "Semgrep finding", rule);
                        violation.Engine = "Semgrep";
                        violations.Add(violation);
                    }
                }
            }

            return violations;
        }

        private async Task<string> RunProcessAsync(string fileName, string arguments, string workingDir, string jobId, TimeSpan timeout, string? addToPath = null)
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = workingDir,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            
            // Force Python/Semgrep to use UTF-8 to avoid charmap codec errors on Windows
            psi.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8";
            psi.EnvironmentVariables["PYTHONUTF8"] = "1"; // Forces Python 3.7+ to use UTF-8 for all I/O
            psi.EnvironmentVariables["LANG"] = "C.UTF-8";

            if (!string.IsNullOrEmpty(addToPath))
            {
                var currentPath = Environment.GetEnvironmentVariable("PATH") ?? "";
                psi.EnvironmentVariables["PATH"] = addToPath + Path.PathSeparator + currentPath;
            }

            var outputBuilder = new StringBuilder();
            var errorBuilder = new StringBuilder();

            using var process = new Process { StartInfo = psi };

            process.OutputDataReceived += (sender, e) =>
            {
                if (e.Data != null)
                {
                    outputBuilder.AppendLine(e.Data);
                }
            };

            process.ErrorDataReceived += (sender, e) =>
            {
                if (e.Data != null)
                {
                    errorBuilder.AppendLine(e.Data);
                }
            };

            process.Start();

            try
            {
                await _progressRepo.UpdateProcessIdAsync(jobId, process.Id);
            }
            catch (Exception)
            {
            }

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            var cts = new CancellationTokenSource(timeout);
            try
            {
                await process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                process.Kill();
                throw new Exception("Command " + fileName + " timed out.");
            }

            if (process.ExitCode != 0)
            {
                var msg = "Exit Code: " + process.ExitCode + " Error: " + errorBuilder.ToString();
                throw new Exception(msg);
            }

            return outputBuilder.ToString();
        }

        private Violation CreateSystemViolation(string title, string message)
        {
            var rule = new Audit.AuditRule(
               "SYSTEM-ADV-SCAN-ERR",
               title,
               "System Configuration",
               message,
               Audit.AuditSeverity.Critical,
               "Ensure required advanced scan tools are installed and accessible on PATH.",
               "",
               null!
           );
            var violation = new Violation("System", 0, message, rule);
            violation.Engine = "System";
            return violation;
        }

        private static string Quote(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }
    }
}
