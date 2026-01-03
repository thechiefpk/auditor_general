using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ComplianceSecurityAuditor.Data;
using ComplianceSecurityAuditor.Models;
using Hangfire;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace ComplianceSecurityAuditor.Services
{
    public class SchedulerService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;

        public SchedulerService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            Console.WriteLine("Scheduler Service Starting...");
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    using (var scope = _serviceProvider.CreateScope())
                    {
                        var repo = scope.ServiceProvider.GetRequiredService<IScheduleRepository>();
                        var progressRepo = scope.ServiceProvider.GetRequiredService<IScanProgressRepository>();
                        
                        var schedules = await repo.GetDueSchedulesAsync();

                        foreach (var schedule in schedules)
                        {
                            await ProcessScheduleAsync(schedule, repo, progressRepo);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Scheduler Error: {ex.Message}");
                }

                // Check every minute
                await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            }
        }

        private async Task ProcessScheduleAsync(ScanSchedule schedule, IScheduleRepository repo, IScanProgressRepository progressRepo)
        {
            var jobId = Guid.NewGuid().ToString("N");
            string hangfireJobId = "";

            try
            {
                // Parse Config
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                
                // Trigger Scan based on Type
                switch (schedule.ScanType.ToLower())
                {
                    case "local":
                        var localReq = JsonSerializer.Deserialize<ScanRequest>(schedule.ConfigJson, options);
                        if (localReq != null)
                        {
                            hangfireJobId = BackgroundJob.Enqueue<ScanJobService>(s => s.RunLocalScan(jobId, schedule.UserId, localReq.Path, localReq.IsAdvanced, schedule.Id));
                        }
                        break;

                    case "git":
                        // We need a specific model for Git config or reuse dynamic
                        var gitConfig = JsonSerializer.Deserialize<GitScanRequest>(schedule.ConfigJson, options);
                        if (gitConfig != null)
                        {
                             hangfireJobId = BackgroundJob.Enqueue<ScanJobService>(s => s.RunGitScan(jobId, schedule.UserId, gitConfig.RepositoryUrl, gitConfig.Branch, null, gitConfig.IsAdvanced, schedule.Id));
                        }
                        break;

                    case "sql":
                        var sqlReq = JsonSerializer.Deserialize<ScanRequest>(schedule.ConfigJson, options);
                        if (sqlReq != null)
                        {
                            hangfireJobId = BackgroundJob.Enqueue<ScanJobService>(s => s.RunSqlScan(jobId, schedule.UserId, sqlReq.Path, schedule.Id));
                        }
                        break;
                    
                    case "network":
                        var netConfig = JsonSerializer.Deserialize<NetworkScanConfig>(schedule.ConfigJson, options);
                        if (netConfig != null)
                        {
                            hangfireJobId = BackgroundJob.Enqueue<ScanJobService>(s => s.RunNetworkScan(jobId, schedule.UserId, netConfig.Target, schedule.Id));
                        }
                        break;
                }

                if (!string.IsNullOrEmpty(hangfireJobId))
                {
                    await progressRepo.StartAsync(jobId, schedule.UserId, "Scheduled", hangfireJobId);
                    Console.WriteLine($"Triggered Scheduled Scan {schedule.Id} (Job: {jobId})");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to trigger schedule {schedule.Id}: {ex.Message}");
            }

            // Calculate Next Run
            var nextRun = CalculateNextRun(schedule.NextRun, schedule.Frequency);
            
            // If next run is still in past (e.g. we missed multiple), jump to future
            if (nextRun < DateTime.UtcNow)
            {
                nextRun = CalculateNextRun(DateTime.UtcNow, schedule.Frequency);
            }

            await repo.UpdateExecutionAsync(schedule.Id, DateTime.UtcNow, nextRun);
        }

        private DateTime CalculateNextRun(DateTime current, string frequency)
        {
            return frequency.ToLower() switch
            {
                "hourly" => current.AddHours(1),
                "daily" => current.AddDays(1),
                "weekly" => current.AddDays(7),
                "monthly" => current.AddMonths(1),
                _ => current.AddDays(1) // Default
            };
        }

        private class NetworkScanConfig
        {
            public string Target { get; set; }
        }
    }
}
