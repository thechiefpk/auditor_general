using ComplianceSecurityAuditor.Services;
using ComplianceSecurityAuditor.Data;
using ComplianceSecurityAuditor.Validators;
using SecureSoftAPI.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using FluentValidation;
using System.Text;
using Hangfire;
using Hangfire.SqlServer;
using Microsoft.Data.SqlClient;

var builder = WebApplication.CreateBuilder(args);

// Configure explicit URLs so the server listens on well-known ports for local dev
// HTTP used by some clients, HTTPS used by Swagger and secure clients
builder.WebHost.UseUrls("http://localhost:5059", "https://localhost:7120");

// Add services to the container.
builder.Services.AddControllers();

// CORS - allow local frontend dev servers (Vite5173, CRA3000) to call the API
builder.Services.AddCors(options =>
{
    options.AddPolicy(name: "AllowFrontend",
        policy =>
        {
            policy.WithOrigins("http://localhost:5173", "https://localhost:5173", "http://localhost:3000")
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
        });
});


// Add CORS configuration
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocalhost", policy =>
    {
        policy.WithOrigins("http://localhost:3000", "https://localhost:3000")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});


// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Register FluentValidation
builder.Services.AddValidatorsFromAssemblyContaining<LoginRequestValidator>();

// Prefer env var CONNECTION_STRING if present; otherwise use local dev with TrustServerCertificate
var conn = builder.Configuration["SQL_SERVER_CONNECTION"];
builder.Services.AddSingleton<ISqlReportRepository>(new SqlReportRepository(conn));
builder.Services.AddSingleton<IScanProgressRepository>(new SqlScanProgressRepository(conn));
builder.Services.AddSingleton<IScheduleRepository>(new SqlScheduleRepository(conn));

// register ComplianceService with repo
builder.Services.AddScoped<ComplianceService>(sp => new ComplianceService(sp.GetService<ISqlReportRepository>()));
builder.Services.AddScoped<SqlScanner>();
builder.Services.AddScoped<AdvancedScanPipeline>();
builder.Services.AddScoped<ScanJobService>();
builder.Services.AddScoped<PdfReportService>();
builder.Services.AddScoped<NetworkAuditService>();

// Register Scheduler Service
builder.Services.AddHostedService<SchedulerService>();

builder.Services.AddHangfire(configuration => configuration
    .UseSimpleAssemblyNameTypeSerializer()
    .UseRecommendedSerializerSettings()
    .UseSqlServerStorage(conn, new SqlServerStorageOptions
    {
        PrepareSchemaIfNecessary = true
    }));
builder.Services.AddHangfireServer();

// register auth repository and service
builder.Services.AddSingleton<IAuthRepository>(new SqlAuthRepository(conn));
builder.Services.AddScoped<AuthService>();

// JWT configuration - use environment variable 'JWT_SECRET' or a fallback (dev only)
var jwtSecret = builder.Configuration["JWT_SECRET"];
if (string.IsNullOrEmpty(jwtSecret))
{
    Console.WriteLine("CRITICAL: JWT_SECRET is null or empty!");
}
else
{
    Console.WriteLine($"JWT_SECRET found, length: {jwtSecret.Length}");
}
var key = Encoding.ASCII.GetBytes(jwtSecret ?? "default_secret_should_be_long_enough_for_hmacsha256");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ClockSkew = TimeSpan.Zero
    };
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            Console.WriteLine($"Authentication failed: {context.Exception.Message}");
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            Console.WriteLine("Token validated successfully.");
            return Task.CompletedTask;
        },
        OnMessageReceived = context =>
        {
            Console.WriteLine($"Token received: {context.Token?.Substring(0, Math.Min(10, context.Token?.Length ?? 0))}...");
            return Task.CompletedTask;
        },
        OnChallenge = context =>
        {
            Console.WriteLine($"OnChallenge: {context.Error}, {context.ErrorDescription}, {context.AuthenticateFailure?.Message}");
            return Task.CompletedTask;
        }
    };
});

var app = builder.Build();

// Cleanup stuck jobs on startup
try
{
    using (var connection = new SqlConnection(conn))
    {
        connection.Open();
        var command = new SqlCommand("UPDATE ScanProgress SET Status = 'Failed', Error = 'Server restarted' WHERE Status IN ('Cloning', 'Scanning')", connection);
        command.ExecuteNonQuery();
    }
}
catch (Exception ex)
{
    Console.WriteLine($"Error cleaning up stuck jobs: {ex.Message}");
}

// Use CORS before routing/controllers
app.UseCors("AllowFrontend");

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseHangfireDashboard("/hangfire");

app.MapControllers();

app.Run();
