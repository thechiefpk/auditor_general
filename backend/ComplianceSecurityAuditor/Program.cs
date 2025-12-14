using ComplianceSecurityAuditor.Services;
using ComplianceSecurityAuditor.Data;
using SecureSoftAPI.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

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

// Prefer env var CONNECTION_STRING if present; otherwise use local dev with TrustServerCertificate
var conn = builder.Configuration["SQL_SERVER_CONNECTION"];
builder.Services.AddSingleton<ISqlReportRepository>(new SqlReportRepository(conn));

// register ComplianceService with repo
builder.Services.AddScoped<ComplianceService>(sp => new ComplianceService(sp.GetService<ISqlReportRepository>()));

// register auth repository and service
builder.Services.AddSingleton<IAuthRepository>(new SqlAuthRepository(conn));
builder.Services.AddScoped<AuthService>();

// JWT configuration - use environment variable 'JWT_SECRET' or a fallback (dev only)
var jwtSecret = builder.Configuration["JWT_SECRET"];
var key = Encoding.ASCII.GetBytes(jwtSecret);

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
});

var app = builder.Build();

// Dev-only: ensure SQL schema exists
if (app.Environment.IsDevelopment())
{
    await DevSqlSchemaInitializer.EnsureAsync(conn);
}

// Use CORS before routing/controllers
app.UseCors("AllowFrontend");

// After app is built
app.UseCors("AllowLocalhost");

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
