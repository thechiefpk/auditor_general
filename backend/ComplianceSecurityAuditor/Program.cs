using ComplianceSecurityAuditor.Server;
using ComplianceSecurityAuditor.Services;
using ComplianceSecurityAuditor.Data;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// configure SQL repo with provided connection string
var conn = "Server=localhost\\SQLEXPRESS;Database=secureSoft;Trusted_Connection=True;";
builder.Services.AddSingleton<ISqlReportRepository>(new SqlReportRepository(conn));

// register ComplianceService with repo
builder.Services.AddScoped<ComplianceService>(sp => 
    new ComplianceService(sp.GetService<ISqlReportRepository>())
);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();       

app.Run();
