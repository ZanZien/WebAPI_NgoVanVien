using System.Net;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using WebAPI_TongNhatBaoAn.Data;
using WebAPI_TongNhatBaoAn.Models;
using WebAPI_TongNhatBaoAn.Services;

var builder = WebApplication.CreateBuilder(args);

var port = Environment.GetEnvironmentVariable("PORT");
if (!string.IsNullOrEmpty(port)) builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

var connectionString = NormalizeConnectionString(
    builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException("Thiếu biến môi trường ConnectionStrings__Default."));
var jwtKey = builder.Configuration["Jwt:Key"];
if (string.IsNullOrEmpty(jwtKey) || jwtKey.Length < 32)
    throw new InvalidOperationException("Jwt__Key phải có ít nhất 32 ký tự.");

builder.Services.AddDbContext<AppDb>(o => o.UseNpgsql(connectionString,
    npgsql => npgsql.EnableRetryOnFailure(maxRetryCount: 4, maxRetryDelay: TimeSpan.FromSeconds(3), errorCodesToAdd: null)));
builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<OtpService>();
builder.Services.AddHttpClient<OtpEmailSender>(client => client.Timeout = TimeSpan.FromSeconds(15));
builder.Services.AddSingleton<QrService>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
{
    o.MapInboundClaims = false;
    o.Events = new JwtBearerEvents
    {
        OnTokenValidated = async context =>
        {
            var raw = context.Principal?.FindFirst("uid")?.Value;
            if (!Guid.TryParse(raw, out var uid)) { context.Fail("Invalid user."); return; }
            var db = context.HttpContext.RequestServices.GetRequiredService<AppDb>();
            var employee = await db.Employees.AsNoTracking().FirstOrDefaultAsync(e => e.Id == uid);
            if (employee == null || !employee.Active || !employee.EmailVerified ||
                employee.Role != context.Principal?.FindFirst("role")?.Value)
                context.Fail("Account access changed. Sign in again.");
        }
    };
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        ValidateIssuer = false,
        ValidateAudience = false,
        NameClaimType = "uid",
        RoleClaimType = "role",
        ClockSkew = TimeSpan.FromSeconds(30)
    };
});
builder.Services.AddAuthorization();

builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("auth", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 20, Window = TimeSpan.FromMinutes(1) }));
});

builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownIPNetworks.Clear();
    o.KnownProxies.Clear();
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Configuration.GetValue<bool>("RUN_MIGRATIONS"))
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    await db.Database.MigrateAsync();
    await SeedAsync(db, app.Configuration);
}
else
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    await EnsureDepartmentsTableAsync(db);
    await SeedAsync(db, app.Configuration);
}

app.UseForwardedHeaders();
app.UseSwagger();
app.UseSwaggerUI();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Redirect("/swagger"));
app.MapGet("/health/live", () => Results.Ok(new { status = "ok" }));
app.MapGet("/health/ready", async (AppDb db) =>
    await db.Database.CanConnectAsync()
        ? Results.Ok(new { status = "ready" })
        : Results.StatusCode(StatusCodes.Status503ServiceUnavailable));
app.MapControllers();

app.Run();

static string NormalizeConnectionString(string value)
{
    if (!value.StartsWith("postgres://") && !value.StartsWith("postgresql://")) return value;
    var uri = new Uri(value);
    var parts = uri.UserInfo.Split(':', 2);
    var ssl = uri.Host is "localhost" or "127.0.0.1" ? "Prefer" : "Require";
    return $"Host={uri.Host};Port={(uri.Port > 0 ? uri.Port : 5432)};Database={uri.AbsolutePath.TrimStart('/')};" +
           $"Username={Uri.UnescapeDataString(parts[0])};Password={Uri.UnescapeDataString(parts.Length > 1 ? parts[1] : "")};SSL Mode={ssl}";
}

static async Task EnsureDepartmentsTableAsync(AppDb db)
{
    try
    {
        await db.Database.ExecuteSqlRawAsync(@"
            CREATE TABLE IF NOT EXISTS ""Departments"" (
                ""Id"" uuid NOT NULL PRIMARY KEY,
                ""Name"" character varying(100) NOT NULL,
                ""Description"" text NULL,
                ""CreatedAt"" timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc')
            );
        ");
    }
    catch { /* Ignore if already exists */ }
}

static async Task SeedAsync(AppDb db, IConfiguration cfg)
{
    await EnsureDepartmentsTableAsync(db);

    if (await db.Offices.FindAsync(1) == null)
        db.Offices.Add(new Office { QrSecret = QrService.NewSecret() });

    if (!await db.Departments.AnyAsync())
    {
        db.Departments.AddRange(
            new Department { Name = "Phòng Kỹ thuật", Description = "Phát triển phần mềm và hạ tầng công nghệ" },
            new Department { Name = "Phòng Kinh doanh", Description = "Kinh doanh và chăm sóc khách hàng" },
            new Department { Name = "Phòng Kế toán", Description = "Quản lý tài chính và kế toán" },
            new Department { Name = "Phòng Nhân sự", Description = "Quản trị nguồn nhân lực và tuyển dụng" }
        );
    }

    var username = cfg["Seed:AdminUsername"]?.Trim().ToLowerInvariant();
    var email = cfg["Seed:AdminEmail"]?.Trim().ToLowerInvariant();
    var password = cfg["Seed:AdminPassword"];
    var existingAdmin = await db.Employees.FirstOrDefaultAsync(e => e.Role == Roles.Admin);
    if (existingAdmin == null &&
        !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(email) && password is { Length: >= 8 })
    {
        db.Employees.Add(new Employee
        {
            Name = cfg["Seed:AdminName"] ?? "Quản trị viên", Username = username, Email = email,
            Role = Roles.Admin, EmailVerified = true, PasswordHash = BCrypt.Net.BCrypt.HashPassword(password)
        });
    }
    else if (existingAdmin != null && !string.IsNullOrEmpty(email) && existingAdmin.Email != email)
    {
        existingAdmin.Email = email;
    }
    await db.SaveChangesAsync();
}
