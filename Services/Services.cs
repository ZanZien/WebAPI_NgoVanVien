using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using WebAPI_TongNhatBaoAn.Data;
using WebAPI_TongNhatBaoAn.Dtos;
using WebAPI_TongNhatBaoAn.Models;

namespace WebAPI_TongNhatBaoAn.Services;

/// <summary>Múi giờ Việt Nam (UTC+7, không có giờ mùa hè). Dữ liệu lưu UTC, nghiệp vụ tính theo giờ VN.</summary>
public static class TimeVn
{
    public static readonly TimeSpan Offset = TimeSpan.FromHours(7);
    public static DateTime ToLocal(DateTime utc) => DateTime.SpecifyKind(utc, DateTimeKind.Utc).Add(Offset).WithKind(DateTimeKind.Unspecified);
    public static DateTime ToUtc(DateTime local) => DateTime.SpecifyKind(local - Offset, DateTimeKind.Utc);
    public static string DayKey(DateTime d) => d.ToString("yyyy-MM-dd");
    private static DateTime WithKind(this DateTime d, DateTimeKind k) => DateTime.SpecifyKind(d, k);
}

public static class GeoService
{
    public static double DistanceMeters(double lat1, double lon1, double lat2, double lon2)
    {
        const double rad = Math.PI / 180;
        var h = Math.Pow(Math.Sin((lat1 - lat2) * rad / 2), 2) +
                Math.Cos(lat1 * rad) * Math.Cos(lat2 * rad) * Math.Pow(Math.Sin((lon1 - lon2) * rad / 2), 2);
        return 6371000 * 2 * Math.Atan2(Math.Sqrt(h), Math.Sqrt(Math.Max(0, 1 - h)));
    }
}

public class QrService
{
    public static string NewSecret() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private static string Sign(string secret, long slot)
    {
        using var h = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return $"BAOAN:{slot}:{Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes($"baoan:{slot}"))).ToLowerInvariant()}";
    }

    public static long SlotOf(DateTime utc) => new DateTimeOffset(DateTime.SpecifyKind(utc, DateTimeKind.Utc)).ToUnixTimeSeconds() / 60;

    public QrResponse Create(string secret, DateTime nowUtc)
    {
        var slot = SlotOf(nowUtc);
        return new QrResponse(Sign(secret, slot), DateTimeOffset.FromUnixTimeSeconds((slot + 2) * 60).UtcDateTime);
    }

    public bool IsValid(string secret, string? code, DateTime nowUtc)
    {
        if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(code)) return false;
        var slot = SlotOf(nowUtc);
        var given = Encoding.UTF8.GetBytes(code);
        return new[] { slot, slot - 1 }.Any(s =>
            CryptographicOperations.FixedTimeEquals(given, Encoding.UTF8.GetBytes(Sign(secret, s))));
    }
}

public class TokenService(IConfiguration cfg, AppDb db)
{
    private SymmetricSecurityKey Key => new(Encoding.UTF8.GetBytes(cfg["Jwt:Key"]!));

    public (string token, DateTime expires) CreateAccess(Employee e)
    {
        var expires = DateTime.UtcNow.AddMinutes(int.Parse(cfg["Jwt:AccessMinutes"] ?? "30"));
        var jwt = new JwtSecurityToken(
            claims: [new Claim("uid", e.Id.ToString()), new Claim("role", e.Role), new Claim("name", e.Name)],
            expires: expires,
            signingCredentials: new SigningCredentials(Key, SecurityAlgorithms.HmacSha256));
        return (new JwtSecurityTokenHandler().WriteToken(jwt), expires);
    }

    public static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    public string CreateRefresh(Employee e)
    {
        var raw = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
        db.RefreshTokens.Add(new RefreshToken
        {
            EmployeeId = e.Id,
            TokenHash = Hash(raw),
            ExpiresAt = DateTime.UtcNow.AddDays(int.Parse(cfg["Jwt:RefreshDays"] ?? "7"))
        });
        return raw;
    }
}

public class OtpService(AppDb db, IConfiguration cfg, OtpEmailSender emailSender, IHostEnvironment environment)
{
    public bool DebugReturn => environment.IsDevelopment() && cfg.GetValue<bool>("Auth:DebugReturnOtp");

    private static string HashCode(Guid id, string code) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{id}:{code}")));

    public (OtpChallenge challenge, string code) Create(Guid employeeId, string purpose)
    {
        var code = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
        var c = new OtpChallenge
        {
            EmployeeId = employeeId,
            Purpose = purpose,
            ExpiresAt = DateTime.UtcNow.AddMinutes(int.Parse(cfg["Auth:OtpMinutes"] ?? "5"))
        };
        c.CodeHash = HashCode(c.Id, code);
        db.OtpChallenges.Add(c);
        return (c, code);
    }

    public async Task<(Employee? employee, string? error)> VerifyAsync(Guid challengeId, string? code, string purpose)
    {
        const string fail = "OTP hết hạn hoặc không hợp lệ. Hãy thử lại.";
        var c = await db.OtpChallenges.FirstOrDefaultAsync(x => x.Id == challengeId && x.Purpose == purpose);
        if (c == null || c.Consumed || c.ExpiresAt < DateTime.UtcNow || c.Attempts >= 5) return (null, fail);
        c.Attempts++;
        var ok = CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(HashCode(c.Id, (code ?? "").Trim())), Encoding.UTF8.GetBytes(c.CodeHash));
        if (ok) c.Consumed = true;
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateConcurrencyException) { return (null, fail); }
        if (!ok) return (null, "OTP không đúng.");
        var emp = await db.Employees.FindAsync(c.EmployeeId);
        return emp == null ? (null, fail) : (emp, null);
    }

    public Task SendAsync(string to, string subject, string code)
    {
        // Local development only; never bypass email verification on Render.
        if (DebugReturn) return Task.CompletedTask;
        return emailSender.SendAsync(to, subject, code);
    }

}

public static class Validators
{
    private static readonly System.Text.RegularExpressions.Regex UserRx = new("^[a-zA-Z0-9_.-]{3,40}$");
    private static readonly System.Text.RegularExpressions.Regex MailRx = new(@"^[^\s@]+@[^\s@]+\.[^\s@]+$");

    public static string? Employee(string? name, string? username, string? email, string? password = null)
    {
        if (string.IsNullOrWhiteSpace(name) || username == null || !UserRx.IsMatch(username.Trim()))
            return "Nhập họ tên và tên đăng nhập 3–40 ký tự không dấu (chữ, số, _, ., -).";
        if (email == null || !MailRx.IsMatch(email.Trim())) return "Email không hợp lệ.";
        if (password != null && password.Length < 8) return "Mật khẩu phải có ít nhất 8 ký tự.";
        return null;
    }
}
