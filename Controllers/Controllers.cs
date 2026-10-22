using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using WebAPI_TongNhatBaoAn.Data;
using WebAPI_TongNhatBaoAn.Dtos;
using WebAPI_TongNhatBaoAn.Models;
using WebAPI_TongNhatBaoAn.Services;

namespace WebAPI_TongNhatBaoAn.Controllers;

public abstract class ApiBase : ControllerBase
{
    protected Guid UserId => Guid.Parse(User.FindFirstValue("uid")!);
    protected IActionResult Fail(string message, int status = 400) => StatusCode(status, new { error = message });
}

[ApiController, Route("api/auth"), EnableRateLimiting("auth")]
public class AuthController(AppDb db, TokenService tokens, OtpService otp) : ApiBase
{
    private const string Verify = "verify-email", Login = "login";
    private static readonly string DummyHash = BCrypt.Net.BCrypt.HashPassword("dummy-password");

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest r)
    {
        var err = Validators.Employee(r.Name, r.Username, r.Email, r.Password);
        if (err != null) return Fail(err);
        var username = r.Username.Trim().ToLowerInvariant();
        var email = r.Email.Trim().ToLowerInvariant();
        var existing = await db.Employees.FirstOrDefaultAsync(e => e.Username == username || e.Email == email);
        // Recover an interrupted registration only with the original credentials.
        if (existing != null && (existing.Username != username || existing.Email != email ||
            existing.EmailVerified || !existing.Active || !BCrypt.Net.BCrypt.Verify(r.Password, existing.PasswordHash)))
            return Fail("Email hoặc tên đăng nhập đã tồn tại.", 409);

        var emp = existing ?? new Employee
        {
            Name = r.Name.Trim(), Email = email, Username = username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(r.Password), Role = Roles.Employee
        };
        if (existing == null) db.Employees.Add(emp);
        var (challenge, code) = otp.Create(emp.Id, Verify);
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException) { return Fail("Email hoặc tên đăng nhập đã tồn tại.", 409); }
        try { await otp.SendAsync(emp.Email, "Xác minh email đăng ký", code); }
        catch (OtpDeliveryException)
        {
            // Allow registration to be retried after delivery failure.
            db.OtpChallenges.Remove(challenge);
            if (existing == null) db.Employees.Remove(emp);
            await db.SaveChangesAsync();
            return Fail(OtpDeliveryException.PublicMessage, 503);
        }
        return Ok(new ChallengeResponse(challenge.Id, otp.DebugReturn ? code : null));
    }

    [HttpPost("verify-email")]
    public async Task<IActionResult> VerifyEmail(VerifyCodeRequest r)
    {
        var (emp, error) = await otp.VerifyAsync(r.ChallengeId, r.Code, Verify);
        if (emp == null) return Fail(error!, 400);
        emp.EmailVerified = true;
        await db.SaveChangesAsync();
        return Ok(new { verified = true });
    }

    [HttpPost("login")]
    public async Task<IActionResult> LoginStep1(LoginRequest r)
    {
        var username = (r.Username ?? "").Trim().ToLowerInvariant();
        var emp = await db.Employees.FirstOrDefaultAsync(e => e.Username == username);
        var passwordOk = BCrypt.Net.BCrypt.Verify(r.Password ?? "", emp?.PasswordHash ?? DummyHash);
        if (emp == null || !passwordOk || !emp.Active || !emp.EmailVerified)
            return Fail("Tên đăng nhập hoặc mật khẩu không đúng, tài khoản bị khóa hoặc chưa xác minh email.", 401);

        var (challenge, code) = otp.Create(emp.Id, Login);
        await db.SaveChangesAsync();
        try { await otp.SendAsync(emp.Email, "Mã OTP đăng nhập", code); }
        catch (OtpDeliveryException)
        {
            challenge.Consumed = true;
            await db.SaveChangesAsync();
            return Fail(OtpDeliveryException.PublicMessage, 503);
        }
        return Ok(new ChallengeResponse(challenge.Id, otp.DebugReturn ? code : null));
    }

    [HttpPost("verify-otp")]
    public async Task<IActionResult> VerifyOtp(VerifyCodeRequest r)
    {
        var (emp, error) = await otp.VerifyAsync(r.ChallengeId, r.Code, Login);
        if (emp == null) return Fail(error!, 401);
        if (!emp.Active || !emp.EmailVerified) return Fail("Tài khoản bị khóa hoặc chưa xác minh email.", 403);
        return Ok(await IssueAsync(emp));
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh(RefreshRequest r)
    {
        var hash = TokenService.Hash(r.RefreshToken ?? "");
        var stored = await db.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == hash);
        if (stored == null || stored.Revoked || stored.ExpiresAt < DateTime.UtcNow)
            return Fail("Phiên đăng nhập hết hạn.", 401);
        var emp = await db.Employees.FindAsync(stored.EmployeeId);
        if (emp == null || !emp.Active) return Fail("Phiên đăng nhập hết hạn.", 401);
        stored.Revoked = true;
        return Ok(await IssueAsync(emp));
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout(RefreshRequest r)
    {
        var hash = TokenService.Hash(r.RefreshToken ?? "");
        var stored = await db.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == hash);
        if (stored != null) { stored.Revoked = true; await db.SaveChangesAsync(); }
        return NoContent();
    }

    private async Task<TokenResponse> IssueAsync(Employee emp)
    {
        var (access, expires) = tokens.CreateAccess(emp);
        var refresh = tokens.CreateRefresh(emp);
        await db.SaveChangesAsync();
        return new TokenResponse(access, expires, refresh, EmployeeDto.From(emp));
    }
}

[ApiController, Route("api/me"), Authorize]
public class MeController(AppDb db) : ApiBase
{
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var emp = await db.Employees.FindAsync(UserId);
        return emp == null || !emp.Active ? Fail("Vui lòng đăng nhập lại.", 401) : Ok(EmployeeDto.From(emp));
    }
}

[ApiController, Route("api/employees"), Authorize(Roles = Roles.AdminOrManager)]
public class EmployeesController(AppDb db) : ApiBase
{
    [HttpGet]
    public async Task<IActionResult> List() =>
        Ok(await db.Employees.OrderBy(e => e.Name).Select(e => EmployeeDto.From(e)).ToListAsync());

    [HttpPost, Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Create(EmployeeCreate r)
    {
        var err = Validators.Employee(r.Name, r.Username, r.Email, r.Password ?? "");
        if (err != null) return Fail(err);
        var role = (r.Role ?? Roles.Employee).ToLowerInvariant();
        if (!Roles.IsValid(role)) return Fail("Vai trò không hợp lệ.");
        if (r.ShiftId != null && !await db.Shifts.AnyAsync(s => s.Id == r.ShiftId)) return Fail("Ca làm không tồn tại.");
        var username = r.Username.Trim().ToLowerInvariant();
        var email = r.Email.Trim().ToLowerInvariant();
        if (await db.Employees.AnyAsync(e => e.Username == username || e.Email == email))
            return Fail("Email hoặc tên đăng nhập đã tồn tại.", 409);

        var emp = new Employee
        {
            Name = r.Name.Trim(), Email = email, Username = username, Department = r.Department?.Trim() ?? "",
            Role = role, ShiftId = r.ShiftId, EmailVerified = true,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(r.Password)
        };
        db.Employees.Add(emp);
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException) { return Fail("Email hoặc tên đăng nhập đã tồn tại.", 409); }
        return Created($"/api/employees/{emp.Id}", EmployeeDto.From(emp));
    }

    [HttpPatch("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, EmployeeUpdate r)
    {
        var isAdmin = User.IsInRole(Roles.Admin);
        if (!isAdmin && id != UserId) return Forbid();

        var emp = await db.Employees.FindAsync(id);
        if (emp == null) return Fail("Không tìm thấy nhân viên.", 404);
        var name = r.Name ?? emp.Name;
        var username = (r.Username ?? emp.Username).Trim().ToLowerInvariant();
        var email = (r.Email ?? emp.Email).Trim().ToLowerInvariant();
        var err = Validators.Employee(name, username, email, string.IsNullOrEmpty(r.Password) ? null : r.Password);
        if (err != null) return Fail(err);

        var role = isAdmin ? (r.Role ?? emp.Role).ToLowerInvariant() : emp.Role;
        if (!Roles.IsValid(role)) return Fail("Vai trò không hợp lệ.");
        var active = isAdmin ? (r.Active ?? emp.Active) : emp.Active;
        if (isAdmin && id == UserId && (!active || role != Roles.Admin)) return Fail("Không được khóa hoặc hạ quyền chính mình.", 409);
        if (await db.Employees.AnyAsync(e => e.Id != id && (e.Username == username || e.Email == email)))
            return Fail("Email hoặc tên đăng nhập đã tồn tại.", 409);

        emp.Name = name.Trim(); emp.Username = username; emp.Email = email; emp.Role = role; emp.Active = active;
        if (isAdmin && r.Department != null) emp.Department = r.Department.Trim();
        if (!string.IsNullOrEmpty(r.Password)) emp.PasswordHash = BCrypt.Net.BCrypt.HashPassword(r.Password);
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException) { return Fail("Email hoặc tên đăng nhập đã tồn tại.", 409); }
        return Ok(EmployeeDto.From(emp));
    }

    [HttpDelete("{id:guid}"), Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Delete(Guid id)
    {
        if (id == UserId) return Fail("Không thể xóa tài khoản đang đăng nhập.", 409);
        var emp = await db.Employees.FindAsync(id);
        if (emp == null) return Fail("Không tìm thấy nhân viên.", 404);
        if (await db.Attendance.AnyAsync(a => a.EmployeeId == id) || await db.WorkRequests.AnyAsync(r => r.EmployeeId == id))
            return Fail("Nhân viên đã có lịch sử. Hãy khóa tài khoản để giữ dữ liệu.", 409);
        db.Employees.Remove(emp);
        await db.SaveChangesAsync();
        return NoContent();
    }

    [HttpPut("{id:guid}/shift"), Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> AssignShift(Guid id, AssignShift r)
    {
        var emp = await db.Employees.FindAsync(id);
        if (emp == null) return Fail("Không tìm thấy nhân viên.", 404);
        if (r.ShiftId != null && !await db.Shifts.AnyAsync(s => s.Id == r.ShiftId)) return Fail("Ca làm không tồn tại.");
        emp.ShiftId = r.ShiftId;
        await db.SaveChangesAsync();
        return Ok(EmployeeDto.From(emp));
    }
}

[ApiController, Route("api/shifts"), Authorize]
public class ShiftsController(AppDb db) : ApiBase
{
    [HttpGet]
    public async Task<IActionResult> List() =>
        Ok(await db.Shifts.OrderBy(s => s.StartMinute).Select(s => ShiftDto.From(s)).ToListAsync());

    private static string? Check(ShiftUpsert r) =>
        string.IsNullOrWhiteSpace(r.Name) || r.StartMinute is < 0 or >= 1440 || r.EndMinute is < 0 or >= 1440 ||
        r.StartMinute == r.EndMinute || r.Grace is < 0 or > 60
            ? "Ca phải có tên, giờ vào/ra khác nhau và dung sai từ 0–60 phút."
            : null;

    [HttpPost, Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Create(ShiftUpsert r)
    {
        var err = Check(r);
        if (err != null) return Fail(err);
        var s = new Shift { Name = r.Name.Trim(), StartMinute = r.StartMinute, EndMinute = r.EndMinute, Grace = r.Grace };
        db.Shifts.Add(s);
        await db.SaveChangesAsync();
        return Created($"/api/shifts/{s.Id}", ShiftDto.From(s));
    }

    [HttpPatch("{id:guid}"), Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Update(Guid id, ShiftUpsert r)
    {
        var err = Check(r);
        if (err != null) return Fail(err);
        var s = await db.Shifts.FindAsync(id);
        if (s == null) return Fail("Không tìm thấy ca.", 404);
        s.Name = r.Name.Trim(); s.StartMinute = r.StartMinute; s.EndMinute = r.EndMinute; s.Grace = r.Grace;
        await db.SaveChangesAsync();
        return Ok(ShiftDto.From(s));
    }

    [HttpDelete("{id:guid}"), Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Delete(Guid id, [FromQuery] bool force = false)
    {
        var s = await db.Shifts.FindAsync(id);
        if (s == null) return Fail("Không tìm thấy ca.", 404);
        var assigned = await db.Employees.Where(e => e.ShiftId == id).ToListAsync();
        if (assigned.Count > 0)
        {
            if (!force)
            {
                var names = string.Join(", ", assigned.Take(3).Select(e => e.Name));
                var extra = assigned.Count > 3 ? $" và {assigned.Count - 3} người khác" : "";
                return Fail($"Ca đang được phân công cho {assigned.Count} nhân viên ({names}{extra}). Hãy bỏ phân công trước khi xóa.", 409);
            }
            foreach (var e in assigned) e.ShiftId = null;
        }
        db.Shifts.Remove(s);
        await db.SaveChangesAsync();
        return NoContent();
    }
}

[ApiController, Route("api/departments"), Authorize]
public class DepartmentsController(AppDb db) : ApiBase
{
    [HttpGet]
    public async Task<IActionResult> List() =>
        Ok(await db.Departments.OrderBy(d => d.Name).Select(d => DepartmentDto.From(d)).ToListAsync());

    [HttpPost, Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Create(DepartmentUpsert r)
    {
        var name = (r.Name ?? "").Trim();
        if (string.IsNullOrWhiteSpace(name)) return Fail("Tên phòng ban không được để trống.");
        if (await db.Departments.AnyAsync(d => d.Name.ToLower() == name.ToLower()))
            return Fail("Phòng ban này đã tồn tại.", 409);
        var d = new Department { Name = name, Description = r.Description?.Trim() };
        db.Departments.Add(d);
        await db.SaveChangesAsync();
        return Created($"/api/departments/{d.Id}", DepartmentDto.From(d));
    }

    [HttpPatch("{id:guid}"), Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Update(Guid id, DepartmentUpsert r)
    {
        var name = (r.Name ?? "").Trim();
        if (string.IsNullOrWhiteSpace(name)) return Fail("Tên phòng ban không được để trống.");
        var d = await db.Departments.FindAsync(id);
        if (d == null) return Fail("Không tìm thấy phòng ban.", 404);
        if (await db.Departments.AnyAsync(x => x.Id != id && x.Name.ToLower() == name.ToLower()))
            return Fail("Tên phòng ban đã trùng với phòng ban khác.", 409);

        var oldName = d.Name;
        d.Name = name;
        d.Description = r.Description?.Trim();

        if (oldName != name)
        {
            var emps = await db.Employees.Where(e => e.Department == oldName).ToListAsync();
            foreach (var e in emps) e.Department = name;
        }

        await db.SaveChangesAsync();
        return Ok(DepartmentDto.From(d));
    }

    [HttpDelete("{id:guid}"), Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Delete(Guid id)
    {
        var d = await db.Departments.FindAsync(id);
        if (d == null) return Fail("Không tìm thấy phòng ban.", 404);
        if (await db.Employees.AnyAsync(e => e.Department == d.Name))
            return Fail($"Phòng ban '{d.Name}' đang có nhân viên trực thuộc. Hãy chuyển phòng ban cho nhân viên trước khi xóa.", 409);
        db.Departments.Remove(d);
        await db.SaveChangesAsync();
        return NoContent();
    }
}

[ApiController, Route("api/office"), Authorize]
public class OfficeController(AppDb db, QrService qr) : ApiBase
{
    private async Task<Office> GetOfficeAsync()
    {
        var o = await db.Offices.FindAsync(1);
        if (o != null) return o;
        o = new Office { QrSecret = QrService.NewSecret() };
        db.Offices.Add(o);
        await db.SaveChangesAsync();
        return o;
    }

    [HttpGet]
    public async Task<IActionResult> Get() => Ok(OfficeDto.From(await GetOfficeAsync()));

    [HttpPut, Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Update(OfficeUpdate r)
    {
        if (string.IsNullOrWhiteSpace(r.Name) || !double.IsFinite(r.Latitude) || !double.IsFinite(r.Longitude) ||
            Math.Abs(r.Latitude) > 90 || Math.Abs(r.Longitude) > 180 || !double.IsFinite(r.Radius) ||
            r.Radius is < 20 or > 5000)
            return Fail("Nhập tọa độ hợp lệ và bán kính 20–5000 mét.");
        var o = await GetOfficeAsync();
        o.Name = r.Name.Trim(); o.Latitude = r.Latitude; o.Longitude = r.Longitude; o.Radius = r.Radius;
        if (o.QrSecret.Length == 0) o.QrSecret = QrService.NewSecret();
        await db.SaveChangesAsync();
        return Ok(OfficeDto.From(o));
    }

    [HttpPost("qr"), Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> CreateQr()
    {
        var o = await GetOfficeAsync();
        if (!o.Configured) return Fail("Chưa cấu hình văn phòng.", 409);
        return Ok(qr.Create(o.QrSecret, DateTime.UtcNow));
    }
}

[ApiController, Route("api/attendance"), Authorize]
public class AttendanceController(AppDb db, QrService qr) : ApiBase
{
    private static AttendanceDto ToDto(Attendance a, string? name) => new(a.Id, a.EmployeeId, name, a.ShiftName,
        a.WorkDate, a.CheckIn, a.ScheduledEnd, a.LateMinutes, a.Latitude, a.Longitude, a.Accuracy, a.CheckOut,
        a.OutLatitude, a.OutLongitude);

    private string? ValidatePunch(PunchRequest r, Office o, DateTime now)
    {
        if (!o.Configured) return "Admin chưa cấu hình văn phòng.";
        if (string.IsNullOrWhiteSpace(r.IdempotencyKey) || r.IdempotencyKey.Length > 100) return "Thiếu mã yêu cầu (idempotencyKey).";
        if (!qr.IsValid(o.QrSecret, r.Qr, now)) return "QR sai hoặc hết hạn. Quét mã mới từ Admin.";
        var captured = r.CapturedAt.ToUniversalTime();
        if (r.IsMocked || !double.IsFinite(r.Accuracy) || r.Accuracy < 0 || r.Accuracy > 80 ||
            !double.IsFinite(r.Latitude) || Math.Abs(r.Latitude) > 90 ||
            !double.IsFinite(r.Longitude) || Math.Abs(r.Longitude) > 180 ||
            (now - captured).TotalSeconds > 60 || captured > now.AddSeconds(5))
            return "Vị trí không hợp lệ hoặc độ chính xác kém. Hãy lấy GPS mới, tắt vị trí giả.";
        var distance = GeoService.DistanceMeters(r.Latitude, r.Longitude, o.Latitude!.Value, o.Longitude!.Value);
        return distance > o.Radius
            ? $"Bạn cách văn phòng {Math.Round(distance)} m, ngoài bán kính {Math.Round(o.Radius)} m."
            : null;
    }

    private async Task<Office?> OfficeAsync() => await db.Offices.FindAsync(1);

    [HttpPost("check-in")]
    public async Task<IActionResult> CheckIn(PunchRequest r)
    {
        var uid = UserId;
        var emp = await db.Employees.FindAsync(uid);
        if (emp == null || !emp.Active) return Fail("Vui lòng đăng nhập lại.", 401);

        var existing = await db.Attendance.FirstOrDefaultAsync(a => a.EmployeeId == uid && a.IdempotencyKey == r.IdempotencyKey);
        if (existing != null) return Ok(ToDto(existing, emp.Name));

        var now = DateTime.UtcNow;
        var office = await OfficeAsync() ?? new Office();
        var error = ValidatePunch(r, office, now);
        if (error != null) return Fail(error);

        if (await db.Attendance.AnyAsync(a => a.EmployeeId == uid && a.CheckOut == null))
            return Fail("Bạn đang trong ca. Hãy chấm công ra trước.", 409);
        var shift = emp.ShiftId == null ? null : await db.Shifts.FindAsync(emp.ShiftId);
        if (shift == null) return Fail("Bạn chưa được phân ca. Liên hệ Admin.", 409);

        var local = TimeVn.ToLocal(now);
        var overnight = shift.EndMinute < shift.StartMinute;
        var anchor = (overnight && local.Hour * 60 + local.Minute < shift.EndMinute ? local.AddDays(-1) : local).Date;
        var start = anchor.AddMinutes(shift.StartMinute);
        var end = anchor.AddMinutes(shift.EndMinute + (shift.EndMinute <= shift.StartMinute ? 1440 : 0));
        if (local >= end) return Fail("Ca đã kết thúc. Không thể chấm vào; hãy gửi đơn giải trình.", 409);
        var workDate = TimeVn.DayKey(end);

        if (await db.Attendance.AnyAsync(a => a.EmployeeId == uid && a.WorkDate == workDate))
            return Fail("Bạn đã hoàn tất ca của ngày này.", 409);
        var day = DateOnly.FromDateTime(anchor);
        if (await db.WorkRequests.AnyAsync(w => w.EmployeeId == uid && w.Type == RequestTypes.Leave &&
                w.Status == RequestStatus.Approved && w.From <= day && w.To >= day))
            return Fail("Ngày này đã được duyệt nghỉ phép. Liên hệ Admin nếu lịch thay đổi.", 409);

        var late = (int)Math.Max(0, Math.Floor((local - start).TotalMinutes) - shift.Grace);
        var a = new Attendance
        {
            EmployeeId = uid, ShiftName = shift.Name, WorkDate = workDate, CheckIn = now,
            ScheduledEnd = TimeVn.ToUtc(end), LateMinutes = late, Latitude = r.Latitude, Longitude = r.Longitude,
            Accuracy = r.Accuracy, IdempotencyKey = r.IdempotencyKey
        };
        db.Attendance.Add(a);
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException) { return Fail("Yêu cầu chấm công trùng lặp. Hãy tải lại trạng thái.", 409); }
        return Created($"/api/attendance/{a.Id}", ToDto(a, emp.Name));
    }

    [HttpPost("check-out")]
    public async Task<IActionResult> CheckOut(PunchRequest r)
    {
        var uid = UserId;
        var emp = await db.Employees.FindAsync(uid);
        if (emp == null || !emp.Active) return Fail("Vui lòng đăng nhập lại.", 401);

        var done = await db.Attendance.FirstOrDefaultAsync(a => a.EmployeeId == uid && a.CheckOutIdempotencyKey == r.IdempotencyKey);
        if (done != null) return Ok(ToDto(done, emp.Name));

        var now = DateTime.UtcNow;
        var office = await OfficeAsync() ?? new Office();
        var error = ValidatePunch(r, office, now);
        if (error != null) return Fail(error);

        var open = await db.Attendance.FirstOrDefaultAsync(a => a.EmployeeId == uid && a.CheckOut == null);
        if (open == null) return Fail("Bạn chưa chấm công vào.", 409);
        if (now < open.CheckIn) return Fail("Giờ thiết bị không hợp lệ.");
        open.CheckOut = now;
        open.OutLatitude = r.Latitude;
        open.OutLongitude = r.Longitude;
        open.CheckOutIdempotencyKey = r.IdempotencyKey;
        await db.SaveChangesAsync();
        return Ok(ToDto(open, emp.Name));
    }

    [HttpGet]
    public async Task<IActionResult> List(DateOnly? from, DateOnly? to, Guid? employeeId, int page = 1, int pageSize = 50)
    {
        if (from != null && to != null && from > to) return Fail("Ngày kết thúc phải từ ngày bắt đầu trở đi.");
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 100);
        var isStaff = User.IsInRole(Roles.Admin) || User.IsInRole(Roles.Manager);
        var scope = isStaff ? employeeId : UserId;

        var q = db.Attendance.AsQueryable();
        if (scope != null) q = q.Where(a => a.EmployeeId == scope);
        if (from != null) q = q.Where(a => a.CheckIn >= TimeVn.ToUtc(from.Value.ToDateTime(TimeOnly.MinValue)));
        if (to != null) q = q.Where(a => a.CheckIn < TimeVn.ToUtc(to.Value.AddDays(1).ToDateTime(TimeOnly.MinValue)));

        var total = await q.CountAsync();
        var rows = await q.OrderByDescending(a => a.CheckIn).ThenByDescending(a => a.Id).Skip((page - 1) * pageSize).Take(pageSize)
            .Join(db.Employees, a => a.EmployeeId, e => e.Id, (a, e) => new { a, e.Name }).ToListAsync();
        return Ok(new PagedResult<AttendanceDto>(total, page, pageSize, rows.Select(x => ToDto(x.a, x.Name)).ToList()));
    }
}

[ApiController, Route("api/requests"), Authorize]
public class RequestsController(AppDb db) : ApiBase
{
    private static WorkRequestDto ToDto(WorkRequest r, string? name) => new(r.Id, r.EmployeeId, name, r.Type,
        r.Reason, r.From, r.To, r.Status, r.ReviewerNote, r.CreatedAt, r.Version);

    private static string? Check(RequestUpsert r) =>
        !RequestTypes.All.Contains(r.Type) || (r.Reason ?? "").Trim().Length < 10 || r.To < r.From
            ? "Loại đơn hợp lệ, lý do ít nhất 10 ký tự, ngày kết thúc không trước ngày bắt đầu."
            : null;

    [HttpGet]
    public async Task<IActionResult> List(string? status)
    {
        var q = db.WorkRequests.AsQueryable();
        if (!User.IsInRole(Roles.Admin) && !User.IsInRole(Roles.Manager)) q = q.Where(r => r.EmployeeId == UserId);
        if (!string.IsNullOrEmpty(status)) q = q.Where(r => r.Status == status);
        var rows = await q.OrderByDescending(r => r.CreatedAt)
            .Join(db.Employees, r => r.EmployeeId, e => e.Id, (r, e) => new { r, e.Name }).ToListAsync();
        return Ok(rows.Select(x => ToDto(x.r, x.Name)));
    }

    private Task<bool> OverlapsLeave(Guid uid, RequestUpsert r, Guid? ignore) =>
        r.Type != RequestTypes.Leave
            ? Task.FromResult(false)
            : db.WorkRequests.AnyAsync(e => e.Id != ignore && e.EmployeeId == uid && e.Type == r.Type &&
                                            e.Status != RequestStatus.Rejected && e.To >= r.From && e.From <= r.To);

    [HttpPost]
    public async Task<IActionResult> Create(RequestUpsert r)
    {
        var err = Check(r);
        if (err != null) return Fail(err);
        var uid = UserId;
        if (await OverlapsLeave(uid, r, null)) return Fail("Khoảng ngày trùng với một đơn nghỉ phép hiện có.", 409);
        var w = new WorkRequest { EmployeeId = uid, Type = r.Type, Reason = r.Reason.Trim(), From = r.From, To = r.To };
        db.WorkRequests.Add(w);
        await db.SaveChangesAsync();
        return Created($"/api/requests/{w.Id}", ToDto(w, null));
    }

    [HttpPatch("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, RequestUpsert r)
    {
        var err = Check(r);
        if (err != null) return Fail(err);
        var w = await db.WorkRequests.FindAsync(id);
        if (w == null) return Fail("Không tìm thấy đơn.", 404);
        if (w.EmployeeId != UserId || w.Status != RequestStatus.Pending)
            return Fail("Chỉ được sửa đơn của mình đang chờ duyệt.", 403);
        if (await OverlapsLeave(w.EmployeeId, r, id)) return Fail("Khoảng ngày trùng với một đơn nghỉ phép hiện có.", 409);
        w.Type = r.Type; w.Reason = r.Reason.Trim(); w.From = r.From; w.To = r.To;
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateConcurrencyException) { return Fail("Đơn vừa được xử lý. Hãy tải lại.", 409); }
        return Ok(ToDto(w, null));
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        var w = await db.WorkRequests.FindAsync(id);
        if (w == null) return Fail("Không tìm thấy đơn.", 404);
        if (w.EmployeeId != UserId || w.Status != RequestStatus.Pending)
            return Fail("Chỉ được xóa đơn của mình đang chờ duyệt.", 403);
        db.WorkRequests.Remove(w);
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateConcurrencyException) { return Fail("Đơn vừa được xử lý. Hãy tải lại.", 409); }
        return NoContent();
    }

    [HttpPost("{id:guid}/review"), Authorize(Roles = Roles.AdminOrManager)]
    public async Task<IActionResult> Review(Guid id, ReviewRequest r)
    {
        if (string.IsNullOrWhiteSpace(r.Note)) return Fail("Nhập nhận xét khi duyệt hoặc từ chối.");
        var w = await db.WorkRequests.FindAsync(id);
        if (w == null) return Fail("Không tìm thấy đơn.", 404);
        if (w.EmployeeId == UserId || w.Status != RequestStatus.Pending)
            return Fail("Không được duyệt đơn của mình hoặc đơn đã xử lý.", 409);
        if (r.Version != null) db.Entry(w).Property(x => x.Version).OriginalValue = r.Version.Value;
        w.Status = r.Approve ? RequestStatus.Approved : RequestStatus.Rejected;
        w.ReviewerNote = r.Note.Trim();
        w.ReviewedBy = UserId;
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateConcurrencyException) { return Fail("Đơn vừa được thay đổi. Hãy tải lại.", 409); }
        return Ok(ToDto(w, null));
    }
}
