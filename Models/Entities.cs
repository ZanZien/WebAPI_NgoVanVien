namespace WebAPI_TongNhatBaoAn.Models;

public class Employee
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public string Email { get; set; } = "";
    public string Username { get; set; } = "";
    public string Department { get; set; } = "";
    public string Role { get; set; } = Roles.Employee;
    public string PasswordHash { get; set; } = "";
    public Guid? ShiftId { get; set; }
    public bool Active { get; set; } = true;
    public bool EmailVerified { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public static class Roles
{
    public const string Admin = "admin";
    public const string Manager = "manager";
    public const string Employee = "employee";
    public const string AdminOrManager = Admin + "," + Manager;
    public static bool IsValid(string role) => role is Admin or Manager or Employee;
}

public class Shift
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public int StartMinute { get; set; }
    public int EndMinute { get; set; }
    public int Grace { get; set; } = 5;
}

public class Department
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public class Office
{
    public int Id { get; set; } = 1;
    public string Name { get; set; } = "Văn phòng";
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public double Radius { get; set; } = 150;
    public string QrSecret { get; set; } = "";
    public bool Configured => Latitude != null && Longitude != null && QrSecret.Length > 0;
}

public class Attendance
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid EmployeeId { get; set; }
    public string ShiftName { get; set; } = "";
    public string WorkDate { get; set; } = "";
    public DateTime CheckIn { get; set; }
    public DateTime ScheduledEnd { get; set; }
    public int LateMinutes { get; set; }
    public double Latitude { get; set; }
    public double Longitude { get; set; }
    public double Accuracy { get; set; }
    public DateTime? CheckOut { get; set; }
    public double? OutLatitude { get; set; }
    public double? OutLongitude { get; set; }
    public string IdempotencyKey { get; set; } = "";
    public string? CheckOutIdempotencyKey { get; set; }
}

public class WorkRequest
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid EmployeeId { get; set; }
    public string Type { get; set; } = "";
    public string Reason { get; set; } = "";
    public DateOnly From { get; set; }
    public DateOnly To { get; set; }
    public string Status { get; set; } = RequestStatus.Pending;
    public string ReviewerNote { get; set; } = "";
    public Guid? ReviewedBy { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public uint Version { get; set; }
}

public static class RequestStatus
{
    public const string Pending = "pending";
    public const string Approved = "approved";
    public const string Rejected = "rejected";
}

public static class RequestTypes
{
    public const string Leave = "Nghỉ phép";
    public const string Explain = "Giải trình chấm công";
    public static readonly string[] All = [Leave, Explain];
}

public class OtpChallenge
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid EmployeeId { get; set; }
    public string Purpose { get; set; } = "";
    public string CodeHash { get; set; } = "";
    public DateTime ExpiresAt { get; set; }
    public int Attempts { get; set; }
    public bool Consumed { get; set; }
    public uint Version { get; set; }
}

public class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid EmployeeId { get; set; }
    public string TokenHash { get; set; } = "";
    public DateTime ExpiresAt { get; set; }
    public bool Revoked { get; set; }
}
