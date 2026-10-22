# WebAPI_TongNhatBaoAn

ASP.NET Core 10 Web API + PostgreSQL cho app chấm công. Cả nhóm dùng chung API này.

## Cấu trúc
```
WebAPI_TongNhatBaoAn/
├── Controllers/   Auth, Me, Employees, Shifts, Office, Attendance, Requests
├── Models/        Entity (Employee, Shift, Office, Attendance, WorkRequest, OtpChallenge, RefreshToken)
├── Dtos/          Request/Response (không bao giờ trả passwordHash hay QR secret)
├── Services/      JWT, OTP + Brevo HTTPS, QR ký HMAC, GPS, múi giờ VN, Validators
├── Data/          AppDb (EF Core) + Migrations
├── Program.cs     Cấu hình, health check, swagger, migrate + seed admin
└── Dockerfile     Đóng gói để deploy (Render/Koyeb/Railway)
```

## Biến môi trường (KHÔNG commit giá trị thật)
| Biến | Ý nghĩa |
|---|---|
| `ConnectionStrings__Default` | Chuỗi kết nối PostgreSQL (dạng Npgsql hoặc `postgresql://...`) |
| `Jwt__Key` | Chuỗi bí mật >= 32 ký tự, **giống nhau** ở mọi server |
| `RUN_MIGRATIONS` | `true` chỉ ở **server chính** (migrate DB + seed admin). Server phụ để `false` |
| `Seed__AdminUsername`, `Seed__AdminEmail`, `Seed__AdminPassword` | Tạo admin đầu tiên (mật khẩu >= 8 ký tự) |
| `Brevo__ApiKey`, `Email__From`, `Email__FromName` | Gửi OTP qua Brevo HTTPS API; email người gửi phải được xác minh |
| `Auth__DebugReturnOtp` | `true` chỉ khi test: trả OTP trong response (tắt khi chạy thật) |

## Chạy local
```powershell
cd WebAPI_TongNhatBaoAn
$env:ConnectionStrings__Default = "Host=localhost;Database=AppChamCong_TongNhatBaoAn;Username=postgres;Password=<mat-khau>"
$env:Jwt__Key = "<chuoi-ngau-nhien-it-nhat-32-ky-tu>"
$env:RUN_MIGRATIONS = "true"
$env:Seed__AdminUsername = "admin"; $env:Seed__AdminEmail = "admin@example.com"; $env:Seed__AdminPassword = "<mat-khau-manh>"
$env:Auth__DebugReturnOtp = "true"
dotnet run
```
Mở `http://localhost:5000/swagger` (cổng hiển thị trong log).

## Migration mới
```powershell
dotnet tool restore
dotnet tool run dotnet-ef migrations add TenThayDoi -o Data/Migrations
```

## Endpoint chính
Xem `/swagger`. Đăng nhập 2 bước: `POST /api/auth/login` (trả `challengeId`) → `POST /api/auth/verify-otp` (trả token). Gửi token ở header `Authorization: Bearer <accessToken>`.
Chấm công: `POST /api/attendance/check-in` và `/check-out`, body gồm `qr, latitude, longitude, accuracy, capturedAt (UTC ISO8601), idempotencyKey`.
Sức khỏe: `/health/live`, `/health/ready`.

## Gửi OTP trên Render

Xem [hướng dẫn cấu hình Brevo](../docs/RENDER_EMAIL_OTP.md). Production không trả OTP trực tiếp dù bật DebugReturnOtp.
