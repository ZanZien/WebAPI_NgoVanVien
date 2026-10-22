using System.Net.Http.Json;

namespace WebAPI_TongNhatBaoAn.Services;

public sealed class OtpDeliveryException : Exception
{
    public const string PublicMessage = "Chưa gửi được email OTP. Vui lòng thử lại sau hoặc liên hệ quản trị viên.";
    public OtpDeliveryException() : base(PublicMessage) { }
}

// Brevo REST API uses HTTPS (443), not the SMTP ports blocked by Render Free.
public sealed class OtpEmailSender(HttpClient client, IConfiguration cfg, ILogger<OtpEmailSender> log)
{
    public async Task SendAsync(string to, string subject, string code)
    {
        var key = cfg["Brevo:ApiKey"];
        var from = cfg["Email:From"];
        if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(from))
        {
            log.LogError("OTP email configuration missing: set Brevo__ApiKey and Email__From.");
            throw new OtpDeliveryException();
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.brevo.com/v3/smtp/email");
        request.Headers.Add("api-key", key);
        request.Content = JsonContent.Create(new
        {
            sender = new { email = from, name = cfg["Email:FromName"] ?? "Chấm công - Tống Nhật Bảo An" },
            to = new[] { new { email = to } },
            subject,
            textContent = $"Mã xác thực của bạn là {code}. Mã có hiệu lực {cfg["Auth:OtpMinutes"] ?? "5"} phút. Không chia sẻ mã cho người khác."
        });
        try
        {
            // No automatic retry: a timeout may happen after the provider accepted the email.
            using var response = await client.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                // Do not log request/response bodies: they may contain OTPs or personal data.
                log.LogError("Brevo rejected OTP email: HTTP {Status}. Check API key, verified sender, account activation and quota in Brevo.", (int)response.StatusCode);
                throw new OtpDeliveryException();
            }
            log.LogInformation("OTP email accepted by Brevo.");
        }
        catch (OperationCanceledException)
        {
            log.LogWarning("Brevo OTP HTTPS request timed out.");
            throw new OtpDeliveryException();
        }
        catch (HttpRequestException ex)
        {
            log.LogWarning("Brevo OTP HTTPS connection failed ({Error}).", ex.HttpRequestError);
            throw new OtpDeliveryException();
        }
    }
}
