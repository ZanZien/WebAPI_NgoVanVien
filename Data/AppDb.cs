using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using WebAPI_TongNhatBaoAn.Models;

namespace WebAPI_TongNhatBaoAn.Data;

public class AppDb(DbContextOptions<AppDb> options) : DbContext(options)
{
    public DbSet<Employee> Employees => Set<Employee>();
    public DbSet<Shift> Shifts => Set<Shift>();
    public DbSet<Department> Departments => Set<Department>();
    public DbSet<Office> Offices => Set<Office>();
    public DbSet<Attendance> Attendance => Set<Attendance>();
    public DbSet<WorkRequest> WorkRequests => Set<WorkRequest>();
    public DbSet<OtpChallenge> OtpChallenges => Set<OtpChallenge>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Employee>(e =>
        {
            e.HasIndex(x => x.Username).IsUnique();
            e.HasIndex(x => x.Email).IsUnique();
            e.HasOne<Shift>().WithMany().HasForeignKey(x => x.ShiftId).OnDelete(DeleteBehavior.Restrict);
        });

        b.Entity<Office>(e => e.Ignore(x => x.Configured));

        b.Entity<Attendance>(e =>
        {
            e.HasOne<Employee>().WithMany().HasForeignKey(x => x.EmployeeId).OnDelete(DeleteBehavior.Restrict);
            e.HasIndex(x => new { x.EmployeeId, x.WorkDate }).IsUnique();
            e.HasIndex(x => new { x.EmployeeId, x.IdempotencyKey }).IsUnique();
            e.HasIndex(x => x.EmployeeId).IsUnique().HasFilter("\"CheckOut\" IS NULL").HasDatabaseName("UX_Attendance_OpenPerEmployee");
            e.HasIndex(x => x.CheckIn);
        });

        b.Entity<WorkRequest>(e =>
        {
            e.HasOne<Employee>().WithMany().HasForeignKey(x => x.EmployeeId).OnDelete(DeleteBehavior.Restrict);
            e.Property(x => x.Version).IsRowVersion();
        });

        b.Entity<OtpChallenge>(e =>
        {
            e.HasOne<Employee>().WithMany().HasForeignKey(x => x.EmployeeId).OnDelete(DeleteBehavior.Cascade);
            e.Property(x => x.Version).IsRowVersion();
        });

        b.Entity<RefreshToken>(e =>
        {
            e.HasOne<Employee>().WithMany().HasForeignKey(x => x.EmployeeId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => x.TokenHash).IsUnique();
        });
    }
}

public class DesignTimeFactory : IDesignTimeDbContextFactory<AppDb>
{
    public AppDb CreateDbContext(string[] args) => new(
        new DbContextOptionsBuilder<AppDb>()
            .UseNpgsql("Host=localhost;Database=design_time_only;Username=design;Password=design")
            .Options);
}
