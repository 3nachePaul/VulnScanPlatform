using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace VulnScanPlatform.Models
{
    public class ApplicationDbContext : IdentityDbContext<User>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<Application> Applications { get; set; }
        public DbSet<ApplicationCollaborator> ApplicationCollaborators { get; set; }
        public DbSet<Scan> Scans { get; set; }
        public DbSet<Vulnerability> Vulnerabilities { get; set; }
        public DbSet<Report> Reports { get; set; }
        public DbSet<ReportInvitation> ReportInvitations { get; set; }
        public DbSet<ChatMessage> ChatMessages { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // User configuration
            builder.Entity<User>(entity =>
            {
                entity.Property(e => e.FirstName).IsRequired().HasMaxLength(50);
                entity.Property(e => e.LastName).IsRequired().HasMaxLength(50);
                entity.Property(e => e.Role).HasConversion<int>();
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.HasIndex(e => e.Role);
                entity.HasIndex(e => e.IsActive);
            });

            // Application configuration
            builder.Entity<Application>(entity =>
            {
                entity.HasOne(a => a.User)
                    .WithMany()
                    .HasForeignKey(a => a.UserId)
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasIndex(a => a.UserId);
                entity.HasIndex(a => a.IsActive);
            });

            // ApplicationCollaborator configuration
            builder.Entity<ApplicationCollaborator>(entity =>
            {
                entity.HasOne(ac => ac.Application)
                    .WithMany(a => a.Collaborators)
                    .HasForeignKey(ac => ac.ApplicationId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(ac => ac.User)
                    .WithMany()
                    .HasForeignKey(ac => ac.UserId)
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasIndex(ac => new { ac.ApplicationId, ac.UserId }).IsUnique();
            });

            // Scan configuration
            builder.Entity<Scan>(entity =>
            {
                entity.HasOne(s => s.Application)
                    .WithMany(a => a.Scans)
                    .HasForeignKey(s => s.ApplicationId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(s => s.StartedBy)
                    .WithMany()
                    .HasForeignKey(s => s.StartedByUserId)
                    .OnDelete(DeleteBehavior.Restrict)
                    .IsRequired(false);


                entity.HasIndex(s => s.Status);
            });

            // Vulnerability configuration
            builder.Entity<Vulnerability>(entity =>
            {
                entity.HasOne(v => v.Scan)
                    .WithMany(s => s.Vulnerabilities)
                    .HasForeignKey(v => v.ScanId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasIndex(v => v.Severity);
                entity.HasIndex(v => v.Status);
            });

            // Report configuration
            builder.Entity<Report>(entity =>
            {
                entity.HasOne(r => r.CreatedBy)
                    .WithMany()
                    .HasForeignKey(r => r.CreatedByUserId)
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasIndex(r => r.CreatedByUserId);

                entity.HasOne(r => r.Scan)
                    .WithOne(s => s.Report)
                    .HasForeignKey<Report>(r => r.ScanId)
                    .IsRequired(false)
                    .OnDelete(DeleteBehavior.SetNull);
            });

            // ReportInvitation configuration
            builder.Entity<ReportInvitation>(entity =>
            {
                entity.HasOne(ri => ri.Report)
                    .WithMany(r => r.Invitations)
                    .HasForeignKey(ri => ri.ReportId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(ri => ri.InvitedUser)
                    .WithMany()
                    .HasForeignKey(ri => ri.InvitedUserId)
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasOne(ri => ri.InvitedBy)
                    .WithMany()
                    .HasForeignKey(ri => ri.InvitedByUserId)
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasIndex(ri => new { ri.ReportId, ri.InvitedUserEmail }).IsUnique();
            });

            // ChatMessage configuration
            builder.Entity<ChatMessage>(entity =>
            {
                entity.HasOne(cm => cm.Report)
                    .WithMany(r => r.ChatMessages)
                    .HasForeignKey(cm => cm.ReportId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(cm => cm.User)
                    .WithMany()
                    .HasForeignKey(cm => cm.UserId)
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasIndex(cm => cm.CreatedAt);
            });
        }
    }
}