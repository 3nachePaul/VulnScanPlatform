using System;
using System.ComponentModel.DataAnnotations;

namespace VulnScanPlatform.Models
{
    public class Application
    {
        public int Id { get; set; }

        [Required]
        [StringLength(200)]
        public string Name { get; set; }

        [StringLength(500)]
        public string Description { get; set; }

        public ApplicationType Type { get; set; } = ApplicationType.WebApplication;

        [Required]
        public string UserId { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public bool IsActive { get; set; } = true;

        // Navigation properties
        public User User { get; set; }
        public List<Scan> Scans { get; set; } = new();
        public List<ApplicationCollaborator> Collaborators { get; set; } = new();
    }

    public enum ApplicationType
    {
        WebApplication,
        API,
        MobileBackend,
        Other
    }

    public class ApplicationCollaborator
    {
        public int Id { get; set; }
        public int ApplicationId { get; set; }
        public string UserId { get; set; }
        public DateTime AddedAt { get; set; } = DateTime.UtcNow;

        public Application Application { get; set; }
        public User User { get; set; }
    }
}