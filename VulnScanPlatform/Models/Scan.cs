using System.ComponentModel.DataAnnotations;

namespace VulnScanPlatform.Models
{
    public class Scan
    {
        public int Id { get; set; }

        [Required]
        public int ApplicationId { get; set; }

        public ScanType Type { get; set; } = ScanType.Full;

        public ScanStatus Status { get; set; } = ScanStatus.Pending;

        [StringLength(500)]
        public string Configuration { get; set; }

        public DateTime StartedAt { get; set; } = DateTime.UtcNow;

        public DateTime? CompletedAt { get; set; }

        [Required]
        public string StartedByUserId { get; set; }

        // File upload info
        public string FileName { get; set; }
        public string FilePath { get; set; }
        public long FileSize { get; set; }
        public string FileContent { get; set; } // Store HTML content

        // Navigation properties
        public Application Application { get; set; }
        public User StartedBy { get; set; }
        public List<Vulnerability> Vulnerabilities { get; set; } = new();
        public Report Report { get; set; }
    }

    public enum ScanType
    {
        Quick,
        Full,
        Manual,
        Custom
    }

    public enum ScanStatus
    {
        Pending,
        InProgress,
        Completed,
        Failed,
        Cancelled
    }
}