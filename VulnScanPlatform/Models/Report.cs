namespace VulnScanPlatform.Models
{
    public partial class Report
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string Content { get; set; }
        public string CreatedByUserId { get; set; }
        public DateTime CreatedAt { get; set; }
        public User CreatedBy { get; set; }
        public List<ReportInvitation> Invitations { get; set; } = new();
        public List<ChatMessage> ChatMessages { get; set; } = new();
    }

    public class ReportInvitation
    {
        public int Id { get; set; }
        public int ReportId { get; set; }
        public string InvitedUserEmail { get; set; }
        public string InvitedUserId { get; set; }
        public string InvitedByUserId { get; set; }
        public bool IsAccepted { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? AcceptedAt { get; set; }
        public User InvitedUser { get; set; }
        public User InvitedBy { get; set; }
        public Report Report { get; set; }
    }

    public class ChatMessage
    {
        public int Id { get; set; }
        public int ReportId { get; set; }
        public string UserId { get; set; }
        public string Message { get; set; }
        public DateTime CreatedAt { get; set; }
        public User User { get; set; }
        public Report Report { get; set; }
    }

    public partial class Report
    {
        public int? ScanId { get; set; }
        public Scan Scan { get; set; }
    }
}
