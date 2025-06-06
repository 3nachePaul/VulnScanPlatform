
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Pages.Reports
{
    [Authorize]
    public class DetailsModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<User> _userManager;
        private readonly ILogger<DetailsModel> _logger;

        public DetailsModel(
            ApplicationDbContext context,
            UserManager<User> userManager,
            ILogger<DetailsModel> logger)
        {
            _context = context;
            _userManager = userManager;
            _logger = logger;
        }

        public Report Report { get; set; }
        public List<ReportInvitation> Invitations { get; set; }
        public List<ChatMessage> ChatMessages { get; set; }
        public bool IsOwner { get; set; }
        public bool HasAccess { get; set; }
        public bool HasPendingInvitation { get; set; }
        public string CurrentUserId { get; set; }

        public async Task<IActionResult> OnGetAsync(int id)
        {
            CurrentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Load report with all related data
            Report = await _context.Reports
                .Include(r => r.CreatedBy)
                .Include(r => r.Invitations)
                    .ThenInclude(i => i.InvitedUser)
                .Include(r => r.Invitations)
                    .ThenInclude(i => i.InvitedBy)
                .Include(r => r.ChatMessages)
                    .ThenInclude(m => m.User)
                .Include(r => r.Scan)
                    .ThenInclude(s => s.Application)
                .FirstOrDefaultAsync(r => r.Id == id);

            if (Report == null)
            {
                return NotFound();
            }

            IsOwner = Report.CreatedByUserId == CurrentUserId;

            // Check if user has access
            var hasInvitation = await _context.ReportInvitations
                .AnyAsync(i => i.ReportId == id &&
                              i.InvitedUserId == CurrentUserId &&
                              i.IsAccepted);

            HasAccess = IsOwner || hasInvitation;

            if (!HasAccess)
            {
                // Check for pending invitation
                HasPendingInvitation = await _context.ReportInvitations
                    .AnyAsync(i => i.ReportId == id &&
                                  i.InvitedUserEmail == User.FindFirst(ClaimTypes.Email).Value &&
                                  !i.IsAccepted);

                if (!HasPendingInvitation)
                {
                    return Forbid();
                }
            }

            Invitations = Report.Invitations.ToList();
            ChatMessages = Report.ChatMessages.OrderBy(m => m.CreatedAt).ToList();

            return Page();
        }

        public async Task<IActionResult> OnPostInviteAsync(int id, string email)
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Verify user is owner
            var report = await _context.Reports
                .FirstOrDefaultAsync(r => r.Id == id && r.CreatedByUserId == currentUserId);

            if (report == null)
            {
                return Forbid();
            }

            if (string.IsNullOrWhiteSpace(email))
            {
                TempData["ErrorMessage"] = "Vă rugăm să introduceți o adresă de email validă.";
                return RedirectToPage(new { id });
            }

            // Check if user exists
            var invitedUser = await _userManager.FindByEmailAsync(email);
            if (invitedUser == null)
            {
                TempData["ErrorMessage"] = "Nu există un utilizator cu acest email în sistem.";
                return RedirectToPage(new { id });
            }

            // Check if already invited
            var existingInvitation = await _context.ReportInvitations
                .AnyAsync(i => i.ReportId == id && i.InvitedUserEmail == email);

            if (existingInvitation)
            {
                TempData["ErrorMessage"] = "Acest utilizator a fost deja invitat.";
                return RedirectToPage(new { id });
            }

            // Create invitation
            var invitation = new ReportInvitation
            {
                ReportId = id,
                InvitedByUserId = currentUserId,
                InvitedUserEmail = email,
                InvitedUserId = invitedUser.Id,
                CreatedAt = DateTime.UtcNow
            };

            _context.ReportInvitations.Add(invitation);
            await _context.SaveChangesAsync();

            _logger.LogInformation("User {UserId} invited {Email} to report {ReportId}",
                currentUserId, email, id);

            TempData["SuccessMessage"] = $"Invitație trimisă către {email}!";
            return RedirectToPage(new { id });
        }

        public async Task<IActionResult> OnPostSendMessageAsync(int id, string message)
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrWhiteSpace(message))
            {
                return RedirectToPage(new { id });
            }

            // Verify user has access
            var hasAccess = await _context.Reports.AnyAsync(r => r.Id == id && r.CreatedByUserId == currentUserId)
                || await _context.ReportInvitations.AnyAsync(i => i.ReportId == id && i.InvitedUserId == currentUserId && i.IsAccepted);

            if (!hasAccess)
            {
                return Forbid();
            }

            var chatMessage = new ChatMessage
            {
                ReportId = id,
                UserId = currentUserId,
                Message = message.Trim(),
                CreatedAt = DateTime.UtcNow
            };

            _context.ChatMessages.Add(chatMessage);
            await _context.SaveChangesAsync();

            _logger.LogInformation("User {UserId} sent message in report {ReportId}", currentUserId, id);

            return RedirectToPage(new { id });
        }

        public async Task<IActionResult> OnPostAcceptInvitationAsync(int id)
        {
            var currentUserEmail = User.FindFirstValue(ClaimTypes.Email);
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var invitation = await _context.ReportInvitations
                .FirstOrDefaultAsync(i => i.ReportId == id &&
                                         i.InvitedUserEmail == currentUserEmail &&
                                         !i.IsAccepted);

            if (invitation != null)
            {
                invitation.IsAccepted = true;
                invitation.AcceptedAt = DateTime.UtcNow;
                invitation.InvitedUserId = currentUserId;

                await _context.SaveChangesAsync();

                TempData["SuccessMessage"] = "Invitație acceptată! Acum ai acces la acest raport.";
            }

            return RedirectToPage(new { id });
        }

        public async Task<IActionResult> OnPostRemoveCollaboratorAsync(int id, [FromBody] RemoveCollaboratorRequest request)
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Verify user is owner
            var report = await _context.Reports
                .FirstOrDefaultAsync(r => r.Id == id && r.CreatedByUserId == currentUserId);

            if (report == null)
            {
                return new JsonResult(new { success = false, message = "Nu aveți permisiunea." });
            }

            var invitation = await _context.ReportInvitations
                .FirstOrDefaultAsync(i => i.Id == request.InvitationId && i.ReportId == id);

            if (invitation != null)
            {
                _context.ReportInvitations.Remove(invitation);
                await _context.SaveChangesAsync();
                return new JsonResult(new { success = true });
            }

            return new JsonResult(new { success = false, message = "Invitația nu a fost găsită." });
        }

        public async Task<IActionResult> OnGetNewMessagesAsync(int id, int lastMessageId)
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Verify user has access
            var hasAccess = await _context.Reports.AnyAsync(r => r.Id == id && r.CreatedByUserId == currentUserId)
                || await _context.ReportInvitations.AnyAsync(i => i.ReportId == id && i.InvitedUserId == currentUserId && i.IsAccepted);

            if (!hasAccess)
            {
                return new JsonResult(new { messages = new List<object>() });
            }

            var messages = await _context.ChatMessages
                .Include(m => m.User)
                .Where(m => m.ReportId == id && m.Id > lastMessageId)
                .OrderBy(m => m.CreatedAt)
                .Select(m => new
                {
                    id = m.Id,
                    userName = m.User.FullName,
                    message = m.Message,
                    time = GetRelativeTime(m.CreatedAt),
                    isOwn = m.UserId == currentUserId
                })
                .ToListAsync();

            return new JsonResult(new { messages });
        }

        public class RemoveCollaboratorRequest
        {
            public int InvitationId { get; set; }
        }

        private string GetRelativeTime(DateTime dateTime)
        {
            var timeSpan = DateTime.Now - dateTime;

            if (timeSpan.TotalMinutes < 1)
                return "Chiar acum";
            if (timeSpan.TotalMinutes < 60)
                return $"{(int)timeSpan.TotalMinutes}m";
            if (timeSpan.TotalHours < 24)
                return $"{(int)timeSpan.TotalHours}h";
            if (timeSpan.TotalDays < 7)
                return $"{(int)timeSpan.TotalDays}z";

            return dateTime.ToString("dd MMM");
        }
    }
}