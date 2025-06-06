using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnScanPlatform.Models;
using System.Collections.Generic;
using System.Linq;

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
        public ICollection<Vulnerability> Vulnerabilities { get; set; }
        public bool IsOwner { get; set; }
        public bool HasAccess { get; set; }
        public bool HasPendingInvitation { get; set; }
        public string CurrentUserId { get; set; }

        public async Task<IActionResult> OnGetAsync(int id)
        {
            CurrentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Încarcă raportul cu toate datele aferente, inclusiv vulnerabilitățile
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
                .Include(r => r.Scan)
                    .ThenInclude(s => s.Vulnerabilities) // Include vulnerabilitățile
                .FirstOrDefaultAsync(r => r.Id == id);

            if (Report == null)
            {
                return NotFound();
            }

            // Populează proprietatea Vulnerabilities
            if (Report.Scan != null)
            {
                Vulnerabilities = Report.Scan.Vulnerabilities;
            }
            else
            {
                Vulnerabilities = new List<Vulnerability>();
            }

            IsOwner = Report.CreatedByUserId == CurrentUserId;

            // Verifică dacă utilizatorul are acces
            var hasInvitation = await _context.ReportInvitations
                .AnyAsync(i => i.ReportId == id &&
                               i.InvitedUserId == CurrentUserId &&
                               i.IsAccepted);

            HasAccess = IsOwner || hasInvitation;

            if (!HasAccess)
            {
                // Verifică dacă există o invitație în așteptare
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

            var invitedUser = await _userManager.FindByEmailAsync(email);
            if (invitedUser == null)
            {
                TempData["ErrorMessage"] = "Nu există un utilizator cu acest email în sistem.";
                return RedirectToPage(new { id });
            }

            var existingInvitation = await _context.ReportInvitations
                .AnyAsync(i => i.ReportId == id && i.InvitedUserEmail == email);

            if (existingInvitation)
            {
                TempData["ErrorMessage"] = "Acest utilizator a fost deja invitat.";
                return RedirectToPage(new { id });
            }

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

            var hasAccess = await _context.Reports.AnyAsync(r => r.Id == id && r.CreatedByUserId == currentUserId)
                || await _context.ReportInvitations.AnyAsync(i => i.ReportId == id && i.InvitedUserId == currentUserId && i.IsAccepted);

            if (!hasAccess)
            {
                return new JsonResult(new { messages = new List<object>() });
            }

            var newMessages = await _context.ChatMessages
            .Where(m => m.ReportId == id && m.Id > lastMessageId)
            .Include(m => m.User)
            .OrderBy(m => m.CreatedAt)
            .ToListAsync();

            var result = newMessages.Select(m => new
            {
                m.Id,
                m.UserId,
                m.Message,
                UserName = m.User.UserName,
                UserAvatar = m.User.FirstName.Substring(0, 1) + m.User.LastName.Substring(0, 1),
                RelativeTime = GetRelativeTime(m.CreatedAt)
            });

            return new JsonResult(new { messages = result });
        }

        public class RemoveCollaboratorRequest
        {
            public int InvitationId { get; set; }
        }

        private string GetRelativeTime(DateTime dateTime)
        {
            var timeSpan = DateTime.UtcNow - dateTime;

            if (timeSpan.TotalMinutes < 1)
                return "Chiar acum";
            if (timeSpan.TotalMinutes < 60)
                return $"Acum {(int)timeSpan.TotalMinutes}m";
            if (timeSpan.TotalHours < 24)
                return $"Acum {(int)timeSpan.TotalHours}h";
            if (timeSpan.TotalDays < 7)
                return $"Acum {(int)timeSpan.TotalDays}z";

            return dateTime.ToString("dd MMM");
        }
    }
}