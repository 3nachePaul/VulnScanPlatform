using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Pages.Notifications
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<User> _userManager;
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(
            ApplicationDbContext context,
            UserManager<User> userManager,
            ILogger<IndexModel> logger)
        {
            _context = context;
            _userManager = userManager;
            _logger = logger;
        }

        public List<ReportInvitation> PendingInvitations { get; set; } = new();
        public List<ReportInvitation> AcceptedInvitations { get; set; } = new();

        public async Task OnGetAsync()
        {
            var currentUserEmail = User.FindFirstValue(ClaimTypes.Email);
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var currentUser = await _userManager.GetUserAsync(User);

            // Mock data for demonstration
            PendingInvitations = new List<ReportInvitation>
            {
                new ReportInvitation
                {
                    Id = 1,
                    ReportId = 1,
                    InvitedUserEmail = currentUserEmail,
                    IsAccepted = false,
                    CreatedAt = DateTime.Now.AddHours(-1),
                    Report = new Report
                    {
                        Id = 1,
                        Title = "Raport Analiză Homepage - Versiunea 2.0"
                    },
                    InvitedBy = new User
                    {
                        FirstName = "Maria",
                        LastName = "Ionescu"
                    }
                },
                new ReportInvitation
                {
                    Id = 2,
                    ReportId = 2,
                    InvitedUserEmail = currentUserEmail,
                    IsAccepted = false,
                    CreatedAt = DateTime.Now.AddDays(-1),
                    Report = new Report
                    {
                        Id = 2,
                        Title = "Analiza Performanță Site E-commerce"
                    },
                    InvitedBy = new User
                    {
                        FirstName = "Alexandru",
                        LastName = "Popescu"
                    }
                }
            };

            AcceptedInvitations = new List<ReportInvitation>
            {
                new ReportInvitation
                {
                    Id = 3,
                    ReportId = 3,
                    InvitedUserEmail = currentUserEmail,
                    IsAccepted = true,
                    AcceptedAt = DateTime.Now.AddDays(-3),
                    CreatedAt = DateTime.Now.AddDays(-4),
                    Report = new Report
                    {
                        Id = 3,
                        Title = "Raport SEO - Landing Page Campaign",
                        ChatMessages = new List<ChatMessage> { new(), new(), new() }
                    },
                    InvitedBy = new User
                    {
                        FirstName = "Andrei",
                        LastName = "Dumitrescu"
                    }
                },
                new ReportInvitation
                {
                    Id = 4,
                    ReportId = 4,
                    InvitedUserEmail = currentUserEmail,
                    IsAccepted = true,
                    AcceptedAt = DateTime.Now.AddDays(-7),
                    CreatedAt = DateTime.Now.AddDays(-8),
                    Report = new Report
                    {
                        Id = 4,
                        Title = "Analiza Structurală Blog Section"
                    },
                    InvitedBy = new User
                    {
                        FirstName = "Elena",
                        LastName = "Vasilescu"
                    }
                }
            };

            // In real implementation:
            /*
            var userEmail = User.FindFirstValue(ClaimTypes.Email);
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Get pending invitations
            PendingInvitations = await _context.ReportInvitations
                .Include(i => i.Report)
                .Include(i => i.InvitedBy)
                .Where(i => i.InvitedUserEmail == userEmail && !i.IsAccepted)
                .OrderByDescending(i => i.CreatedAt)
                .ToListAsync();

            // Get accepted invitations
            AcceptedInvitations = await _context.ReportInvitations
                .Include(i => i.Report)
                    .ThenInclude(r => r.ChatMessages)
                .Include(i => i.InvitedBy)
                .Where(i => i.InvitedUserId == userId && i.IsAccepted)
                .OrderByDescending(i => i.AcceptedAt)
                .ToListAsync();
            */
        }

        public async Task<IActionResult> OnPostAcceptInvitationAsync(int invitationId)
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var currentUserEmail = User.FindFirstValue(ClaimTypes.Email);

            // In real implementation:
            /*
            var invitation = await _context.ReportInvitations
                .FirstOrDefaultAsync(i => i.Id == invitationId && 
                                         i.InvitedUserEmail == currentUserEmail && 
                                         !i.IsAccepted);

            if (invitation == null)
            {
                TempData["ErrorMessage"] = "Invitația nu a fost găsită.";
                return RedirectToPage();
            }

            invitation.IsAccepted = true;
            invitation.AcceptedAt = DateTime.UtcNow;
            invitation.InvitedUserId = currentUserId;

            await _context.SaveChangesAsync();
            */

            _logger.LogInformation("User {UserId} accepted invitation {InvitationId}",
                currentUserId, invitationId);

            TempData["SuccessMessage"] = "Invitație acceptată! Acum ai acces la raport.";
            return RedirectToPage("/Reports/Details", new { id = 1 }); // In real: invitation.ReportId
        }

        public async Task<IActionResult> OnPostDeclineInvitationAsync(int invitationId)
        {
            var currentUserEmail = User.FindFirstValue(ClaimTypes.Email);

            // In real implementation:
            /*
            var invitation = await _context.ReportInvitations
                .FirstOrDefaultAsync(i => i.Id == invitationId && 
                                         i.InvitedUserEmail == currentUserEmail && 
                                         !i.IsAccepted);

            if (invitation == null)
            {
                TempData["ErrorMessage"] = "Invitația nu a fost găsită.";
                return RedirectToPage();
            }

            _context.ReportInvitations.Remove(invitation);
            await _context.SaveChangesAsync();
            */

            _logger.LogInformation("User {Email} declined invitation {InvitationId}",
                currentUserEmail, invitationId);

            TempData["SuccessMessage"] = "Invitația a fost refuzată.";
            return RedirectToPage();
        }
    }
}