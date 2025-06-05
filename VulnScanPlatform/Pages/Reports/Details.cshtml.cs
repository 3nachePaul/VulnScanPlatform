//using Microsoft.AspNetCore.Authorization;
//using Microsoft.AspNetCore.Identity;
//using Microsoft.AspNetCore.Mvc;
//using Microsoft.AspNetCore.Mvc.RazorPages;
//using Microsoft.EntityFrameworkCore;
//using System.Security.Claims;
//using VulnScanPlatform.Models;

//namespace VulnScanPlatform.Pages.Reports
//{
//    [Authorize]
//    public class DetailsModel : PageModel
//    {
//        private readonly ApplicationDbContext _context;
//        private readonly UserManager<User> _userManager;
//        private readonly ILogger<DetailsModel> _logger;

//        public DetailsModel(
//            ApplicationDbContext context,
//            UserManager<User> userManager,
//            ILogger<DetailsModel> logger)
//        {
//            _context = context;
//            _userManager = userManager;
//            _logger = logger;
//        }

//        public Report Report { get; set; }
//        public List<ReportInvitation> Invitations { get; set; }
//        public List<ChatMessage> ChatMessages { get; set; }
//        public bool IsOwner { get; set; }
//        public bool HasAccess { get; set; }
//        public bool HasPendingInvitation { get; set; }
//        public string CurrentUserId { get; set; }

//        public async Task<IActionResult> OnGetAsync(int id)
//        {
//            CurrentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

//            // For demo purposes, create mock data
//            Report = new Report
//            {
//                Id = id,
//                Title = $"Raport de Analiză pentru index.html",
//                Content = GenerateMockReportContent(),
//                CreatedByUserId = CurrentUserId, // Make current user the owner for demo
//                CreatedAt = DateTime.Now.AddHours(-2),
//                CreatedBy = await _userManager.GetUserAsync(User)
//            };

//            IsOwner = Report.CreatedByUserId == CurrentUserId;

//            // Mock invitations
//            Invitations = new List<ReportInvitation>
//            {
//                new ReportInvitation
//                {
//                    Id = 1,
//                    ReportId = id,
//                    InvitedUserEmail = "ion.popescu@example.com",
//                    IsAccepted = true,
//                    InvitedUser = new User
//                    {
//                        FirstName = "Ion",
//                        LastName = "Popescu",
//                        Email = "ion.popescu@example.com"
//                    }
//                },
//                new ReportInvitation
//                {
//                    Id = 2,
//                    ReportId = id,
//                    InvitedUserEmail = "maria.ionescu@example.com",
//                    IsAccepted = false
//                }
//            };

//            // Mock chat messages
//            ChatMessages = new List<ChatMessage>
//            {
//                new ChatMessage
//                {
//                    Id = 1,
//                    UserId = CurrentUserId,
//                    Message = "Am finalizat analiza. Arată bine overall, dar sunt câteva aspecte de îmbunătățit.",
//                    CreatedAt = DateTime.Now.AddHours(-1),
//                    User = Report.CreatedBy
//                },
//                new ChatMessage
//                {
//                    Id = 2,
//                    UserId = "other-user-id",
//                    Message = "Mulțumesc pentru raport! Am văzut recomandările pentru optimizarea imaginilor.",
//                    CreatedAt = DateTime.Now.AddMinutes(-45),
//                    User = new User
//                    {
//                        FirstName = "Ion",
//                        LastName = "Popescu"
//                    }
//                },
//                new ChatMessage
//                {
//                    Id = 3,
//                    UserId = CurrentUserId,
//                    Message = "Da, asta ar trebui să îmbunătățească timpul de încărcare cu cel puțin 30%.",
//                    CreatedAt = DateTime.Now.AddMinutes(-30),
//                    User = Report.CreatedBy
//                }
//            };

//            HasAccess = IsOwner || Invitations.Any(i => i.InvitedUserId == CurrentUserId && i.IsAccepted);

//            // In real implementation, check database
//            /*
//            Report = await _context.Reports
//                .Include(r => r.CreatedBy)
//                .Include(r => r.Invitations)
//                    .ThenInclude(i => i.InvitedUser)
//                .FirstOrDefaultAsync(r => r.Id == id);

//            if (Report == null)
//            {
//                return NotFound();
//            }

//            IsOwner = Report.CreatedByUserId == CurrentUserId;

//            var hasInvitation = await _context.ReportInvitations
//                .AnyAsync(i => i.ReportId == id && 
//                              i.InvitedUserId == CurrentUserId && 
//                              i.IsAccepted);

//            HasAccess = IsOwner || hasInvitation;

//            if (!HasAccess)
//            {
//                // Check for pending invitation
//                HasPendingInvitation = await _context.ReportInvitations
//                    .AnyAsync(i => i.ReportId == id && 
//                                  i.InvitedUserEmail == User.FindFirst(ClaimTypes.Email).Value && 
//                                  !i.IsAccepted);

//                if (!HasPendingInvitation)
//                {
//                    return Forbid();
//                }
//            }

//            Invitations = await _context.ReportInvitations
//                .Include(i => i.InvitedUser)
//                .Where(i => i.ReportId == id)
//                .ToListAsync();

//            ChatMessages = await _context.ChatMessages
//                .Include(m => m.User)
//                .Where(m => m.ReportId == id)
//                .OrderBy(m => m.CreatedAt)
//                .ToListAsync();
//            */

//            return Page();
//        }

//        public async Task<IActionResult> OnPostInviteAsync(int id, string email)
//        {
//            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

//            // Check if user is owner
//            // In real implementation, verify from database

//            if (string.IsNullOrWhiteSpace(email))
//            {
//                TempData["ErrorMessage"] = "Vă rugăm să introduceți o adresă de email validă.";
//                return RedirectToPage(new { id });
//            }

//            // Check if user exists
//            var invitedUser = await _userManager.FindByEmailAsync(email);
//            if (invitedUser == null)
//            {
//                TempData["ErrorMessage"] = "Nu există un utilizator cu acest email în sistem.";
//                return RedirectToPage(new { id });
//            }

//            // Check if already invited
//            /*
//            var existingInvitation = await _context.ReportInvitations
//                .AnyAsync(i => i.ReportId == id && i.InvitedUserEmail == email);

//            if (existingInvitation)
//            {
//                TempData["ErrorMessage"] = "Acest utilizator a fost deja invitat.";
//                return RedirectToPage(new { id });
//            }

//            // Create invitation
//            var invitation = new ReportInvitation
//            {
//                ReportId = id,
//                InvitedByUserId = currentUserId,
//                InvitedUserEmail = email,
//                InvitedUserId = invitedUser.Id,
//                CreatedAt = DateTime.UtcNow
//            };

//            _context.ReportInvitations.Add(invitation);
//            await _context.SaveChangesAsync();
//            */

//            _logger.LogInformation("User {UserId} invited {Email} to report {ReportId}",
//                currentUserId, email, id);

//            TempData["SuccessMessage"] = $"Invitație trimisă către {email}!";
//            return RedirectToPage(new { id });
//        }

//        public async Task<IActionResult> OnPostSendMessageAsync(int id, string message)
//        {
//            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

//            if (string.IsNullOrWhiteSpace(message))
//            {
//                return RedirectToPage(new { id });
//            }

//            // In real implementation
//            /*
//            var chatMessage = new ChatMessage
//            {
//                ReportId = id,
//                UserId = currentUserId,
//                Message = message.Trim(),
//                CreatedAt = DateTime.UtcNow
//            };

//            _context.ChatMessages.Add(chatMessage);
//            await _context.SaveChangesAsync();
//            */

//            _logger.LogInformation("User {UserId} sent message in report {ReportId}", currentUserId, id);

//            return RedirectToPage(new { id });
//        }

//        public async Task<IActionResult> OnPostAcceptInvitationAsync(int id)
//        {
//            var currentUserEmail = User.FindFirstValue(ClaimTypes.Email);
//            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

//            // In real implementation
//            /*
//            var invitation = await _context.ReportInvitations
//                .FirstOrDefaultAsync(i => i.ReportId == id && 
//                                         i.InvitedUserEmail == currentUserEmail && 
//                                         !i.IsAccepted);

//            if (invitation != null)
//            {
//                invitation.IsAccepted = true;
//                invitation.AcceptedAt = DateTime.UtcNow;
//                invitation.InvitedUserId = currentUserId;

//                await _context.SaveChangesAsync();

//                TempData["SuccessMessage"] = "Invitație acceptată! Acum ai acces la acest raport.";
//            }
//            */

//            return RedirectToPage(new { id });
//        }

//        public async Task<IActionResult> OnPostRemoveCollaboratorAsync(int id, [FromBody] RemoveCollaboratorRequest request)
//        {
//            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

//            // Verify user is owner
//            // Remove invitation

//            return new JsonResult(new { success = true });
//        }

//        public async Task<IActionResult> OnGetNewMessagesAsync(int id, int lastMessageId)
//        {
//            // In real implementation, get messages newer than lastMessageId
//            // This would be better implemented with SignalR for real-time updates

//            var messages = new List<object>();

//            return new JsonResult(new { messages });
//        }

//        private string GenerateMockReportContent()
//        {
//            return @"
//                <h3>Raport de Analiză pentru index.html</h3>
//                <p>Data analizei: " + DateTime.Now.ToString("dd MMMM yyyy, HH:mm") + @"</p>

//                <h4>Sumar Executiv</h4>
//                <p>Analiza fișierului HTML a fost completată cu succes. Documentul prezintă o structură bine organizată cu câteva oportunități de optimizare.</p>

//                <h4>Structură Document</h4>
//                <ul>
//                    <li><strong>Doctype:</strong> HTML5 ✓</li>
//                    <li><strong>Encoding:</strong> UTF-8 ✓</li>
//                    <li><strong>Total elemente HTML:</strong> 234</li>
//                    <li><strong>Elemente semantice:</strong> 67 (28.6%)</li>
//                    <li><strong>Imagini:</strong> 12 (3 fără atribut alt)</li>
//                    <li><strong>Link-uri:</strong> 45 (8 externe)</li>
//                    <li><strong>Formulare:</strong> 2</li>
//                </ul>

//                <h4>Performanță</h4>
//                <table class='table table-bordered'>
//                    <tr>
//                        <th>Metrică</th>
//                        <th>Valoare</th>
//                        <th>Status</th>
//                    </tr>
//                    <tr>
//                        <td>Dimensiune fișier</td>
//                        <td>32.5 KB</td>
//                        <td><span class='badge bg-success'>Bun</span></td>
//                    </tr>
//                    <tr>
//                        <td>Timp estimat încărcare (3G)</td>
//                        <td>2.8s</td>
//                        <td><span class='badge bg-warning'>Mediu</span></td>
//                    </tr>
//                    <tr>
//                        <td>Resurse externe</td>
//                        <td>23</td>
//                        <td><span class='badge bg-danger'>Necesită optimizare</span></td>
//                    </tr>
//                    <tr>
//                        <td>CSS inline</td>
//                        <td>15 instanțe</td>
//                        <td><span class='badge bg-warning'>Poate fi îmbunătățit</span></td>
//                    </tr>
//                </table>

//                <h4>SEO & Accesibilitate</h4>
//                <ul>
//                    <li>✓ Tag &lt;title&gt; prezent și optimizat (58 caractere)</li>
//                    <li>✓ Meta description prezent (152 caractere)</li>
//                    <li>✓ Headings ierarhice corecte (H1 → H2 → H3)</li>
//                    <li>⚠️ 3 imagini fără atribut 'alt'</li>
//                    <li>⚠️ Lipsește meta viewport pentru responsive</li>
//                    <li>✗ Lipsesc meta tags Open Graph</li>
//                </ul>

//                <h4>Recomandări Prioritare</h4>
//                <ol>
//                    <li><strong>Optimizează imaginile:</strong> Compresează imaginile și folosește formate moderne (WebP). Estimare reducere: 40% din dimensiune.</li>
//                    <li><strong>Implementează lazy loading:</strong> Pentru imaginile below-the-fold pentru îmbunătățirea timpului de încărcare inițial.</li>
//                    <li><strong>Minifică resursele:</strong> CSS și JavaScript pot fi reduse cu aproximativ 25%.</li>
//                    <li><strong>Adaugă atribute 'alt':</strong> Pentru toate imaginile pentru îmbunătățirea accesibilității.</li>
//                    <li><strong>Implementează cache headers:</strong> Pentru resursele statice.</li>
//                </ol>

//                <h4>Scor General</h4>
//                <div class='text-center my-4'>
//                    <h1 class='display-1 text-primary'>76/100</h1>
//                    <p class='lead'>Structură bună cu potențial de optimizare</p>
//                </div>
//            ";
//        }

//        public class RemoveCollaboratorRequest
//        {
//            public int InvitationId { get; set; }
//        }
//    }
//}


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