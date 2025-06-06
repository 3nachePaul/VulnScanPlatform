using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using VulnScanPlatform.Models;
using Newtonsoft.Json;

namespace VulnScanPlatform.Pages.Vulnerabilities
{
    [Authorize]
    public class CreateModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<CreateModel> _logger;

        public CreateModel(ApplicationDbContext context, ILogger<CreateModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public List<UserScanDto> UserScans { get; set; } = new();

        public class InputModel
        {
            [Required(ErrorMessage = "Selectează o scanare")]
            [Display(Name = "Scanare")]
            public int ScanId { get; set; }

            [Required(ErrorMessage = "Titlul este obligatoriu")]
            [StringLength(200, ErrorMessage = "Titlul nu poate avea mai mult de {1} caractere")]
            [Display(Name = "Titlu")]
            public string Title { get; set; }

            [Required(ErrorMessage = "Descrierea este obligatorie")]
            [StringLength(1000, ErrorMessage = "Descrierea nu poate avea mai mult de {1} caractere")]
            [Display(Name = "Descriere")]
            public string Description { get; set; }

            [Display(Name = "Include codul HTML scanat")]
            public bool IncludeHtmlContent { get; set; } = true;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            await LoadUserScans();
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                await LoadUserScans();
                return Page();
            }

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Verifică că scanarea aparține utilizatorului
            var scan = await _context.Scans
                .Include(s => s.Application)
                .Include(s => s.Vulnerabilities)
                .FirstOrDefaultAsync(s => s.Id == Input.ScanId &&
                    (s.Application.UserId == userId || s.Application.Collaborators.Any(c => c.UserId == userId)));

            if (scan == null)
            {
                ModelState.AddModelError(string.Empty, "Scanarea selectată nu a fost găsită.");
                await LoadUserScans();
                return Page();
            }

            // Verifică dacă scanarea a fost deja postată
            var existingPost = await _context.VulnerabilityPosts
                .AnyAsync(vp => vp.ScanId == Input.ScanId);

            if (existingPost)
            {
                ModelState.AddModelError(string.Empty, "Această scanare a fost deja postată.");
                await LoadUserScans();
                return Page();
            }

            // Pregătește datele vulnerabilităților pentru JSON
            var vulnerabilitiesData = scan.Vulnerabilities.Select(v => new
            {
                Title = v.Title,
                Description = v.Description,
                Severity = v.Severity.ToString(),
                Type = v.Type.ToString(),
                Impact = v.Impact,
                Recommendation = v.Recommendation
            }).ToList();

            // Creează postarea
            var post = new VulnerabilityPost
            {
                Title = Input.Title,
                Description = Input.Description,
                HtmlContent = Input.IncludeHtmlContent ? scan.FileContent : null,
                VulnerabilitiesJson = JsonConvert.SerializeObject(vulnerabilitiesData),
                VulnerabilityCount = scan.Vulnerabilities.Count,
                CriticalCount = scan.Vulnerabilities.Count(v => v.Severity == Severity.Critical),
                HighCount = scan.Vulnerabilities.Count(v => v.Severity == Severity.High),
                MediumCount = scan.Vulnerabilities.Count(v => v.Severity == Severity.Medium),
                LowCount = scan.Vulnerabilities.Count(v => v.Severity == Severity.Low),
                PostedByUserId = userId,
                PostedAt = DateTime.UtcNow,
                ScanId = scan.Id,
                IsApproved = true // Auto-aprobare pentru moment
            };

            _context.VulnerabilityPosts.Add(post);
            await _context.SaveChangesAsync();

            _logger.LogInformation("User {UserId} created vulnerability post {PostId} from scan {ScanId}",
                userId, post.Id, scan.Id);

            TempData["SuccessMessage"] = "Postarea a fost creată cu succes!";
            return RedirectToPage("/Vulnerabilities/Details", new { id = post.Id });
        }

        private async Task LoadUserScans()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Obține scanările care nu au fost încă postate
            var postedScanIds = await _context.VulnerabilityPosts
                .Where(vp => vp.ScanId != null)
                .Select(vp => vp.ScanId.Value)
                .ToListAsync();

            UserScans = await _context.Scans
                .Include(s => s.Application)
                .Include(s => s.Vulnerabilities)
                .Where(s => (s.Application.UserId == userId ||
                            s.Application.Collaborators.Any(c => c.UserId == userId)) &&
                           s.Status == ScanStatus.Completed &&
                           s.Vulnerabilities.Any() &&
                           !postedScanIds.Contains(s.Id))
                .OrderByDescending(s => s.CompletedAt)
                .Select(s => new UserScanDto
                {
                    Id = s.Id,
                    ApplicationName = s.Application.Name,
                    FileName = s.FileName,
                    ScanDate = s.CompletedAt ?? s.StartedAt,
                    VulnerabilityCount = s.Vulnerabilities.Count,
                    CriticalCount = s.Vulnerabilities.Count(v => v.Severity == Severity.Critical),
                    HighCount = s.Vulnerabilities.Count(v => v.Severity == Severity.High)
                })
                .ToListAsync();
        }
    }

    public class UserScanDto
    {
        public int Id { get; set; }
        public string ApplicationName { get; set; }
        public string FileName { get; set; }
        public DateTime ScanDate { get; set; }
        public int VulnerabilityCount { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
    }
}