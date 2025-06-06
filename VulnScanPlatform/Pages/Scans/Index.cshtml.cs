// Pages/Scans/Index.cshtml.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnScanPlatform.Models;
using VulnScanPlatform.Services;

namespace VulnScanPlatform.Pages.Scans
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<User> _userManager;
        private readonly IWebHostEnvironment _environment;
        private readonly IScanService _scanService;
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(
            ApplicationDbContext context,
            UserManager<User> userManager,
            IWebHostEnvironment environment,
            IScanService scanService,
            ILogger<IndexModel> logger)
        {
            _context = context;
            _userManager = userManager;
            _environment = environment;
            _scanService = scanService;
            _logger = logger;
        }

        public List<ReportDto> UserReports { get; set; } = new();
        public List<ReportDto> SharedReports { get; set; } = new();

        public async Task OnGetAsync()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Get reports created by the user
            UserReports = await _context.Reports
                .Where(r => r.CreatedByUserId == userId)
                .Include(r => r.Scan)
                    .ThenInclude(s => s.Application)
                .Include(r => r.Scan)
                    .ThenInclude(s => s.Vulnerabilities)
                .OrderByDescending(r => r.CreatedAt)
                .Select(r => new ReportDto
                {
                    Id = r.Id,
                    Title = r.Title,
                    CreatedAt = r.CreatedAt,
                    CreatedBy = r.CreatedBy,
                    Scan = r.Scan,
                    CriticalCount = r.Scan.Vulnerabilities.Count(v => v.Severity == Severity.Critical),
                    HighCount = r.Scan.Vulnerabilities.Count(v => v.Severity == Severity.High),
                    MediumCount = r.Scan.Vulnerabilities.Count(v => v.Severity == Severity.Medium),
                    LowCount = r.Scan.Vulnerabilities.Count(v => v.Severity == Severity.Low)
                })
                .ToListAsync();

            // Get reports shared with the user (where user is invited and accepted)
            SharedReports = await _context.ReportInvitations
                .Where(ri => ri.InvitedUserId == userId && ri.IsAccepted)
                .Include(ri => ri.Report)
                    .ThenInclude(r => r.CreatedBy)
                .Include(ri => ri.Report.Scan)
                    .ThenInclude(s => s.Application)
                .Include(ri => ri.Report.Scan)
                    .ThenInclude(s => s.Vulnerabilities)
                .OrderByDescending(ri => ri.Report.CreatedAt)
                .Select(ri => new ReportDto
                {
                    Id = ri.Report.Id,
                    Title = ri.Report.Title,
                    CreatedAt = ri.Report.CreatedAt,
                    CreatedBy = ri.Report.CreatedBy,
                    Scan = ri.Report.Scan,
                    CriticalCount = ri.Report.Scan.Vulnerabilities.Count(v => v.Severity == Severity.Critical),
                    HighCount = ri.Report.Scan.Vulnerabilities.Count(v => v.Severity == Severity.High),
                    MediumCount = ri.Report.Scan.Vulnerabilities.Count(v => v.Severity == Severity.Medium),
                    LowCount = ri.Report.Scan.Vulnerabilities.Count(v => v.Severity == Severity.Low)
                })
                .ToListAsync();
        }

        public async Task<IActionResult> OnPostAsync(string scanName, IFormFile htmlFile, ScanType scanType)
        {
            if (!ModelState.IsValid || htmlFile == null || htmlFile.Length == 0)
            {
                TempData["ErrorMessage"] = "Vă rugăm să selectați un fișier HTML valid.";
                return RedirectToPage();
            }

            // Validate file
            if (htmlFile.Length > 10 * 1024 * 1024) // 10MB limit
            {
                TempData["ErrorMessage"] = "Fișierul nu poate depăși 10MB.";
                return RedirectToPage();
            }

            var allowedExtensions = new[] { ".html", ".htm" };
            var fileExtension = Path.GetExtension(htmlFile.FileName).ToLowerInvariant();
            if (!allowedExtensions.Contains(fileExtension))
            {
                TempData["ErrorMessage"] = "Doar fișiere HTML sunt acceptate.";
                return RedirectToPage();
            }

            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

                // Create a default application for standalone scans
                var application = await _context.Applications
                    .FirstOrDefaultAsync(a => a.UserId == userId && a.Name == "Scanări Rapide");

                if (application == null)
                {
                    application = new Application
                    {
                        Name = "Scanări Rapide",
                        Description = "Aplicație pentru scanări individuale",
                        Type = ApplicationType.Other,
                        UserId = userId,
                        CreatedAt = DateTime.UtcNow,
                        IsActive = true
                    };
                    _context.Applications.Add(application);
                    await _context.SaveChangesAsync();
                }

                // Save file
                var uploadPath = Path.Combine(_environment.WebRootPath, "uploads", "scans", DateTime.Now.ToString("yyyy-MM"));
                Directory.CreateDirectory(uploadPath);

                var fileName = $"{Guid.NewGuid()}{fileExtension}";
                var filePath = Path.Combine(uploadPath, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await htmlFile.CopyToAsync(stream);
                }

                // Read file content
                var fileContent = await System.IO.File.ReadAllTextAsync(filePath);

                // Create scan
                var scan = new Scan
                {
                    ApplicationId = application.Id,
                    Type = scanType,
                    Status = ScanStatus.Pending,
                    StartedByUserId = userId,
                    FileName = htmlFile.FileName,
                    FilePath = filePath,
                    FileSize = htmlFile.Length,
                    FileContent = fileContent,
                    StartedAt = DateTime.UtcNow
                };

                _context.Scans.Add(scan);
                await _context.SaveChangesAsync();

                // Create report
                var reportTitle = !string.IsNullOrWhiteSpace(scanName)
                    ? scanName
                    : $"Scanare {htmlFile.FileName} - {DateTime.Now:dd MMM yyyy HH:mm}";

                var report = new Report
                {
                    Title = reportTitle,
                    Content = "Scanare în progres...",
                    CreatedByUserId = userId,
                    CreatedAt = DateTime.UtcNow,
                    ScanId = scan.Id
                };

                _context.Reports.Add(report);
                await _context.SaveChangesAsync();

                // Start scan in background
                _ = Task.Run(async () => await _scanService.ProcessScanAsync(scan.Id));

                _logger.LogInformation("Scan {ScanId} started for file {FileName} by user {UserId}",
                    scan.Id, htmlFile.FileName, userId);

                TempData["SuccessMessage"] = "Scanarea a început! Vei fi redirecționat către raport.";
                return RedirectToPage("/Reports/Details", new { id = report.Id });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating scan");
                TempData["ErrorMessage"] = "A apărut o eroare la procesarea fișierului. Vă rugăm să încercați din nou.";
                return RedirectToPage();
            }
        }
    }

    public class ReportDto
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public DateTime CreatedAt { get; set; }
        public User CreatedBy { get; set; }
        public Scan Scan { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
    }
}