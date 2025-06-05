// Pages/Applications/Index.cshtml.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnScanPlatform.Models;
using VulnScanPlatform.Services;

namespace VulnScanPlatform.Pages.Applications
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

        public List<ApplicationDto> Applications { get; set; } = new();
        public int TotalApplications { get; set; }
        public int ActiveApplications { get; set; }
        public int SharedApplications { get; set; }
        public int TotalScans { get; set; }

        public async Task OnGetAsync()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Get all applications where user is owner or collaborator
            var ownApplications = await _context.Applications
                .Where(a => a.UserId == userId && a.IsActive)
                .Select(a => new ApplicationDto
                {
                    Id = a.Id,
                    Name = a.Name,
                    Description = a.Description,
                    Type = a.Type,
                    IsOwner = true,
                    ScanCount = a.Scans.Count,
                    VulnerabilityCount = a.Scans.SelectMany(s => s.Vulnerabilities).Count(),
                    CollaboratorCount = a.Collaborators.Count,
                    LastScanDate = a.Scans.OrderByDescending(s => s.StartedAt).FirstOrDefault().StartedAt
                })
                .ToListAsync();

            var sharedApplications = await _context.ApplicationCollaborators
                .Where(ac => ac.UserId == userId)
                .Include(ac => ac.Application)
                    .ThenInclude(a => a.Scans)
                .Include(ac => ac.Application.Collaborators)
                .Select(ac => new ApplicationDto
                {
                    Id = ac.Application.Id,
                    Name = ac.Application.Name,
                    Description = ac.Application.Description,
                    Type = ac.Application.Type,
                    IsOwner = false,
                    ScanCount = ac.Application.Scans.Count,
                    VulnerabilityCount = ac.Application.Scans.SelectMany(s => s.Vulnerabilities).Count(),
                    CollaboratorCount = ac.Application.Collaborators.Count,
                    LastScanDate = ac.Application.Scans.OrderByDescending(s => s.StartedAt).FirstOrDefault().StartedAt
                })
                .ToListAsync();

            Applications = ownApplications.Concat(sharedApplications)
                .OrderByDescending(a => a.IsOwner)
                .ThenBy(a => a.Name)
                .ToList();

            // Calculate statistics
            TotalApplications = Applications.Count;
            ActiveApplications = ownApplications.Count;
            SharedApplications = sharedApplications.Count;
            TotalScans = Applications.Sum(a => a.ScanCount);
        }

        public async Task<IActionResult> OnPostAsync(
            string applicationName,
            string description,
            ApplicationType applicationType,
            IFormFile htmlFile,
            List<string> collaborators)
        {
            if (!ModelState.IsValid || htmlFile == null || htmlFile.Length == 0)
            {
                TempData["ErrorMessage"] = "Vă rugăm să completați toate câmpurile obligatorii.";
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

                // Create application
                var application = new Application
                {
                    Name = applicationName,
                    Description = description,
                    Type = applicationType,
                    UserId = userId,
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                };

                _context.Applications.Add(application);
                await _context.SaveChangesAsync();

                // Add collaborators
                if (collaborators != null && collaborators.Any())
                {
                    foreach (var email in collaborators.Where(e => !string.IsNullOrWhiteSpace(e)))
                    {
                        var collaboratorUser = await _userManager.FindByEmailAsync(email.Trim());
                        if (collaboratorUser != null && collaboratorUser.Id != userId)
                        {
                            _context.ApplicationCollaborators.Add(new ApplicationCollaborator
                            {
                                ApplicationId = application.Id,
                                UserId = collaboratorUser.Id,
                                AddedAt = DateTime.UtcNow
                            });
                        }
                    }
                    await _context.SaveChangesAsync();
                }

                // Save file and start initial scan
                var uploadPath = Path.Combine(_environment.WebRootPath, "uploads", "applications", application.Id.ToString());
                Directory.CreateDirectory(uploadPath);

                var fileName = $"{Guid.NewGuid()}{fileExtension}";
                var filePath = Path.Combine(uploadPath, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await htmlFile.CopyToAsync(stream);
                }

                // Read file content
                var fileContent = await System.IO.File.ReadAllTextAsync(filePath);

                // Create initial scan
                var scan = new Scan
                {
                    ApplicationId = application.Id,
                    Type = ScanType.Full,
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

                // Start scan in background
                _ = Task.Run(async () => await _scanService.ProcessScanAsync(scan.Id));

                _logger.LogInformation("Application {AppId} created with initial scan {ScanId}",
                    application.Id, scan.Id);

                TempData["SuccessMessage"] = "Aplicația a fost creată și scanarea a început!";
                return RedirectToPage();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating application");
                TempData["ErrorMessage"] = "A apărut o eroare. Vă rugăm să încercați din nou.";
                return RedirectToPage();
            }
        }

        public async Task<IActionResult> OnPostStartScanAsync(int applicationId, ScanType scanType, string inviteEmails)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Verify user has access to this application
            var hasAccess = await _context.Applications.AnyAsync(a => a.Id == applicationId && a.UserId == userId)
                || await _context.ApplicationCollaborators.AnyAsync(ac => ac.ApplicationId == applicationId && ac.UserId == userId);

            if (!hasAccess)
            {
                return Forbid();
            }

            // Get the latest file from previous scans
            var latestScan = await _context.Scans
                .Where(s => s.ApplicationId == applicationId)
                .OrderByDescending(s => s.StartedAt)
                .FirstOrDefaultAsync();

            if (latestScan == null || string.IsNullOrEmpty(latestScan.FilePath))
            {
                TempData["ErrorMessage"] = "Nu există fișier pentru scanare.";
                return RedirectToPage();
            }

            // Create new scan
            var scan = new Scan
            {
                ApplicationId = applicationId,
                Type = scanType,
                Status = ScanStatus.Pending,
                StartedByUserId = userId,
                FileName = latestScan.FileName,
                FilePath = latestScan.FilePath,
                FileSize = latestScan.FileSize,
                FileContent = latestScan.FileContent,
                StartedAt = DateTime.UtcNow
            };

            _context.Scans.Add(scan);
            await _context.SaveChangesAsync();

            // Create report for this scan
            var report = new Report
            {
                Title = $"Raport Scanare - {DateTime.Now:dd MMM yyyy HH:mm}",
                Content = "Scanare în progres...",
                CreatedByUserId = userId,
                CreatedAt = DateTime.UtcNow,
                ScanId = scan.Id
            };

            _context.Reports.Add(report);
            await _context.SaveChangesAsync();

            // Add invitations if provided
            if (!string.IsNullOrWhiteSpace(inviteEmails))
            {
                var emails = inviteEmails.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(e => e.Trim())
                    .Where(e => !string.IsNullOrWhiteSpace(e));

                foreach (var email in emails)
                {
                    var invitedUser = await _userManager.FindByEmailAsync(email);
                    if (invitedUser != null)
                    {
                        _context.ReportInvitations.Add(new ReportInvitation
                        {
                            ReportId = report.Id,
                            InvitedUserEmail = email,
                            InvitedUserId = invitedUser.Id,
                            InvitedByUserId = userId,
                            CreatedAt = DateTime.UtcNow
                        });
                    }
                }
                await _context.SaveChangesAsync();
            }

            // Start scan in background
            _ = Task.Run(async () => await _scanService.ProcessScanAsync(scan.Id));

            TempData["SuccessMessage"] = "Scanarea a început! Vei primi o notificare când este completă.";
            return RedirectToPage("/Reports/Details", new { id = report.Id });
        }
    }

    public class ApplicationDto
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public ApplicationType Type { get; set; }
        public bool IsOwner { get; set; }
        public int ScanCount { get; set; }
        public int VulnerabilityCount { get; set; }
        public int CollaboratorCount { get; set; }
        public DateTime? LastScanDate { get; set; }
    }
}