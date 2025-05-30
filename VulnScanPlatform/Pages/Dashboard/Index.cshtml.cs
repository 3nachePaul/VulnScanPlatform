using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Pages.Dashboard
{
    [Authorize] // Allows any authenticated user
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

        // User Information
        public string UserFirstName { get; set; }
        public string UserRole { get; set; }
        public int SecurityScore { get; set; }

        // Statistics
        public int TotalApplications { get; set; }
        public int NewApplicationsThisWeek { get; set; }
        public int TotalScans { get; set; }
        public string LastScanTime { get; set; }
        public int CriticalVulnerabilities { get; set; }
        public int HighVulnerabilities { get; set; }
        public int MediumVulnerabilities { get; set; }
        public int LowVulnerabilities { get; set; }
        public int ResolvedVulnerabilities { get; set; }
        public int ResolutionRate { get; set; }

        // Lists and Collections
        public List<RecentScanDto> RecentScans { get; set; } = new();
        public List<CriticalAlertDto> CriticalAlerts { get; set; } = new();
        public Dictionary<string, int> VulnerabilitiesByCategory { get; set; } = new();

        // Chart Data
        public List<string> ChartLabels { get; set; } = new();
        public List<int> CriticalTrend { get; set; } = new();
        public List<int> HighTrend { get; set; } = new();
        public List<int> MediumTrend { get; set; } = new();
        public List<int> LowTrend { get; set; } = new();

        public async Task<IActionResult> OnGetAsync()
        {
            try
            {
                // Get current user
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                var user = await _userManager.FindByIdAsync(userId);

                if (user == null)
                {
                    _logger.LogWarning($"User not found for ID: {userId}");
                    return RedirectToPage("/Account/Login");
                }

                // Set user information
                UserFirstName = user.FirstName;
                UserRole = user.Role.ToString();

                // Log successful dashboard access
                _logger.LogInformation($"Dashboard accessed by user: {user.Email} (Role: {UserRole})");

                // Load dashboard data
                await LoadDashboardStatistics(userId);
                await LoadRecentScans(userId);
                await LoadVulnerabilityData(userId);
                LoadChartData();
                CalculateSecurityScore();

                return Page();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading dashboard");
                TempData["ErrorMessage"] = "A apărut o eroare la încărcarea dashboard-ului.";
                return Page();
            }
        }

        private async Task LoadDashboardStatistics(string userId)
        {
            // For now, we'll use mock data since the full database schema isn't implemented yet
            // In a real implementation, these would query the actual database tables

            // Mock data for demonstration
            TotalApplications = 5;
            NewApplicationsThisWeek = 2;
            TotalScans = 23;
            LastScanTime = "Acum 2 ore";
            CriticalVulnerabilities = 3;
            HighVulnerabilities = 7;
            MediumVulnerabilities = 15;
            LowVulnerabilities = 22;
            ResolvedVulnerabilities = 18;

            var totalVulnerabilities = CriticalVulnerabilities + HighVulnerabilities +
                                     MediumVulnerabilities + LowVulnerabilities;
            ResolutionRate = totalVulnerabilities > 0
                ? (int)((ResolvedVulnerabilities * 100.0) / totalVulnerabilities)
                : 0;

            // In a real implementation:
            /*
            TotalApplications = await _context.Applications
                .Where(a => a.UserId == userId && a.IsActive)
                .CountAsync();

            NewApplicationsThisWeek = await _context.Applications
                .Where(a => a.UserId == userId && a.CreatedAt >= DateTime.UtcNow.AddDays(-7))
                .CountAsync();

            TotalScans = await _context.Scans
                .Where(s => s.Application.UserId == userId)
                .CountAsync();

            var lastScan = await _context.Scans
                .Where(s => s.Application.UserId == userId)
                .OrderByDescending(s => s.StartedAt)
                .FirstOrDefaultAsync();

            LastScanTime = lastScan != null 
                ? GetRelativeTime(lastScan.StartedAt) 
                : "Niciodată";

            // Count vulnerabilities by severity
            var vulnerabilities = await _context.Vulnerabilities
                .Where(v => v.Scan.Application.UserId == userId)
                .GroupBy(v => v.Severity)
                .Select(g => new { Severity = g.Key, Count = g.Count() })
                .ToListAsync();

            CriticalVulnerabilities = vulnerabilities.FirstOrDefault(v => v.Severity == Severity.Critical)?.Count ?? 0;
            HighVulnerabilities = vulnerabilities.FirstOrDefault(v => v.Severity == Severity.High)?.Count ?? 0;
            MediumVulnerabilities = vulnerabilities.FirstOrDefault(v => v.Severity == Severity.Medium)?.Count ?? 0;
            LowVulnerabilities = vulnerabilities.FirstOrDefault(v => v.Severity == Severity.Low)?.Count ?? 0;

            ResolvedVulnerabilities = await _context.Vulnerabilities
                .Where(v => v.Scan.Application.UserId == userId && v.Status == VulnerabilityStatus.Resolved)
                .CountAsync();
            */
        }

        private async Task LoadRecentScans(string userId)
        {
            // Mock data for demonstration
            RecentScans = new List<RecentScanDto>
            {
                new RecentScanDto
                {
                    Id = 1,
                    ApplicationName = "Portal Web Principal",
                    ApplicationUrl = "https://example.com",
                    ScanType = "Full",
                    Status = "Completed",
                    CriticalCount = 1,
                    HighCount = 3,
                    MediumCount = 5,
                    LowCount = 8,
                    ScanDate = DateTime.Now.AddHours(-2)
                },
                new RecentScanDto
                {
                    Id = 2,
                    ApplicationName = "API Backend",
                    ApplicationUrl = "https://api.example.com",
                    ScanType = "Quick",
                    Status = "In Progress",
                    CriticalCount = 0,
                    HighCount = 1,
                    MediumCount = 3,
                    LowCount = 4,
                    ScanDate = DateTime.Now.AddHours(-5)
                },
                new RecentScanDto
                {
                    Id = 3,
                    ApplicationName = "Mobile Backend",
                    ApplicationUrl = "https://mobile-api.example.com",
                    ScanType = "Manual",
                    Status = "Completed",
                    CriticalCount = 2,
                    HighCount = 3,
                    MediumCount = 7,
                    LowCount = 10,
                    ScanDate = DateTime.Now.AddDays(-1)
                }
            };

            // In a real implementation:
            /*
            RecentScans = await _context.Scans
                .Where(s => s.Application.UserId == userId)
                .OrderByDescending(s => s.StartedAt)
                .Take(5)
                .Select(s => new RecentScanDto
                {
                    Id = s.Id,
                    ApplicationName = s.Application.Name,
                    ApplicationUrl = s.Application.Url,
                    ScanType = s.ScanType.ToString(),
                    Status = s.Status.ToString(),
                    CriticalCount = s.Vulnerabilities.Count(v => v.Severity == Severity.Critical),
                    HighCount = s.Vulnerabilities.Count(v => v.Severity == Severity.High),
                    MediumCount = s.Vulnerabilities.Count(v => v.Severity == Severity.Medium),
                    LowCount = s.Vulnerabilities.Count(v => v.Severity == Severity.Low),
                    ScanDate = s.StartedAt
                })
                .ToListAsync();
            */
        }

        private async Task LoadVulnerabilityData(string userId)
        {
            // Mock OWASP categories
            VulnerabilitiesByCategory = new Dictionary<string, int>
            {
                { "SQL Injection", 5 },
                { "XSS", 8 },
                { "Authentication", 3 },
                { "CSRF", 2 }
            };

            // Mock critical alerts
            if (CriticalVulnerabilities > 0)
            {
                CriticalAlerts = new List<CriticalAlertDto>
                {
                    new CriticalAlertDto
                    {
                        Id = 1,
                        Title = "SQL Injection în formularul de login",
                        ApplicationName = "Portal Web Principal",
                        DetectedDate = DateTime.Now.AddDays(-2)
                    }
                };
            }

            // In a real implementation:
            /*
            VulnerabilitiesByCategory = await _context.Vulnerabilities
                .Where(v => v.Scan.Application.UserId == userId && v.Status != VulnerabilityStatus.Resolved)
                .GroupBy(v => v.Category)
                .Select(g => new { Category = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Category, x => x.Count);

            CriticalAlerts = await _context.Vulnerabilities
                .Where(v => v.Scan.Application.UserId == userId && 
                           v.Severity == Severity.Critical && 
                           v.Status != VulnerabilityStatus.Resolved)
                .OrderByDescending(v => v.DetectedAt)
                .Take(5)
                .Select(v => new CriticalAlertDto
                {
                    Id = v.Id,
                    Title = v.Title,
                    ApplicationName = v.Scan.Application.Name,
                    DetectedDate = v.DetectedAt
                })
                .ToListAsync();
            */
        }

        private void LoadChartData()
        {
            // Generate mock chart data for the last 30 days
            var today = DateTime.Now.Date;
            ChartLabels = new List<string>();
            CriticalTrend = new List<int>();
            HighTrend = new List<int>();
            MediumTrend = new List<int>();
            LowTrend = new List<int>();

            for (int i = 29; i >= 0; i--)
            {
                var date = today.AddDays(-i);
                ChartLabels.Add(date.ToString("dd MMM"));

                // Mock random data with some trend
                CriticalTrend.Add(Random.Shared.Next(0, 5));
                HighTrend.Add(Random.Shared.Next(3, 10));
                MediumTrend.Add(Random.Shared.Next(10, 20));
                LowTrend.Add(Random.Shared.Next(15, 30));
            }
        }

        private void CalculateSecurityScore()
        {
            // Simple security score calculation
            var totalVulnerabilities = CriticalVulnerabilities + HighVulnerabilities +
                                     MediumVulnerabilities + LowVulnerabilities;

            if (totalVulnerabilities == 0)
            {
                SecurityScore = 100;
            }
            else
            {
                // Weight vulnerabilities by severity
                var weightedScore = (CriticalVulnerabilities * 10) +
                                  (HighVulnerabilities * 5) +
                                  (MediumVulnerabilities * 2) +
                                  (LowVulnerabilities * 1);

                SecurityScore = Math.Max(0, 100 - weightedScore);
            }
        }

        private string GetRelativeTime(DateTime dateTime)
        {
            var timeSpan = DateTime.UtcNow - dateTime;

            if (timeSpan.TotalMinutes < 1)
                return "Chiar acum";
            if (timeSpan.TotalMinutes < 60)
                return $"Acum {(int)timeSpan.TotalMinutes} minute";
            if (timeSpan.TotalHours < 24)
                return $"Acum {(int)timeSpan.TotalHours} ore";
            if (timeSpan.TotalDays < 7)
                return $"Acum {(int)timeSpan.TotalDays} zile";

            return dateTime.ToString("dd MMM yyyy");
        }
    }

    // DTOs for Dashboard
    public class RecentScanDto
    {
        public int Id { get; set; }
        public string ApplicationName { get; set; }
        public string ApplicationUrl { get; set; }
        public string ScanType { get; set; }
        public string Status { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public DateTime ScanDate { get; set; }
    }

    public class CriticalAlertDto
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string ApplicationName { get; set; }
        public DateTime DetectedDate { get; set; }
    }
}