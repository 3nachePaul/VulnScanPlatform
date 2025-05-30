using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Pages.Account
{
    [Authorize]
    public class ProfileModel : PageModel
    {
        private readonly UserManager<User> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<ProfileModel> _logger;

        public ProfileModel(
            UserManager<User> userManager,
            ApplicationDbContext context,
            ILogger<ProfileModel> logger)
        {
            _userManager = userManager;
            _context = context;
            _logger = logger;
        }

        public UserProfileDto UserProfile { get; set; }
        public int TotalApplications { get; set; }
        public int TotalScans { get; set; }
        public int ResolvedVulnerabilities { get; set; }
        public List<ActivityDto> RecentActivities { get; set; } = new();

        [BindProperty]
        public InputModel Input { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Prenumele este obligatoriu")]
            [StringLength(50, ErrorMessage = "Prenumele nu poate avea mai mult de {1} caractere")]
            [Display(Name = "Prenume")]
            public string FirstName { get; set; }

            [Required(ErrorMessage = "Numele este obligatoriu")]
            [StringLength(50, ErrorMessage = "Numele nu poate avea mai mult de {1} caractere")]
            [Display(Name = "Nume")]
            public string LastName { get; set; }

            [Required(ErrorMessage = "Email-ul este obligatoriu")]
            [EmailAddress(ErrorMessage = "Format email invalid")]
            [Display(Name = "Email")]
            public string Email { get; set; }

            [Phone(ErrorMessage = "Număr de telefon invalid")]
            [Display(Name = "Telefon")]
            public string PhoneNumber { get; set; }

            [StringLength(500, ErrorMessage = "Bio nu poate avea mai mult de {1} caractere")]
            [Display(Name = "Bio")]
            public string Bio { get; set; }

            [StringLength(100, ErrorMessage = "Numele companiei nu poate avea mai mult de {1} caractere")]
            [Display(Name = "Companie")]
            public string Company { get; set; }

            [StringLength(100, ErrorMessage = "Poziția nu poate avea mai mult de {1} caractere")]
            [Display(Name = "Poziție")]
            public string JobTitle { get; set; }
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound();
            }

            // Load user profile
            UserProfile = new UserProfileDto
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                FullName = user.FullName,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                Role = user.Role.ToString(),
                IsActive = user.IsActive,
                CreatedAt = user.CreatedAt,
                LastLoginAt = user.LastLoginAt,
                Bio = "", // Add these fields to User model if needed
                Company = "",
                JobTitle = ""
            };

            // Populate input model
            Input = new InputModel
            {
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                Bio = UserProfile.Bio,
                Company = UserProfile.Company,
                JobTitle = UserProfile.JobTitle
            };

            // Load statistics (mock data for now)
            await LoadUserStatistics(userId);

            // Load recent activities
            await LoadRecentActivities(userId);

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                await LoadPageData();
                return Page();
            }

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound();
            }

            // Check if email is being changed and is unique
            if (Input.Email != user.Email)
            {
                var existingUser = await _userManager.FindByEmailAsync(Input.Email);
                if (existingUser != null && existingUser.Id != user.Id)
                {
                    ModelState.AddModelError("Input.Email", "Acest email este deja folosit.");
                    await LoadPageData();
                    return Page();
                }
            }

            // Update user information
            user.FirstName = Input.FirstName;
            user.LastName = Input.LastName;
            user.Email = Input.Email;
            user.UserName = Input.Email; // Keep username in sync with email
            user.PhoneNumber = Input.PhoneNumber;
            // Add Bio, Company, JobTitle to User model if needed

            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                _logger.LogInformation("User profile updated successfully for user {UserId}", userId);
                TempData["SuccessMessage"] = "Profilul a fost actualizat cu succes!";
                return RedirectToPage();
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            await LoadPageData();
            return Page();
        }

        private async Task LoadPageData()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user != null)
            {
                UserProfile = new UserProfileDto
                {
                    Id = user.Id,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    FullName = user.FullName,
                    Email = user.Email,
                    PhoneNumber = user.PhoneNumber,
                    Role = user.Role.ToString(),
                    IsActive = user.IsActive,
                    CreatedAt = user.CreatedAt,
                    LastLoginAt = user.LastLoginAt
                };

                await LoadUserStatistics(userId);
                await LoadRecentActivities(userId);
            }
        }

        private async Task LoadUserStatistics(string userId)
        {
            // Mock data for demonstration
            TotalApplications = 5;
            TotalScans = 23;
            ResolvedVulnerabilities = 18;

            // In a real implementation:
            /*
            TotalApplications = await _context.Applications
                .Where(a => a.UserId == userId && a.IsActive)
                .CountAsync();

            TotalScans = await _context.Scans
                .Where(s => s.Application.UserId == userId)
                .CountAsync();

            ResolvedVulnerabilities = await _context.Vulnerabilities
                .Where(v => v.Scan.Application.UserId == userId && 
                           v.Status == VulnerabilityStatus.Resolved)
                .CountAsync();
            */
        }

        private async Task LoadRecentActivities(string userId)
        {
            // Mock data for demonstration
            RecentActivities = new List<ActivityDto>
            {
                new ActivityDto
                {
                    Type = "scan_completed",
                    Description = "Scanare completată pentru Portal Web Principal",
                    CreatedAt = DateTime.Now.AddHours(-2)
                },
                new ActivityDto
                {
                    Type = "vulnerability_found",
                    Description = "3 vulnerabilități critice detectate în API Backend",
                    CreatedAt = DateTime.Now.AddHours(-5)
                },
                new ActivityDto
                {
                    Type = "app_added",
                    Description = "Aplicație nouă adăugată: Mobile Backend",
                    CreatedAt = DateTime.Now.AddDays(-1)
                },
                new ActivityDto
                {
                    Type = "report_generated",
                    Description = "Raport de securitate generat pentru Q4 2024",
                    CreatedAt = DateTime.Now.AddDays(-2)
                }
            };

            // In a real implementation, you would query an Activities table
            /*
            RecentActivities = await _context.Activities
                .Where(a => a.UserId == userId)
                .OrderByDescending(a => a.CreatedAt)
                .Take(10)
                .Select(a => new ActivityDto
                {
                    Type = a.Type,
                    Description = a.Description,
                    CreatedAt = a.CreatedAt
                })
                .ToListAsync();
            */
        }
    }

    // DTOs
    public class UserProfileDto
    {
        public string Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string FullName { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public string Role { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public string Bio { get; set; }
        public string Company { get; set; }
        public string JobTitle { get; set; }
    }

    public class ActivityDto
    {
        public string Type { get; set; }
        public string Description { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}