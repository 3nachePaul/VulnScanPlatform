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
    public class SettingsModel : PageModel
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ILogger<SettingsModel> _logger;

        public SettingsModel(
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            ILogger<SettingsModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [BindProperty]
        public GeneralSettingsModel GeneralSettings { get; set; }

        [BindProperty]
        public SecuritySettingsModel SecuritySettings { get; set; }

        [BindProperty]
        public NotificationSettingsModel NotificationSettings { get; set; }

        [BindProperty]
        public PrivacySettingsModel PrivacySettings { get; set; }

        public List<SessionDto> ActiveSessions { get; set; } = new();

        public class GeneralSettingsModel
        {
            public string Language { get; set; } = "ro";
            public string TimeZone { get; set; } = "Europe/Bucharest";
            public string DateFormat { get; set; } = "dd/MM/yyyy";
        }

        public class SecuritySettingsModel
        {
            public bool TwoFactorEnabled { get; set; }
            public DateTime? LastPasswordChange { get; set; }
        }

        public class NotificationSettingsModel
        {
            [Display(Name = "Vulnerabilități critice")]
            public bool EmailOnCriticalVulnerability { get; set; } = true;

            [Display(Name = "Scanare completată")]
            public bool EmailOnScanComplete { get; set; } = true;

            [Display(Name = "Raport săptămânal")]
            public bool EmailWeeklyReport { get; set; } = true;

            [Display(Name = "Raport lunar")]
            public bool EmailMonthlyReport { get; set; } = true;

            [Display(Name = "Notificări în aplicație")]
            public bool InAppNotifications { get; set; } = true;
        }

        public class PrivacySettingsModel
        {
            public string ProfileVisibility { get; set; } = "team";

            [Display(Name = "Afișează email")]
            public bool ShowEmail { get; set; }

            [Display(Name = "Afișează activitate")]
            public bool ShowActivity { get; set; } = true;

            [Display(Name = "Afișează statistici")]
            public bool ShowStatistics { get; set; } = true;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await GetCurrentUserAsync();
            if (user == null)
            {
                return NotFound();
            }

            // Load user settings
            await LoadUserSettings(user);

            // Load active sessions
            LoadActiveSessions();

            return Page();
        }

        public async Task<IActionResult> OnPostUpdateGeneralAsync()
        {
            var user = await GetCurrentUserAsync();
            if (user == null)
            {
                return NotFound();
            }

            // Save general settings
            // In a real app, you'd save these to a UserSettings table or user claims
            _logger.LogInformation("General settings updated for user {UserId}", user.Id);

            TempData["SuccessMessage"] = "Setările generale au fost salvate cu succes!";
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostUpdateNotificationsAsync()
        {
            var user = await GetCurrentUserAsync();
            if (user == null)
            {
                return NotFound();
            }

            // Save notification preferences
            _logger.LogInformation("Notification settings updated for user {UserId}", user.Id);

            TempData["SuccessMessage"] = "Preferințele de notificare au fost salvate!";
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostUpdatePrivacyAsync()
        {
            var user = await GetCurrentUserAsync();
            if (user == null)
            {
                return NotFound();
            }

            // Save privacy settings
            _logger.LogInformation("Privacy settings updated for user {UserId}", user.Id);

            TempData["SuccessMessage"] = "Setările de confidențialitate au fost salvate!";
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostChangePasswordAsync(string currentPassword, string newPassword, string confirmPassword)
        {
            var user = await GetCurrentUserAsync();
            if (user == null)
            {
                return NotFound();
            }

            if (newPassword != confirmPassword)
            {
                TempData["ErrorMessage"] = "Parolele nu se potrivesc!";
                return RedirectToPage();
            }

            var changePasswordResult = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
            if (changePasswordResult.Succeeded)
            {
                await _signInManager.RefreshSignInAsync(user);
                _logger.LogInformation("User changed their password successfully.");

                TempData["SuccessMessage"] = "Parola a fost schimbată cu succes!";
                return RedirectToPage();
            }

            var errors = string.Join(", ", changePasswordResult.Errors.Select(e => e.Description));
            TempData["ErrorMessage"] = $"Eroare la schimbarea parolei: {errors}";
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostRevokeSessionAsync(string sessionId)
        {
            var user = await GetCurrentUserAsync();
            if (user == null)
            {
                return NotFound();
            }

            // In a real app, you'd revoke the specific session
            _logger.LogInformation("Session {SessionId} revoked for user {UserId}", sessionId, user.Id);

            TempData["SuccessMessage"] = "Sesiunea a fost revocată!";
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostRevokeAllSessionsAsync()
        {
            var user = await GetCurrentUserAsync();
            if (user == null)
            {
                return NotFound();
            }

            // Update security stamp to invalidate all existing tokens/sessions
            await _userManager.UpdateSecurityStampAsync(user);
            await _signInManager.RefreshSignInAsync(user);

            _logger.LogInformation("All sessions revoked for user {UserId}", user.Id);

            TempData["SuccessMessage"] = "Toate sesiunile au fost revocate!";
            return RedirectToPage();
        }

        private async Task<User> GetCurrentUserAsync()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            return await _userManager.FindByIdAsync(userId);
        }

        private async Task LoadUserSettings(User user)
        {
            // Load general settings
            GeneralSettings = new GeneralSettingsModel
            {
                Language = "ro",
                TimeZone = "Europe/Bucharest",
                DateFormat = "dd/MM/yyyy"
            };

            // Load security settings
            SecuritySettings = new SecuritySettingsModel
            {
                TwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user),
                LastPasswordChange = null // Would come from audit log
            };

            // Load notification settings
            NotificationSettings = new NotificationSettingsModel
            {
                EmailOnCriticalVulnerability = true,
                EmailOnScanComplete = true,
                EmailWeeklyReport = true,
                EmailMonthlyReport = true,
                InAppNotifications = true
            };

            // Load privacy settings
            PrivacySettings = new PrivacySettingsModel
            {
                ProfileVisibility = "team",
                ShowEmail = false,
                ShowActivity = true,
                ShowStatistics = true
            };
        }

        private void LoadActiveSessions()
        {
            // Mock data for demonstration
            ActiveSessions = new List<SessionDto>
            {
                new SessionDto
                {
                    Id = "current",
                    Browser = "Chrome 120",
                    Device = "Windows 11",
                    DeviceType = "Desktop",
                    Location = "București, România",
                    IpAddress = "86.123.45.67",
                    LastActivity = DateTime.Now,
                    IsCurrent = true
                },
                new SessionDto
                {
                    Id = "mobile1",
                    Browser = "Safari",
                    Device = "iPhone 14",
                    DeviceType = "Mobile",
                    Location = "Cluj-Napoca, România",
                    IpAddress = "86.123.45.68",
                    LastActivity = DateTime.Now.AddHours(-3),
                    IsCurrent = false
                }
            };
        }
    }

    public class SessionDto
    {
        public string Id { get; set; }
        public string Browser { get; set; }
        public string Device { get; set; }
        public string DeviceType { get; set; }
        public string Location { get; set; }
        public string IpAddress { get; set; }
        public DateTime LastActivity { get; set; }
        public bool IsCurrent { get; set; }
    }
}