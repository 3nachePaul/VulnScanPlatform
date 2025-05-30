using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using VulnScanPlatform.Models;
using VulnScanPlatform.Services;

namespace VulnScanPlatform.Pages.Admin.Users
{
    [Authorize(Policy = "AdminPolicy")]
    public class IndexModel : PageModel
    {
        private readonly UserManager<User> _userManager;
        private readonly IUserService _userService;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<IndexModel> _logger;
        private const int PageSize = 10;

        public IndexModel(
            UserManager<User> userManager,
            IUserService userService,
            ApplicationDbContext context,
            ILogger<IndexModel> logger)
        {
            _userManager = userManager;
            _userService = userService;
            _context = context;
            _logger = logger;
        }

        public List<User> Users { get; set; } = new();

        // Statistics
        public int TotalUsers { get; set; }
        public int ActiveUsers { get; set; }
        public int AdminCount { get; set; }
        public int NewUsersThisMonth { get; set; }

        // Search and Filter
        [BindProperty(SupportsGet = true)]
        public string SearchTerm { get; set; }

        [BindProperty(SupportsGet = true)]
        public string RoleFilter { get; set; }

        [BindProperty(SupportsGet = true)]
        public string StatusFilter { get; set; }

        [BindProperty(SupportsGet = true)]
        public string SortBy { get; set; } = "name";

        // Pagination
        [BindProperty(SupportsGet = true)]
        public int CurrentPage { get; set; } = 1;
        public int TotalPages { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            // Load statistics
            await LoadStatistics();

            // Build query
            var query = _context.Users.AsQueryable();

            // Apply search filter
            if (!string.IsNullOrWhiteSpace(SearchTerm))
            {
                query = query.Where(u =>
                    u.FirstName.Contains(SearchTerm) ||
                    u.LastName.Contains(SearchTerm) ||
                    u.Email.Contains(SearchTerm));
            }

            // Apply role filter
            if (!string.IsNullOrWhiteSpace(RoleFilter) && Enum.TryParse<VulnScanPlatform.Models.UserRole>(RoleFilter, out VulnScanPlatform.Models.UserRole role))
            {
                query = query.Where(u => u.Role == role);
            }

            // Apply status filter
            if (!string.IsNullOrWhiteSpace(StatusFilter))
            {
                if (StatusFilter == "active")
                    query = query.Where(u => u.IsActive);
                else if (StatusFilter == "inactive")
                    query = query.Where(u => !u.IsActive);
            }

            // Apply sorting
            query = SortBy switch
            {
                "email" => query.OrderBy(u => u.Email),
                "role" => query.OrderBy(u => u.Role).ThenBy(u => u.LastName),
                "created" => query.OrderByDescending(u => u.CreatedAt),
                "lastlogin" => query.OrderByDescending(u => u.LastLoginAt ?? DateTime.MinValue),
                _ => query.OrderBy(u => u.LastName).ThenBy(u => u.FirstName)
            };

            // Count total for pagination
            var totalCount = await query.CountAsync();
            TotalPages = (int)Math.Ceiling(totalCount / (double)PageSize);

            // Ensure current page is valid
            if (CurrentPage < 1) CurrentPage = 1;
            if (CurrentPage > TotalPages && TotalPages > 0) CurrentPage = TotalPages;

            // Get paginated results
            Users = await query
                .Skip((CurrentPage - 1) * PageSize)
                .Take(PageSize)
                .ToListAsync();

            return Page();
        }

        public async Task<IActionResult> OnPostDeleteAsync(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                TempData["ErrorMessage"] = "ID utilizator invalid!";
                return RedirectToPage();
            }

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                TempData["ErrorMessage"] = "Utilizatorul nu a fost găsit!";
                return RedirectToPage();
            }

            if (user.IsSystemUser)
            {
                TempData["ErrorMessage"] = "Utilizatorii de sistem nu pot fi șterși!";
                return RedirectToPage();
            }

            // Check if trying to delete self
            if (user.Id == _userManager.GetUserId(User))
            {
                TempData["ErrorMessage"] = "Nu te poți șterge pe tine însuți!";
                return RedirectToPage();
            }

            // Soft delete - just mark as inactive
            user.IsActive = false;
            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                _logger.LogInformation("User {UserId} was deleted by {AdminId}", id, _userManager.GetUserId(User));
                TempData["SuccessMessage"] = $"Utilizatorul {user.FullName} a fost șters cu succes!";
            }
            else
            {
                TempData["ErrorMessage"] = "Eroare la ștergerea utilizatorului!";
            }

            return RedirectToPage();
        }

        private async Task LoadStatistics()
        {
            var now = DateTime.UtcNow;
            var startOfMonth = new DateTime(now.Year, now.Month, 1);

            TotalUsers = await _context.Users.CountAsync();
            ActiveUsers = await _context.Users.Where(u => u.IsActive).CountAsync();
            // Use fully qualified name for UserRole.Administrator
            AdminCount = await _context.Users.Where(u => u.Role == VulnScanPlatform.Models.UserRole.Administrator).CountAsync();
            NewUsersThisMonth = await _context.Users
                .Where(u => u.CreatedAt >= startOfMonth)
                .CountAsync();
        }

        public async Task<IActionResult> OnGetDetailsAsync(string id)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == id);
            if (user == null)
            {
                return NotFound();
            }

            return Partial("_UserDetails", user);
        }
    }
}