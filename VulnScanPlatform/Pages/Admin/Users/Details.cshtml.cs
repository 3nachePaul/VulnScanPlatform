using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Pages.Admin.Users
{
    [Authorize(Policy = "AdminPolicy")]
    public class DetailsModel : PageModel
    {
        private readonly ApplicationDbContext _context;

        public DetailsModel(ApplicationDbContext context)
        {
            _context = context;
        }

        public User UserDetails { get; set; }

        public async Task<IActionResult> OnGetAsync(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            UserDetails = await _context.Users
                .FirstOrDefaultAsync(u => u.Id == id);

            if (UserDetails == null)
            {
                return NotFound();
            }

            // Return the partial view for AJAX requests
            if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
            {
                return Partial("_UserDetails", UserDetails);
            }

            return Page();
        }
    }
}