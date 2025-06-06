using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using VulnScanPlatform.Models;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace VulnScanPlatform.Pages.Scans
{
    [Authorize]
    public class DetailsModel : PageModel
    {
        private readonly VulnScanPlatform.Models.ApplicationDbContext _context;

        public DetailsModel(VulnScanPlatform.Models.ApplicationDbContext context)
        {
            _context = context;
        }

        public Scan Scan { get; set; }

        public async Task<IActionResult> OnGetAsync(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            // Preluam scanarea si includem datele despre aplicatie si vulnerabilitati
            Scan = await _context.Scans
                .Include(s => s.Application)
                .Include(s => s.Vulnerabilities)
                .AsNoTracking()
                .FirstOrDefaultAsync(m => m.Id == id);

            if (Scan == null)
            {
                return NotFound();
            }
            return Page();
        }
    }
}