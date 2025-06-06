using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using VulnScanPlatform.Models;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace VulnScanPlatform.Pages.Reports
{
    [Authorize]
    public class DeleteModel : PageModel
    {
        private readonly VulnScanPlatform.Models.ApplicationDbContext _context;

        public DeleteModel(VulnScanPlatform.Models.ApplicationDbContext context)
        {
            _context = context;
        }

        [BindProperty]
        public Report Report { get; set; }

        public async Task<IActionResult> OnGetAsync(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            Report = await _context.Reports
                .Include(r => r.Scan)
                .ThenInclude(s => s.Application)
                .FirstOrDefaultAsync(m => m.Id == id);

            if (Report == null)
            {
                return NotFound();
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            Report = await _context.Reports.FindAsync(id);

            if (Report != null)
            {
                _context.Reports.Remove(Report);
                await _context.SaveChangesAsync();
            }

            return RedirectToPage("./Index");
        }
    }
}