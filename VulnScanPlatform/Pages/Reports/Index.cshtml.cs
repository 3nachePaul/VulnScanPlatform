using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Pages.Reports
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly VulnScanPlatform.Models.ApplicationDbContext _context;

        public IndexModel(VulnScanPlatform.Models.ApplicationDbContext context)
        {
            _context = context;
        }

        public IList<Report> Report { get; set; }

        public async Task OnGetAsync()
        {
            Report = await _context.Reports
                .Include(r => r.Scan)
                .ThenInclude(s => s.Application).ToListAsync();
        }
    }
}