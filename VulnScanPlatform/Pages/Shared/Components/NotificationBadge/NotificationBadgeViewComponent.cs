using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Threading.Tasks;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Pages.Shared.Components.NotificationBadge
{
    public class NotificationBadgeViewComponent : ViewComponent
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<User> _userManager;

        public NotificationBadgeViewComponent(ApplicationDbContext context, UserManager<User> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        public async Task<IViewComponentResult> InvokeAsync()
        {
            if (User.Identity.IsAuthenticated)
            {
                var userEmail = ((ClaimsPrincipal)User).FindFirstValue(ClaimTypes.Email);
                var notificationCount = await _context.ReportInvitations
                    .CountAsync(i => i.InvitedUserEmail == userEmail && !i.IsAccepted);

                return View(notificationCount);
            }
            return Content(string.Empty);
        }
    }
}