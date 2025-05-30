using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<User> _userManager;
        private readonly ApplicationDbContext _context;

        public UserService(UserManager<User> userManager, ApplicationDbContext context)
        {
            _userManager = userManager;
            _context = context;
        }

        public async Task<IEnumerable<User>> GetAllUsersAsync()
        {
            return await _context.Users
                .Where(u => u.IsActive)
                .OrderBy(u => u.LastName)
                .ThenBy(u => u.FirstName)
                .ToListAsync();
        }

        public async Task<User?> GetUserByIdAsync(string id)
        {
            return await _userManager.FindByIdAsync(id);
        }

        public async Task<bool> UpdateUserAsync(User user)
        {
            if (user.IsSystemUser)
                return false;

            var result = await _userManager.UpdateAsync(user);
            return result.Succeeded;
        }

        public async Task<bool> DeleteUserAsync(string id)
        {
            var user = await GetUserByIdAsync(id);

            if (user == null || user.IsSystemUser)
                return false;

            user.IsActive = false;
            var result = await _userManager.UpdateAsync(user);
            return result.Succeeded;
        }

        public async Task<bool> CanModifyUserAsync(string userId)
        {
            var user = await GetUserByIdAsync(userId);
            return user != null && !user.IsSystemUser;
        }
    }
}