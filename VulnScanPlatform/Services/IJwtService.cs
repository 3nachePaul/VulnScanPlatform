using VulnScanPlatform.Models;

namespace VulnScanPlatform.Services
{
    public interface IJwtService
    {
        string GenerateToken(User user);
        bool ValidateToken(string token);
    }
}