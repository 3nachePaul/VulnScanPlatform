using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Services
{
    public class UserClaimsPrincipalFactory : UserClaimsPrincipalFactory<User>
    {
        public UserClaimsPrincipalFactory(
            UserManager<User> userManager,
            IOptions<IdentityOptions> optionsAccessor)
            : base(userManager, optionsAccessor)
        {
        }

        protected override async Task<ClaimsIdentity> GenerateClaimsAsync(User user)
        {
            var identity = await base.GenerateClaimsAsync(user);

            // Add custom claims
            identity.AddClaim(new Claim("Name", user.FullName));
            identity.AddClaim(new Claim("Role", user.Role.ToString()));
            identity.AddClaim(new Claim("IsSystemUser", user.IsSystemUser.ToString()));
            identity.AddClaim(new Claim("UserId", user.Id));

            return identity;
        }
    }
}