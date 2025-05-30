// Models/UserRole.cs
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace VulnScanPlatform.Models
{
    public enum UserRole
    {
        [Display(Name = "Vizitator")]
        Visitor = 0,

        [Display(Name = "Utilizator Înregistrat")]
        RegisteredUser = 1,

        [Display(Name = "Analist Securitate")]
        SecurityAnalyst = 2,

        [Display(Name = "Administrator")]
        Administrator = 3
    }
}
