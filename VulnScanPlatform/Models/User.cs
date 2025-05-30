// Models/User.cs
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace VulnScanPlatform.Models
{
    public class User : IdentityUser
    {
        [Required]
        [Display(Name = "Prenume")]
        [StringLength(50)]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Nume")]
        [StringLength(50)]
        public string LastName { get; set; } = string.Empty;

        [Display(Name = "Rol")]
        public UserRole Role { get; set; } = UserRole.RegisteredUser;

        [Display(Name = "Data Înregistrării")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [Display(Name = "Ultima Activitate")]
        public DateTime? LastLoginAt { get; set; }

        [Display(Name = "Activ")]
        public bool IsActive { get; set; } = true;

        [Display(Name = "Utilizator Sistem")]
        public bool IsSystemUser { get; set; } = false;

        [Display(Name = "Nume Complet")]
        public string FullName => $"{FirstName} {LastName}";
    }
}