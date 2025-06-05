using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Pages.Admin.Users
{
    [Authorize(Policy = "AdminPolicy")]
    public class CreateModel : PageModel
    {
        private readonly UserManager<User> _userManager;
        private readonly ILogger<CreateModel> _logger;
        private readonly IConfiguration _configuration;

        public CreateModel(
            UserManager<User> userManager,
            ILogger<CreateModel> logger,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _logger = logger;
            _configuration = configuration;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Prenumele este obligatoriu")]
            [StringLength(50, ErrorMessage = "Prenumele nu poate avea mai mult de {1} caractere")]
            [Display(Name = "Prenume")]
            public string FirstName { get; set; }

            [Required(ErrorMessage = "Numele este obligatoriu")]
            [StringLength(50, ErrorMessage = "Numele nu poate avea mai mult de {1} caractere")]
            [Display(Name = "Nume")]
            public string LastName { get; set; }

            [Required(ErrorMessage = "Email-ul este obligatoriu")]
            [EmailAddress(ErrorMessage = "Format email invalid")]
            [Display(Name = "Email")]
            public string Email { get; set; }

            [Phone(ErrorMessage = "Număr de telefon invalid")]
            [Display(Name = "Telefon")]
            public string PhoneNumber { get; set; }

            [Required(ErrorMessage = "Rolul este obligatoriu")]
            [Display(Name = "Rol")]
            public UserRole Role { get; set; }

            [Required(ErrorMessage = "Parola este obligatorie")]
            [StringLength(100, ErrorMessage = "Parola trebuie să aibă cel puțin {2} și maxim {1} caractere.", MinimumLength = 8)]
            [DataType(DataType.Password)]
            [Display(Name = "Parolă")]
            public string Password { get; set; }

            [Display(Name = "Cont Activ")]
            public bool IsActive { get; set; } = true;

            [Display(Name = "Email Confirmat")]
            public bool EmailConfirmed { get; set; } = true;

            [Display(Name = "Trimite Email de Bun Venit")]
            public bool SendWelcomeEmail { get; set; } = true;
        }

        public void OnGet()
        {
            Input = new InputModel
            {
                IsActive = true,
                EmailConfirmed = true,
                SendWelcomeEmail = true
            };
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Check if email already exists
            var existingUser = await _userManager.FindByEmailAsync(Input.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("Input.Email", "Un utilizator cu acest email există deja.");
                return Page();
            }

            var user = new User
            {
                UserName = Input.Email,
                Email = Input.Email,
                FirstName = Input.FirstName,
                LastName = Input.LastName,
                PhoneNumber = Input.PhoneNumber,
                Role = Input.Role,
                IsActive = Input.IsActive,
                EmailConfirmed = Input.EmailConfirmed,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, Input.Password);

            if (result.Succeeded)
            {
                _logger.LogInformation("Admin {AdminId} created new user {UserId} with role {Role}",
                    _userManager.GetUserId(User), user.Id, user.Role);

                // Send welcome email if requested
                if (Input.SendWelcomeEmail)
                {
                    // TODO: Implement email service
                    _logger.LogInformation("Welcome email would be sent to {Email}", user.Email);
                }

                TempData["SuccessMessage"] = $"Utilizatorul {user.FullName} a fost creat cu succes!";
                return RedirectToPage("./Index");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }
    }
}