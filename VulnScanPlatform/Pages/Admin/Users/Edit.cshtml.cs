using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Pages.Admin.Users
{
    [Authorize(Policy = "AdminPolicy")]
    public class EditModel : PageModel
    {
        private readonly UserManager<User> _userManager;
        private readonly ILogger<EditModel> _logger;

        public EditModel(
            UserManager<User> userManager,
            ILogger<EditModel> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public User UserToEdit { get; set; }

        public class InputModel
        {
            [Required]
            public string Id { get; set; }

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

            [Display(Name = "Cont Activ")]
            public bool IsActive { get; set; }

            [Display(Name = "Email Confirmat")]
            public bool EmailConfirmed { get; set; }

            [Display(Name = "Autentificare în Doi Pași")]
            public bool TwoFactorEnabled { get; set; }
        }

        public async Task<IActionResult> OnGetAsync(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            UserToEdit = await _userManager.FindByIdAsync(id);

            if (UserToEdit == null)
            {
                return NotFound();
            }

            Input = new InputModel
            {
                Id = UserToEdit.Id,
                FirstName = UserToEdit.FirstName,
                LastName = UserToEdit.LastName,
                Email = UserToEdit.Email,
                PhoneNumber = UserToEdit.PhoneNumber,
                Role = UserToEdit.Role,
                IsActive = UserToEdit.IsActive,
                EmailConfirmed = UserToEdit.EmailConfirmed,
                TwoFactorEnabled = UserToEdit.TwoFactorEnabled
            };

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                UserToEdit = await _userManager.FindByIdAsync(Input.Id);
                return Page();
            }

            var user = await _userManager.FindByIdAsync(Input.Id);
            if (user == null)
            {
                return NotFound();
            }

            // Check if trying to edit own admin account role
            if (user.Id == _userManager.GetUserId(User) && Input.Role != UserRole.Administrator)
            {
                ModelState.AddModelError(string.Empty, "Nu îți poți schimba propriul rol de administrator!");
                UserToEdit = user;
                return Page();
            }

            // Check if email is being changed and is unique
            if (Input.Email != user.Email)
            {
                var existingUser = await _userManager.FindByEmailAsync(Input.Email);
                if (existingUser != null && existingUser.Id != user.Id)
                {
                    ModelState.AddModelError("Input.Email", "Acest email este deja folosit de alt utilizator.");
                    UserToEdit = user;
                    return Page();
                }
            }

            // Prevent editing system users (except email and active status)
            if (!user.IsSystemUser)
            {
                user.FirstName = Input.FirstName;
                user.LastName = Input.LastName;
                user.Role = Input.Role;
            }

            user.Email = Input.Email;
            user.UserName = Input.Email; // Keep username in sync with email
            user.PhoneNumber = Input.PhoneNumber;
            user.IsActive = Input.IsActive;
            user.EmailConfirmed = Input.EmailConfirmed;
            user.TwoFactorEnabled = Input.TwoFactorEnabled;

            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                _logger.LogInformation("Admin {AdminId} updated user {UserId}",
                    _userManager.GetUserId(User), user.Id);

                TempData["SuccessMessage"] = $"Utilizatorul {user.FullName} a fost actualizat cu succes!";
                return RedirectToPage("./Index");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            UserToEdit = user;
            return Page();
        }

        public async Task<IActionResult> OnPostResetPasswordAsync(string userId, string newPassword, bool requireChange)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            // Remove current password
            var removePasswordResult = await _userManager.RemovePasswordAsync(user);
            if (!removePasswordResult.Succeeded)
            {
                TempData["ErrorMessage"] = "Eroare la resetarea parolei.";
                return RedirectToPage(new { id = userId });
            }

            // Add new password
            var addPasswordResult = await _userManager.AddPasswordAsync(user, newPassword);
            if (addPasswordResult.Succeeded)
            {
                _logger.LogInformation("Admin {AdminId} reset password for user {UserId}",
                    _userManager.GetUserId(User), userId);

                // TODO: If requireChange is true, mark user to change password on next login

                TempData["SuccessMessage"] = "Parola a fost resetată cu succes!";
            }
            else
            {
                var errors = string.Join(", ", addPasswordResult.Errors.Select(e => e.Description));
                TempData["ErrorMessage"] = $"Eroare la setarea parolei: {errors}";
            }

            return RedirectToPage(new { id = userId });
        }

        public async Task<IActionResult> OnPostSendPasswordResetAsync([FromBody] SendPasswordResetRequest request)
        {
            var user = await _userManager.FindByIdAsync(request.UserId);
            if (user == null)
            {
                return new JsonResult(new { success = false, message = "Utilizator negăsit." });
            }

            // TODO: Implement email service to send password reset
            _logger.LogInformation("Password reset email would be sent to {Email}", user.Email);

            return new JsonResult(new
            {
                success = true,
                message = $"Email de resetare parolă trimis către {user.Email}"
            });
        }

        public class SendPasswordResetRequest
        {
            public string UserId { get; set; }
        }
    }
}