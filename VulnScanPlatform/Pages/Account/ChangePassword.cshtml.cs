using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Pages.Account
{
    [Authorize]
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ILogger<ChangePasswordModel> _logger;

        public ChangePasswordModel(
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            ILogger<ChangePasswordModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Parola curentă este obligatorie")]
            [DataType(DataType.Password)]
            [Display(Name = "Parola Curentă")]
            public string CurrentPassword { get; set; }

            [Required(ErrorMessage = "Parola nouă este obligatorie")]
            [StringLength(100, ErrorMessage = "Parola trebuie să aibă cel puțin {2} și maxim {1} caractere.", MinimumLength = 8)]
            [DataType(DataType.Password)]
            [Display(Name = "Parola Nouă")]
            public string NewPassword { get; set; }

            [DataType(DataType.Password)]
            [Display(Name = "Confirmă Parola Nouă")]
            [Compare("NewPassword", ErrorMessage = "Parolele nu se potrivesc.")]
            public string ConfirmPassword { get; set; }
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var changePasswordResult = await _userManager.ChangePasswordAsync(user, Input.CurrentPassword, Input.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                foreach (var error in changePasswordResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return Page();
            }

            await _signInManager.RefreshSignInAsync(user);
            _logger.LogInformation("User changed their password successfully.");

            TempData["SuccessMessage"] = "Parola ta a fost schimbată cu succes!";
            return RedirectToPage("/Account/Profile");
        }
    }
}