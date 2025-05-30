using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;

        public LoginModel(SignInManager<User> signInManager, UserManager<User> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public string? ReturnUrl { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Email-ul este obligatoriu")]
            [EmailAddress(ErrorMessage = "Format email invalid")]
            [Display(Name = "Email")]
            public string Email { get; set; } = string.Empty;

            [Required(ErrorMessage = "Parola este obligatorie")]
            [DataType(DataType.Password)]
            [Display(Name = "Parolă")]
            public string Password { get; set; } = string.Empty;

            [Display(Name = "Ține-mă minte")]
            public bool RememberMe { get; set; }
        }

        public void OnGet(string? returnUrl = null)
        {
            // Dacă utilizatorul este deja logat, du-l la Dashboard
            if (User.Identity?.IsAuthenticated == true)
            {
                Response.Redirect("/Dashboard");
                return;
            }

            // Setează Dashboard ca destinație default după login
            ReturnUrl = returnUrl ?? "/Dashboard";
        }

        public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
        {
            // FORȚEAZĂ redirecționarea către Dashboard
            returnUrl = "/Dashboard";
            ReturnUrl = returnUrl;

            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(Input.Email);

                if (user != null && user.IsActive)
                {
                    var result = await _signInManager.PasswordSignInAsync(
                        user.UserName ?? string.Empty,
                        Input.Password,
                        Input.RememberMe,
                        lockoutOnFailure: false);

                    if (result.Succeeded)
                    {
                        user.LastLoginAt = DateTime.UtcNow;
                        await _userManager.UpdateAsync(user);

                        // Debug: Log successful login
                        Console.WriteLine($"✅ LOGIN SUCCESS - Redirecting to: {returnUrl}");

                        // FORȚEAZĂ redirect la Dashboard
                        return Redirect("/Dashboard");
                    }
                }

                ModelState.AddModelError(string.Empty, "Email sau parolă incorectă.");
            }

            return Page();
        }
    }
}