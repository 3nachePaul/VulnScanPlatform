using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using VulnScanPlatform.Models; // Asigură-te că namespace-ul pentru User este corect

namespace VulnScanPlatform.Pages.Shared.Components.LoginPartial
{
    public class LoginPartialViewComponent : ViewComponent
    {
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;

        // Constructorul primește serviciile necesare prin injecție de dependențe
        public LoginPartialViewComponent(SignInManager<User> signInManager, UserManager<User> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        // Metoda InvokeAsync va fi apelată pentru a reda componenta
        // Aceasta poate returna direct vederea, sau poate pregăti un model simplu pentru vedere
        public IViewComponentResult Invoke()
        {
            // Nu mai este nevoie să pasezi un PageModel complex.
            // Logica de afișare (if user signed in etc.) va fi în vedere sau aici.
            // Pentru _LoginPartial standard, vederea poate accesa SignInManager și UserManager
            // direct prin @inject dacă este necesar, sau putem pasa date simple.
            return View(); // Implicit va căuta vederea "Default.cshtml" în folderul specificat mai jos
        }
    }
}