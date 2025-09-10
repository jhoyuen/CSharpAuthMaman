using IdpServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdpServer.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<AppUser> _signInMgr;
        private readonly UserManager<AppUser> _userMgr;

        public AccountController(SignInManager<AppUser> signInMgr, UserManager<AppUser> userMgr)
        {
            _signInMgr = signInMgr;
            _userMgr = userMgr;
        }

        [HttpGet("/Account/Login")]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View(new LoginViewModel { ReturnUrl = returnUrl });
        }

        [HttpPost("/Account/Login")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userMgr.FindByNameAsync(model.Username);
            if (user != null)
            {
                var result = await _signInMgr.PasswordSignInAsync(
                    user,
                    model.Password,
                    isPersistent: false,
                    lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    // Always redirect back to the OIDC flow if provided
                    if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
                        return Redirect(model.ReturnUrl);

                    // Fallback: go home
                    return RedirectToAction("Login", "Account");
                }
            }

            ModelState.AddModelError("", "Invalid login attempt.");
            return View(model);
        }

        [HttpPost("/Account/Logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInMgr.SignOutAsync();
            return RedirectToAction("Login", "Account");
        }
    }
}
