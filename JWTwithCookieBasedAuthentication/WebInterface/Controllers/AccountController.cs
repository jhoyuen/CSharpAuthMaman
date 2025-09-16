using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace WebInterface.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        public async Task<IActionResult> ExternalLogin(string token)
        {
            if (string.IsNullOrEmpty(token))
                return BadRequest("Missing token");

            token = Uri.UnescapeDataString(token).Trim();

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("super_secret_dev_key_123456789012345"));

            var handler = new JwtSecurityTokenHandler();

            var jwt = handler.ReadToken(token);

            var principal = handler.ValidateToken(token,
                new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromSeconds(30),
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = "JwtAuthIssuer",
                    ValidAudience = "Inception",
                    IssuerSigningKey = key
                },
                out _);

            if (principal == null)
                return Unauthorized();

            // Create auth cookie
            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(principal.Identity!),
                new AuthenticationProperties { IsPersistent = true });

            return RedirectToAction("SecurePage", "Home");
        }

        [HttpPost]
        [Route("Account/ExternalLoginPost")]
        public async Task<IActionResult> ExternalLoginPost([FromForm] string token)
        {
            if (string.IsNullOrEmpty(token))
                return BadRequest("Missing token");

            var handler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal;

            try
            {
                principal = handler.ValidateToken(token,
                    new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = false,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.FromSeconds(30),
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = "JwtAuthIssuer",
                        ValidAudience = "Inception",
                        IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes("super_secret_dev_key_123456789012345"))
                    }, out _);
            }
            catch
            {
                return Unauthorized();
            }

            // Issue cookie
            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(principal.Identity!),
                new AuthenticationProperties { IsPersistent = true });

            return Ok("Cookie issued");
        }

        [HttpGet]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }
    }
}
