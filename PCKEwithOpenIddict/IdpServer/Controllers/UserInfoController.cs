using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdpServer.Controllers
{
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public class UserinfoController : Controller
    {
        [HttpGet("/connect/userinfo"), HttpPost("/connect/userinfo")]
        public IActionResult Userinfo()
        {
            var claims = User.Claims.ToDictionary(c => c.Type, c => c.Value);

            return Ok(new
            {
                sub = claims[Claims.Subject],
                name = claims.ContainsKey(Claims.Name) ? claims[Claims.Name] : null,
                email = claims.ContainsKey(Claims.Email) ? claims[Claims.Email] : null
            });
        }
    }
}
