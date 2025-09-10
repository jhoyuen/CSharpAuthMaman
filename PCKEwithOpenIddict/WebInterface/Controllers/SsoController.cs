using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace WebInterface.Controllers
{
    [ApiController]
    [Route("api/sso")]
    public class SsoController : ControllerBase
    {
        private readonly ConfigurationManager<OpenIdConnectConfiguration> _configManager;

        public SsoController(ConfigurationManager<OpenIdConnectConfiguration> configManager)
        {
            _configManager = configManager;
        }

        [HttpPost("exchange")]
        public async Task<IActionResult> Exchange([FromBody] TokenDto dto)
        {
            if (string.IsNullOrEmpty(dto.IdToken))
                return BadRequest("id_token required");

            var openIdConfig = await _configManager.GetConfigurationAsync(CancellationToken.None);
            var validationParameters = new TokenValidationParameters
            {
                ValidIssuer = openIdConfig.Issuer,
                // Accept any audience for demo; tighten in production:
                ValidateAudience = false,
                IssuerSigningKeys = openIdConfig.SigningKeys,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true
            };

            var handler = new JwtSecurityTokenHandler();
            try
            {
                var principal = handler.ValidateToken(dto.IdToken, validationParameters, out var validatedToken);

                // Create local cookie session using claims from id_token
                var claims = principal.Claims.ToList();
                // Optional: map claims / keep only safe ones
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var userPrincipal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, userPrincipal,
                    new Microsoft.AspNetCore.Authentication.AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
                    });

                return Ok(new { success = true });
            }
            catch (SecurityTokenException ex)
            {
                return Unauthorized(new { error = "invalid_token", detail = ex.Message });
            }
        }

        public class TokenDto { public string IdToken { get; set; } = ""; }
    }
}
