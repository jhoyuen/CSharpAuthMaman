using IdpServer.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using System.Collections.Concurrent;

namespace IdpServer.Controllers
{
    public class AccountController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _config;

        private readonly SignInManager<AppUser> _signInMgr;
        private readonly UserManager<AppUser> _userMgr;

        // In-memory one-time session tokens (demo). Use a proper store in prod.
        private static ConcurrentDictionary<string, (string subject, string name, string email, DateTime expires)> oneTimeSessions = new ConcurrentDictionary<string, (string subject, string name, string email, DateTime expires)>();
        public AccountController(
            IHttpClientFactory httpClientFactory,
            IConfiguration config,
            SignInManager<AppUser> signInMgr,
            UserManager<AppUser> userMgr)
        {
            _httpClientFactory = httpClientFactory;
            _config = config;

            _signInMgr = signInMgr;
            _userMgr = userMgr;
        }

        [HttpGet("/account/login")]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View(new LoginViewModel { ReturnUrl = returnUrl });
        }

        [HttpPost("/account/login")]
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

        [HttpPost("/account/logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInMgr.SignOutAsync();
            return RedirectToAction("Login", "Account");
        }

        [HttpPost("/account/sessions")]
        public async Task<IResult> Sessions([FromBody] LoginViewModel loginViewModel)
        {
            if (loginViewModel is null)
                return Results.BadRequest();

            var user = await _userMgr.FindByNameAsync(loginViewModel.Username);
            if (user == null) return Results.Unauthorized();


            var result = await _signInMgr.PasswordSignInAsync(
                user,
                loginViewModel.Password,
                isPersistent: false,
                lockoutOnFailure: false);


            if (!result.Succeeded)
                return Results.Unauthorized();

            // create one-time session token (short-lived)
            var token = Guid.NewGuid().ToString("N");
            oneTimeSessions[token] = (subject: user.Id.ToString(), name: user.UserName, email: user.Email, expires: DateTime.UtcNow.AddMinutes(2));

            return Results.Ok(new SessionResult(SessionToken: token, ExpiresIn:120));
        }

        [HttpGet("/account/sso")]
        public async Task<IResult> SingleSignOn([FromQuery] SSOModel ssoModel)
        {
            if (string.IsNullOrEmpty(ssoModel.SessionToken) || string.IsNullOrEmpty(ssoModel.ReturnUrl))
                return Results.BadRequest("Missing token or returnUrl");

            if (!oneTimeSessions.TryRemove(ssoModel.SessionToken, out var entry))
                return Results.BadRequest("Invalid or used token");

            if (entry.expires < DateTime.UtcNow)
                return Results.BadRequest("Session token expired");

            var identity = new ClaimsIdentity(
                authenticationType: CookieAuthenticationDefaults.AuthenticationScheme);

            identity.AddClaim(Claims.Subject, entry.subject);
            identity.AddClaim(Claims.Name, entry.name);
            identity.AddClaim(Claims.Email, entry.email);

            // mark which claims go into which token
            identity.SetDestinations(claim =>
            {
                if (claim.Type is Claims.Name or Claims.Email)
                    return new[] { Destinations.AccessToken, Destinations.IdentityToken };

                return new[] { Destinations.AccessToken };
            });

            var principal = new ClaimsPrincipal(identity);
            // Sign-in -> sets the cookie in the browser
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

            // Redirect to original authorize URL (which will now see cookie and issue code)
            return Results.Redirect(ssoModel.ReturnUrl);
        }

        [HttpPost("/account/exchange-pkce")]
        public async Task<IActionResult> ExchangePkce([FromBody] PkceExchangeRequest req)
        {
            var user = await _userMgr.FindByNameAsync(req.Username);
            if (user == null) return Unauthorized("Invalid user");

            var authorizeUrl = $"{_config["Idp:Authority"]}/connect/authorize";
            var query = new Dictionary<string, string?>
            {
                ["client_id"] = req.ClientId,
                ["redirect_uri"] = req.RedirectUri,
                ["response_type"] = "code",
                ["scope"] = req.Scope ?? "openid profile api",
                ["code_challenge"] = req.CodeChallenge,
                ["code_challenge_method"] = "S256",
                ["state"] = Guid.NewGuid().ToString("N")
            };

            var authUrl = QueryHelpers.AddQueryString(authorizeUrl, query);
            var http = _httpClientFactory.CreateClient();
            var authResp = await http.GetAsync(authUrl);
            if (authResp == null || !authResp.IsSuccessStatusCode)
            {
                return BadRequest(new { error = "Authorization request failed" });
            }

            var pckeAuthRedirect = authResp.RequestMessage?.RequestUri?.ToString();
            if (string.IsNullOrEmpty(pckeAuthRedirect) || !pckeAuthRedirect.StartsWith(_config["Idp:Authority"]))
            {
                return BadRequest(new { error = "Invalid redirect URI" });
            }
            var uri = new Uri(pckeAuthRedirect);
            var code = QueryHelpers.ParseQuery(uri.Query).TryGetValue("code", out var codeVal)
                ? codeVal.ToString()
                : null;


            var tokenEndpoint = $"{_config["Idp:Authority"]}/connect/token";
            var tokenRequest = new Dictionary<string, string?>
            {
                ["client_id"] = req.ClientId,
                ["redirect_uri"] = req.RedirectUri,
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["code_verifier"] = req.CodeVerifier
            };

            var resp = await http.PostAsync(tokenEndpoint,
                new FormUrlEncodedContent(tokenRequest!));

            if (!resp.IsSuccessStatusCode)
            {
                var err = await resp.Content.ReadAsStringAsync();
                return BadRequest(new { error = err });
            }

            var json = await resp.Content.ReadAsStringAsync();
            return Content(json, "application/json");
        }
        public class PkceExchangeRequest
        {
            public string Username { get; set; } = string.Empty;
            public string ClientId { get; set; } = string.Empty;
            public string RedirectUri { get; set; } = string.Empty;
            public string CodeChallenge { get; set; } = string.Empty;
            public string CodeVerifier { get; set; } = string.Empty;
            public string AuthorizationCode { get; set; } = string.Empty; // from /connect/authorize
            public string? Scope { get; set; }
        }
        public record SessionResult(string SessionToken, int ExpiresIn);
        public record SSOModel(string SessionToken, string ReturnUrl);
    }
}