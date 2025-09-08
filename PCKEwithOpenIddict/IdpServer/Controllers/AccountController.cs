using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdpServer.Controllers
{
    [Route("account")]
    public class AccountController : Controller
    {
        private readonly SignInManager<AppUser> _signInMgr;
        private readonly UserManager<AppUser> _userMgr;

        public AccountController(SignInManager<AppUser> signInMgr, UserManager<AppUser> userMgr)
        {
            _signInMgr = signInMgr;
            _userMgr = userMgr;
        }

        [HttpGet("login")]
        public IActionResult Login(string? returnUrl = null)
        {
            return Content($"""
        <form method="post" action="/account/login?returnUrl={returnUrl}">
          <input name="username" placeholder="demo" />
          <input name="password" type="password" placeholder="P@ssw0rd!" />
          <button type="submit">Login</button>
        </form>
        """, "text/html");
        }

        [HttpPost("login")]
        public async Task<IActionResult> LoginPost(string username, string password, string? returnUrl = null)
        {
            var user = await _userMgr.FindByNameAsync(username);
            if (user != null && await _userMgr.CheckPasswordAsync(user, password))
            {
                await _signInMgr.SignInAsync(user, false);
                return Redirect(returnUrl ?? "/");
            }

            return Unauthorized("Invalid credentials");
        }
    }
}
