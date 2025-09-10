using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace WebInterface.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            var name = User.FindFirst(ClaimTypes.Name)?.Value ?? User.Identity.Name;
            ViewData["message"] = $"Hello {name} (authenticated)";
        }
        else
        {
            ViewData["message"] = "Not authenticated. Click Login (but in our SSO flow you'll come already logged-in).";
        }
        return View();
    }
}
