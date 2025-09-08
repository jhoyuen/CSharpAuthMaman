using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ResourceWeb.Models;

namespace ResourceWeb.Controllers;

public class HomeController : Controller
{
    [AllowAnonymous]
    public IActionResult Index()
    {
        return View();
    }

    [Authorize(Policy = "ApiScope")]
    public IActionResult Secure()
    {
        var name = User.Identity?.Name ?? "(unknown)";
        return View(model: name);
    }
}