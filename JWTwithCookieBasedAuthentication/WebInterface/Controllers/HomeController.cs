using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebInterface.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult SecurePage()
        {
            return Content($"Welcome {User.Identity?.Name}, you are authenticated via JWT!");
        }
    }
}