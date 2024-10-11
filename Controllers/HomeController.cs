using DirectoryServices.ProtocolsLdapServis.Models;
using DirectoryServices.ProtocolsLdapServis.Service;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace DirectoryServices.ProtocolsLdapServis.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }
        public IActionResult Index()
        {
            return View();
        }
        [HttpPost]
        public IActionResult Index(string userName,string password)
        {
            LdapService Auth = new LdapService();
            var serverControl = Auth.isServerReachable();
            if (serverControl==false)
            {
                return View(Error());
            }
            string result;
            if (Auth.authentication(userName, password, out LdapAuthenticationViewModel userProfile))
            {
                result = "Login successful";
                return View("Index", userProfile);
            }
            else
            {
                result = "Login successful";
            }
            return View("Index", result);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}