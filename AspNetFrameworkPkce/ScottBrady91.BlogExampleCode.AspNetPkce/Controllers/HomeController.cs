using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace ScottBrady91.BlogExampleCode.AspNetPkce.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [Authorize]
        public async Task<ActionResult> About()
        {
            ViewBag.Message = "Your application description page.";

            var result = await HttpContext.GetOwinContext().Authentication.AuthenticateAsync("cookie");
            var accessToken = result.Properties.Dictionary[OpenIdConnectParameterNames.AccessToken];
            
            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}