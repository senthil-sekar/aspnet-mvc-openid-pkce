using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace aspnet_mvc_openid_pkce.Controllers
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

        public ActionResult LogOff()
        {
            Request.GetOwinContext()
                .Authentication
                .SignOut(CookieAuthenticationDefaults.AuthenticationType
                , OpenIdConnectAuthenticationDefaults.AuthenticationType);
            return RedirectToAction("Index");
        }
    }
}