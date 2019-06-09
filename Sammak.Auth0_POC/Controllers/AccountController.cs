using Auth0.AuthenticationApi;
using Auth0.AuthenticationApi.Models;
using System;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Services;
using System.Web;
using System.Web.Mvc;

namespace Sammak.Auth0_POC.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult Login(string returnUrl)
        {
            var isAuthenticated = User.Identity.IsAuthenticated;
            var client = new AuthenticationApiClient(
                new Uri(string.Format("https://{0}", ConfigurationManager.AppSettings["auth0:Domain"])));


            var request = this.Request;
            var redirectUri = new UriBuilder(request.Url.Scheme, request.Url.Host, this.Request.Url.IsDefaultPort ? -1 : request.Url.Port, "LoginCallback.ashx");

            var authorizeUrlBuilder = client.BuildAuthorizationUrl()
                    .WithClient(ConfigurationManager.AppSettings["auth0:ClientId"])
                    .WithRedirectUrl(redirectUri.ToString())
                    .WithResponseType(AuthorizationResponseType.Code)
                    .WithScope("openid profile")
                    .WithConnection("Auth0-MJS-Test")
                //.WithValue("prompt","none")
                // adding this audience will cause Auth0 to use the OIDC-Conformant pipeline
                // you don't need it if your client is flagged as OIDC-Conformant (Advance Settings | OAuth)
                //.WithAudience("https://" + @ConfigurationManager.AppSettings["auth0:Domain"] + "/userinfo")
                ;
            if (!string.IsNullOrEmpty(returnUrl))
            {
                var state = "ru=" + HttpUtility.UrlEncode(returnUrl);
                authorizeUrlBuilder.WithState(state);
            }

            try
            {
                var redirectUrl = authorizeUrlBuilder.Build().ToString();
                var redirect = new RedirectResult(redirectUrl);
                //var redirect = new RedirectResult(authorizeUrlBuilder.Build().ToString());
                return redirect;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public ActionResult Logout()
        {
            var isAuthenticated = User.Identity.IsAuthenticated;
            FederatedAuthentication.SessionAuthenticationModule.SignOut();

            // Redirect to Auth0's logout endpoint.
            // After terminating the user's session, Auth0 will redirect to the 
            // returnTo URL, which you will have to add to the list of allowed logout URLs for the client.
            var returnTo = Url.Action("Index", "Home", null, protocol: Request.Url.Scheme);

            var url = string.Format(CultureInfo.InvariantCulture,
                "https://{0}/v2/logout?returnTo={1}&client_id={2}",
                ConfigurationManager.AppSettings["auth0:Domain"],
                Server.UrlEncode(returnTo),
                ConfigurationManager.AppSettings["auth0:ClientId"]);

            var domain = ConfigurationManager.AppSettings["auth0:Domain"];
            var returnToUrl = Server.UrlEncode(returnTo);
            var clientId = ConfigurationManager.AppSettings["auth0:ClientId"];

            url = $"https://{domain}/v2/logout?returnTo={returnToUrl}&client_id={clientId}";

            return Redirect(
              string.Format(CultureInfo.InvariantCulture,
                "https://{0}/v2/logout?returnTo={1}&client_id={2}",
                ConfigurationManager.AppSettings["auth0:Domain"],
                Server.UrlEncode(returnTo),
                ConfigurationManager.AppSettings["auth0:ClientId"]));
        }

        public ActionResult SignUp()
        {
            ViewBag.Message = "Sign Up Page Not Setup";
            return View();
        }

        public ActionResult Error()
        {
            ViewBag.Message = Request.QueryString["error"];
            return View();
        }
    }
}