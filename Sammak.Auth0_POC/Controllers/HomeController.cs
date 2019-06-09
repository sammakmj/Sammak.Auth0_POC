using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Mvc;

namespace Sammak.Auth0_POC.Controllers
{
    public class HomeController : Controller
    {

        string clientId = ConfigurationManager.AppSettings["auth0:ClientId"];
        string domain = $"https://{ConfigurationManager.AppSettings["auth0:Domain"]}";
        string openIDUrl = ConfigurationManager.AppSettings["openIDUrl"];

        public ActionResult Index()
        {
            var isAuthenticated = User.Identity.IsAuthenticated;
            ViewBag.IsAuthenticatedViaAuth0 = false;

            //in case they have a token

            var name = ClaimsPrincipal.Current.FindFirst("name")?.Value;
            ViewBag.Name = name;

            var sso = ClaimsPrincipal.Current.FindFirst("sso_info")?.Value;
            ViewBag.sso_info = sso;

            var authenticatedViaAuth0 = ClaimsPrincipal.Current.Identities.FirstOrDefault(souce => souce.AuthenticationType.Equals("Auth0"));
            if (authenticatedViaAuth0 != null)
            {
                var idTokenStr = authenticatedViaAuth0.Claims.ToList().FirstOrDefault(t => t.Type.Equals("id_token"))?.Value;
                var isValidToken = IsIdTokenValid(idTokenStr);
                if (isValidToken)
                    ViewBag.IsAuthenticatedViaAuth0 = true;
            }

            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }


        private bool IsIdTokenValid(string idTokenStr)
        {
            try
            {
                var configurationManager =
                    new ConfigurationManager<OpenIdConnectConfiguration>(openIDUrl,
                        new OpenIdConnectConfigurationRetriever());
                var openIdConfig = AsyncHelper.RunSync(async () =>
                    await configurationManager.GetConfigurationAsync(CancellationToken.None));

                var tokenStr = idTokenStr;

                var keySet = openIdConfig?.JsonWebKeySet?.Keys?.FirstOrDefault();
                if (keySet == null)
                    throw new Exception("Unable to Retrieve OpenID Configuration");

                var rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(
                    new RSAParameters()
                    {
                        Modulus = FromBase64Url(keySet.N),
                        Exponent = FromBase64Url(keySet.E)
                    });

                var validationParameters = new TokenValidationParameters
                {
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidAudience = clientId,
                    ValidateAudience = true,
                    ValidIssuer = $"{domain}/",
                    ValidateIssuer = true,
                    ValidateLifetime = false,
                    IssuerSigningKeys = openIdConfig.SigningKeys
                };

                var handler = new JwtSecurityTokenHandler();
                handler.ValidateToken(tokenStr, validationParameters, out SecurityToken validatedSecurityToken);
                var validatedJwt = validatedSecurityToken as JwtSecurityToken;

                return true;
            }
            catch (SecurityTokenExpiredException e)
            {
                Console.WriteLine("Token has expired");
                Console.WriteLine($"Error: {e.Message}");
                throw;
            }
            catch (SecurityTokenInvalidSignatureException e)
            {
                Console.WriteLine("Token has invalid signature");
                Console.WriteLine($"Error: {e.Message}");
                throw;
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error occurred while validating token: {e.Message}");
                throw;
            }
        }
        static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }

    }
}