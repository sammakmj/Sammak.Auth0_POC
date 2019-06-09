namespace Auth0_POC
{
	using Auth0.AspNet;
	using Auth0.AuthenticationApi;
	using Auth0.AuthenticationApi.Models;
	using Microsoft.IdentityModel.Protocols;
	using Microsoft.IdentityModel.Protocols.OpenIdConnect;
	using Microsoft.IdentityModel.Tokens;
	using Newtonsoft.Json;
	using Newtonsoft.Json.Linq;
	using Sammak.Auth0_POC;
	using System;
	using System.Collections.Generic;
	using System.Configuration;
	using System.Diagnostics;
	using System.IdentityModel.Services;
	using System.IdentityModel.Tokens.Jwt;
	using System.Linq;
	using System.Security.Cryptography;
	using System.Threading;
	using System.Threading.Tasks;
	using System.Web;

	public class LoginCallback : HttpTaskAsyncHandler
	{
		public override async Task ProcessRequestAsync(HttpContext context)
		{
			var clientId = ConfigurationManager.AppSettings["auth0:ClientId"];
			var domain = $"https://{ConfigurationManager.AppSettings["auth0:Domain"]}";
			var nameSpace = ConfigurationManager.AppSettings["auth0:ClientNameSpace"];
			var issuer = $"{domain}/";
			var secret = ConfigurationManager.AppSettings["auth0:ClientSecret"];
			var auth0Audience = ConfigurationManager.AppSettings["auth0:API"];
			var openIDUrl = ConfigurationManager.AppSettings["openIDUrl"];

			AuthenticationApiClient client = new AuthenticationApiClient(new Uri(domain));

			var userStr = JsonConvert.SerializeObject(context.User, Formatting.Indented);

			// the code parameter of the returned query string carries the token code.  if that is missing something is wrong at the Auth0 configuration.
			// redirect to the error page.
			var code = context.Request.QueryString["code"];
			if(code == null)
			{
				var errorMessage = "The return Url from Auth0 does not bring back the token code!";
				Debug.WriteLine(errorMessage);
				var path = "~/Account/Error";  // "Account/Error"; works too
				var redirectUri4 = $"{path}?error={errorMessage}";
				context.Response.Redirect(redirectUri4);
				return;
			}

			var redirectUri = context.Request.Url.ToString();
			var token = await client.GetTokenAsync(new AuthorizationCodeTokenRequest
			{
				ClientId = clientId,
				ClientSecret = secret,
				Code = code,
				RedirectUri = redirectUri
			});

			try
			{
				// do it only once
				var configurationManager =
					new ConfigurationManager<OpenIdConnectConfiguration>(openIDUrl,
						new OpenIdConnectConfigurationRetriever());
				var openIdConfig = AsyncHelper.RunSync(async () =>
					await configurationManager.GetConfigurationAsync(CancellationToken.None));

				var tokenStr = token.IdToken;

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
					IssuerSigningKey = new RsaSecurityKey(rsa)
				};

				var handler = new JwtSecurityTokenHandler();
				handler.ValidateToken(tokenStr, validationParameters, out SecurityToken validatedSecurityToken);
				var validatedJwt = validatedSecurityToken as JwtSecurityToken;


				var aud = JsonConvert.SerializeObject(validatedJwt.Audiences, Formatting.Indented);
				var claims = JsonConvert.SerializeObject(validatedJwt.Claims, Formatting.Indented);
				var InnerToken = JsonConvert.SerializeObject(validatedJwt.InnerToken, Formatting.Indented);
				JwtPayload payload = validatedJwt.Payload;
				var payloadStr = JsonConvert.SerializeObject(payload, Formatting.Indented);
				var SigningCredentials = JsonConvert.SerializeObject(validatedJwt.SigningCredentials, Formatting.Indented);
				var Actor = JsonConvert.SerializeObject(validatedJwt.Actor, Formatting.Indented);
				var EncryptingCredentials = JsonConvert.SerializeObject(validatedJwt.EncryptingCredentials, Formatting.Indented);
				var ValidFrom = JsonConvert.SerializeObject(validatedJwt.ValidFrom, Formatting.Indented);
				var ValidTo = JsonConvert.SerializeObject(validatedJwt.ValidTo, Formatting.Indented);
				var EncodedPayload = JsonConvert.SerializeObject(validatedJwt.EncodedPayload, Formatting.Indented);

				var EncodedHeader = JsonConvert.SerializeObject(validatedJwt.EncodedHeader, Formatting.Indented);
				var Header= JsonConvert.SerializeObject(validatedJwt.Header, Formatting.Indented);
				var Id= JsonConvert.SerializeObject(validatedJwt.Id, Formatting.Indented);
				var Issuer= JsonConvert.SerializeObject(validatedJwt.Issuer, Formatting.Indented);
				var RawAuthenticationTag= JsonConvert.SerializeObject(validatedJwt.RawAuthenticationTag, Formatting.Indented);
				var RawCiphertext= JsonConvert.SerializeObject(validatedJwt.RawCiphertext, Formatting.Indented);
				var RawData= JsonConvert.SerializeObject(validatedJwt.RawData, Formatting.Indented);
				var RawEncryptedKey= JsonConvert.SerializeObject(validatedJwt.RawEncryptedKey, Formatting.Indented);
				var RawHeader= JsonConvert.SerializeObject(validatedJwt.RawHeader, Formatting.Indented);
				var RawInitializationVector= JsonConvert.SerializeObject(validatedJwt.RawInitializationVector, Formatting.Indented);
				var RawPayload= JsonConvert.SerializeObject(validatedJwt.RawPayload, Formatting.Indented);
				var RawSignature= JsonConvert.SerializeObject(validatedJwt.RawSignature, Formatting.Indented);
				var SecurityKey= JsonConvert.SerializeObject(validatedJwt.SecurityKey, Formatting.Indented);
				var SignatureAlgorithm= JsonConvert.SerializeObject(validatedJwt.SignatureAlgorithm, Formatting.Indented);
				var Subject= JsonConvert.SerializeObject(validatedJwt.Subject, Formatting.Indented);

				// the following property json convert throws exception!
				//var SigningKey= JsonConvert.SerializeObject(validatedJwt.SigningKey, Formatting.Indented);

				var j = 6;
			}
			catch (SecurityTokenExpiredException e)
			{
				Debug.WriteLine("Token has expired");
				Debug.WriteLine($"Error: {e.Message}");
				throw;
			}
			catch (SecurityTokenInvalidSignatureException e)
			{
				Debug.WriteLine("Token has invalid signature");
				Debug.WriteLine($"Error: {e.Message}");
				throw;
			}
			catch (Exception e)
			{
				Debug.WriteLine($"Error occurred while validating token: {e.Message}");
				throw;
			}
			// at this point the token is valid


			var profile = await client.GetUserInfoAsync(token.AccessToken);

			var user = new List<KeyValuePair<string, object>>
			{
				new KeyValuePair<string, object>("name", profile.FullName ?? profile.PreferredUsername ?? profile.Email),
				new KeyValuePair<string, object>("email", profile.Email),
				new KeyValuePair<string, object>("family_name", profile.LastName),
				new KeyValuePair<string, object>("given_name", profile.FirstName),
				new KeyValuePair<string, object>("nickname", profile.NickName),
				new KeyValuePair<string, object>("picture", profile.Picture),
				new KeyValuePair<string, object>("user_id", profile.UserId),
				new KeyValuePair<string, object>("id_token", token.IdToken),
				new KeyValuePair<string, object>("access_token", token.AccessToken),
				new KeyValuePair<string, object>("refresh_token", token.RefreshToken)
			};
			// this point show if SSO is yes


			var additonalClaimInfo = new JObject();
			if (profile.AdditionalClaims.Any())
			{
				var additonalClaims = profile.AdditionalClaims.TryGetValue(nameSpace, out JToken value);
				if (value != null)
				{
					additonalClaimInfo = (JObject)value;
					user.Add(new KeyValuePair<string, object>("sso_info", additonalClaimInfo.ToString()));
				}
			}
			// retrieves the rules and attachment to the claim's principal

			Console.Write(additonalClaimInfo.ToString());

			// NOTE: Uncomment the following code in order to include claims from associated identities
			//profile.Identities.ToList().ForEach(i =>
			//{
			//    user.Add(new KeyValuePair<string, object>(i.Connection + ".access_token", i.AccessToken));
			//    user.Add(new KeyValuePair<string, object>(i.Connection + ".provider", i.Provider));
			//    user.Add(new KeyValuePair<string, object>(i.Connection + ".user_id", i.UserId));
			//});

			// NOTE: uncomment this if you send roles
			// user.Add(new KeyValuePair<string, object>(ClaimTypes.Role, profile.ExtraProperties["roles"]));

			// NOTE: this will set a cookie with all the user claims that will be converted 
			//       to a ClaimsPrincipal for each request using the SessionAuthenticationModule HttpModule. 
			//       You can choose your own mechanism to keep the user authenticated (FormsAuthentication, Session, etc.)
			var isAuthenticated = context.User.Identity.IsAuthenticated;
			FederatedAuthentication.SessionAuthenticationModule.CreateSessionCookie(user);
			isAuthenticated = context.User.Identity.IsAuthenticated;

			var returnTo = "/";
			var state = context.Request.QueryString["state"];
			if (state != null)
			{
				var stateValues = HttpUtility.ParseQueryString(context.Request.QueryString["state"]);
				var redirectUrl = stateValues["ru"];

				// check for open redirection
				if (redirectUrl != null && IsLocalUrl(redirectUrl))
				{
					returnTo = redirectUrl;
				}
			}

			context.Response.Redirect(returnTo);
		}

		public bool IsReusable
		{
			get { return false; }
		}

		private bool IsLocalUrl(string url)
		{
			return !String.IsNullOrEmpty(url)
				&& url.StartsWith("/")
				&& !url.StartsWith("//")
				&& !url.StartsWith("/\\");
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