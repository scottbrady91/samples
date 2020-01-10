using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup(typeof(ScottBrady91.BlogExampleCode.AspNetPkce.Startup))]

namespace ScottBrady91.BlogExampleCode.AspNetPkce
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "cookie"
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = "mvc.owin",
                Authority = "http://localhost:5000",
                RedirectUri = "http://localhost:5001/",
                Scope = "openid profile api1",

                SignInAsAuthenticationType = "cookie",

                RequireHttpsMetadata = false,
                UseTokenLifetime = false,

                RedeemCode = true,
                SaveTokens = true,
                ClientSecret = "secret",

                ResponseType = "code",
                ResponseMode = "query",

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
                        {
                            // set PKCE parameters
                            var codeVerifier = CryptoRandom.CreateUniqueId(32);

                            string codeChallenge;
                            using (var sha256 = SHA256.Create())
                            {
                                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                                codeChallenge = Base64Url.Encode(challengeBytes);
                            }

                            n.ProtocolMessage.SetParameter("code_challenge", codeChallenge);
                            n.ProtocolMessage.SetParameter("code_challenge_method", "S256");

                            // remember code_verifier (adapted from OWIN nonce cookie)
                            RememberCodeVerifier(n, codeVerifier);
                        }

                        return Task.CompletedTask;
                    },
                    AuthorizationCodeReceived = n =>
                    {
                        // get code_verifier
                        var codeVerifier = RetrieveCodeVerifier(n);

                        // attach code_verifier
                        n.TokenEndpointRequest.SetParameter("code_verifier", codeVerifier);

                        return Task.CompletedTask;
                    }
                }
            });
		}

        private void RememberCodeVerifier(RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> n, string codeVerifier)
        {
            var properties = new AuthenticationProperties();
            properties.Dictionary.Add("cv", codeVerifier);
            n.Options.CookieManager.AppendResponseCookie(
                n.OwinContext,
                GetCodeVerifierKey(n.ProtocolMessage.State),
                Convert.ToBase64String(Encoding.UTF8.GetBytes(n.Options.StateDataFormat.Protect(properties))),
                new CookieOptions
                {
                    SameSite = SameSiteMode.None,
                    HttpOnly = true,
                    Secure = n.Request.IsSecure,
                    Expires = DateTime.UtcNow + n.Options.ProtocolValidator.NonceLifetime
                });
        }

        private string RetrieveCodeVerifier(AuthorizationCodeReceivedNotification n)
        {
            string key = GetCodeVerifierKey(n.ProtocolMessage.State);

            string codeVerifierCookie = n.Options.CookieManager.GetRequestCookie(n.OwinContext, key);
            if (codeVerifierCookie != null)
            {
                var cookieOptions = new CookieOptions
                {
                    SameSite = SameSiteMode.None,
                    HttpOnly = true,
                    Secure = n.Request.IsSecure
                };

                n.Options.CookieManager.DeleteCookie(n.OwinContext, "cv", cookieOptions);
            }

            var cookieProperties = n.Options.StateDataFormat.Unprotect(Encoding.UTF8.GetString(Convert.FromBase64String(codeVerifierCookie)));
            cookieProperties.Dictionary.TryGetValue("cv", out var codeVerifier);
            
            return codeVerifier;
        }
        
        private string GetCodeVerifierKey(string state)
        {
            using (var hash = SHA256.Create())
            {
                return OpenIdConnectAuthenticationDefaults.CookiePrefix + "cv." + Convert.ToBase64String(hash.ComputeHash(Encoding.UTF8.GetBytes(state)));
            }
        }
    }
}
