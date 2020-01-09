using System.Security.Claims;
using IdentityModel.Client;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
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
                ResponseType = "code id_token",
                Scope = "openid profile api1",

                SignInAsAuthenticationType = "cookie",

                RequireHttpsMetadata = false,
                UseTokenLifetime = false,

                RedeemCode = true,
                SaveTokens = true,
                ClientSecret = "secret"
            });
		}
    }
}
