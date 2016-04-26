using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using Client;
using Client.Config;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.WsFederation;
using Owin;

[assembly: OwinStartup(typeof (Startup))]

namespace Client
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions {AuthenticationType = "cookies"});

            app.UseWsFederationAuthentication(new WsFederationAuthenticationOptions
            {
                Wtrealm = "urn:encryptedrealmV2",
                MetadataAddress = "https://localhost:44388/wsfed/metadata",
                Wreply = "https://localhost:44344/",
                SignInAsAuthenticationType = "cookies",
                TokenValidationParameters = new TokenValidationParameters
                {
                    AuthenticationType = "cookies",
                    ClientDecryptionTokens =
                        new ReadOnlyCollection<SecurityToken>(new List<SecurityToken>
                        {
                            new X509SecurityToken(Cert.LoadEncrypting())
                        })
                }
            });
        }
    }
}