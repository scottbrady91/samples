using System.Collections.Generic;
using System.Security.Claims;
using IdentityModel.Constants;
using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services.InMemory;
using IdentityServer3.WsFederation.Configuration;
using IdentityServer3.WsFederation.Models;
using IdentityServer3.WsFederation.Services;
using Owin;
using SecurityTokenService.Config;

namespace SecurityTokenService
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var users = new List<InMemoryUser>
            {
                new InMemoryUser
                {
                    Subject = "E4A8B8DA-87F9-41CB-AA33-F79E621B3A56",
                    Username = "scott@scottbrady91.com",
                    Password = "password",
                    Claims = new List<Claim>
                    {
                        new Claim("email", "scott@scottbrady91.com"),
                        new Claim("role", "badmin")
                    }
                }
            };

            var factory =
                new IdentityServerServiceFactory()
                    .UseInMemoryUsers(users)
                    .UseInMemoryScopes(new List<Scope>())
                    .UseInMemoryClients(new List<Client>());

            app.UseIdentityServer(new IdentityServerOptions
            {
                Factory = factory,
                SigningCertificate = Cert.LoadSigning(),
                PluginConfiguration = PluginConfiguration
            });
        }

        private static void PluginConfiguration(IAppBuilder pluginApp, IdentityServerOptions options)
        {
            var relyingParties = new List<RelyingParty>
            {
                new RelyingParty
                {
                    Realm = "urn:encryptedrealmV1",
                    ReplyUrl = "https://localhost:44344/",
                    TokenType = TokenTypes.Saml11TokenProfile11,
                    DefaultClaimTypeMappingPrefix = "http://local.schema.org/",
                    IncludeAllClaimsForUser = true,
                    ClaimMappings =
                    new Dictionary<string, string> {
                        { "sub", ClaimTypes.NameIdentifier },
                        { "name", ClaimTypes.Name },
                        { "given_name", ClaimTypes.GivenName },
                        { "family_name", ClaimTypes.Surname },
                        { "email", ClaimTypes.Email }
                    },
                    EncryptingCertificate = Cert.LoadEncrypting()
                },
                new RelyingParty
                {
                    Realm = "urn:encryptedrealmV2",
                    ReplyUrl = "https://localhost:44344/",
                    TokenType = TokenTypes.Saml2TokenProfile11,
                    DefaultClaimTypeMappingPrefix = "http://local.schema.org/",
                    IncludeAllClaimsForUser = true,
                    ClaimMappings =
                    new Dictionary<string, string> {
                        { "sub", ClaimTypes.NameIdentifier },
                        { "name", ClaimTypes.Name },
                        { "given_name", ClaimTypes.GivenName },
                        { "family_name", ClaimTypes.Surname },
                        { "email", ClaimTypes.Email }
                    },
                    EncryptingCertificate = Cert.LoadEncrypting()
                }
            };

            var factory = new WsFederationServiceFactory(options.Factory);
            factory.Register(new Registration<IEnumerable<RelyingParty>>(relyingParties));
            factory.RelyingPartyService = new Registration<IRelyingPartyService>(typeof (InMemoryRelyingPartyService));

            pluginApp.UseWsFederationPlugin(new WsFederationPluginOptions
            {
                IdentityServerOptions = options,
                Factory = factory,
                EnableMetadataEndpoint = true
            });
        }


    }
}
