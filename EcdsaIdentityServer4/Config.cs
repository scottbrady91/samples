using IdentityServer4.Models;
using System.Collections.Generic;

namespace EcdsaIdentityServer4
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> IdentityResources =>
            new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
            };

        public static IEnumerable<ApiScope> ApiScopes =>
            new[]
            {
                new ApiScope("api1"),
                new ApiScope("api2"),
            };

        public static IEnumerable<ApiResource> ApiResources =>
            new[]
            {
                new ApiResource("api1")
                {
                    Scopes = {"api1"},
                    AllowedAccessTokenSigningAlgorithms = {"ES256"}
                },
                new ApiResource("api2")
                {
                    Scopes = {"api2"},
                    AllowedAccessTokenSigningAlgorithms = {"RS256", "ES256"}
                }
            };

        public static IEnumerable<Client> Clients =>
            new[]
            {
                new Client
                {
                    ClientId = "machine",
                    ClientName = "Client Credentials Client",

                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets = {new Secret("secret".Sha256())},

                    AllowedScopes = {"api1", "api2"}
                }
            };
    }
}