using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using IdentityServer4.Configuration;
using IdentityServer4.Quickstart.UI;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            var keyClient = new KeyClient(
                new Uri(""), // e.g. https://scottbrady91-test.vault.azure.net/
                new ClientSecretCredential(
                    tenantId: "",
                    clientId: "",
                    clientSecret: ""));

            Response<KeyVaultKey> response = keyClient.GetKey(""); // e.g. IdentityServerSigningKeyEcc

            AsymmetricSecurityKey key;
            string algorithm;

            if (response.Value.KeyType == KeyType.Ec)
            {
                ECDsa ecDsa = response.Value.Key.ToECDsa();
                key = new ECDsaSecurityKey(ecDsa) {KeyId = response.Value.Properties.Version};
                
                // parse from curve
                if (response.Value.Key.CurveName == KeyCurveName.P256) algorithm = "ES256";
                else if (response.Value.Key.CurveName == KeyCurveName.P384) algorithm = "ES384";
                else if (response.Value.Key.CurveName == KeyCurveName.P521) algorithm = "ES521";
                else  throw new NotSupportedException();
            }
            else if (response.Value.KeyType == KeyType.Rsa)
            {
                RSA rsa = response.Value.Key.ToRSA();
                key = new RsaSecurityKey(rsa) {KeyId = response.Value.Properties.Version};

                // you define
                algorithm = "PS256";
            }
            else
            {
                throw new NotSupportedException();
            }
            
            services.AddIdentityServer()
                .AddTestUsers(TestUsers.Users)
                .AddInMemoryIdentityResources(Config.Ids)
                .AddInMemoryApiResources(Config.Apis)
                .AddInMemoryClients(Config.Clients)
                .AddSigningCredential(key, algorithm);

            services.AddTransient<ITokenCreationService, KeyVaultTokenCreationService>();
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();
            app.UseStaticFiles();
            app.UseRouting();

            app.UseIdentityServer();
            app.UseAuthorization();
            app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());
        }
    }

    public class KeyVaultTokenCreationService : DefaultTokenCreationService
    {
        public KeyVaultTokenCreationService(ISystemClock clock, IKeyMaterialService keys, IdentityServerOptions options, ILogger<DefaultTokenCreationService> logger) 
            : base(clock, keys, options, logger)
        {
        }

        protected override async Task<string> CreateJwtAsync(JwtSecurityToken jwt)
        {
            var plaintext = $"{jwt.EncodedHeader}.{jwt.EncodedPayload}";

            byte[] hash;
            using (var hasher = CryptoHelper.GetHashAlgorithmForSigningAlgorithm(jwt.SignatureAlgorithm))
            {
                hash = hasher.ComputeHash(Encoding.UTF8.GetBytes(plaintext));
            }

            var cryptoClient = new CryptographyClient(
                new Uri(""), // e.g. https://scottbrady91-test.vault.azure.net/keys/IdentityServerSigningKeyEcc
                new ClientSecretCredential(
                    tenantId: "",
                    clientId: "",
                    clientSecret: ""));

            var signResult = await cryptoClient.SignAsync(new SignatureAlgorithm(jwt.SignatureAlgorithm), hash);

            return $"{plaintext}.{Base64UrlTextEncoder.Encode(signResult.Signature)}";
        }
    }
}