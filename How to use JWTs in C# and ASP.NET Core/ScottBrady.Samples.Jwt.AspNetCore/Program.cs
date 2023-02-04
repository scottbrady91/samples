using System.Collections.Generic;
using System.Security.Cryptography;
using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();

var key = RSA.Create(3072);

builder.Services.AddIdentityServer()
    .AddInMemoryClients(new[] { new Client { ClientId = "app", ClientSecrets = new[] { new Secret("secret".Sha256()) }, AllowedGrantTypes = GrantTypes.ClientCredentials, AllowedScopes = new[] { "api1" } } })
    .AddInMemoryApiResources(new[] { new ApiResource("api1") { Scopes = new[] { "api1" } } })
    .AddInMemoryApiScopes(new[] { new ApiScope("api1") })
    .AddInMemoryIdentityResources(new List<IdentityResource>())
    .AddSigningCredential(new SigningCredentials(new RsaSecurityKey(key), "RS256"));


builder.Services.AddAuthentication("jwt")
    .AddJwtBearer("jwt", options =>
    {
        options.Audience = "api1";
        
        // set base URL of your OAuth authorization server to load in issuer & keys automatically
        // options.Authority = "https://localhost:5001"; 
        
        // or manually define the TokenValidationParameters
        options.TokenValidationParameters.ValidIssuer = "https://localhost:5001";
        options.TokenValidationParameters.IssuerSigningKey = new RsaSecurityKey(key.ExportParameters(false));
    });

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseIdentityServer();
app.UseAuthorization();

app.MapControllers();

app.Run();