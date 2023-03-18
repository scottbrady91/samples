using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.Samples.Jwt;

public class Jws
{
    private const string KeyId = "efb4e66d8ca343d99afc26826cc74f48";
    private readonly SecurityKey privateKey;
    private readonly SecurityKey publicKey;
    
    public Jws()
    {
        // create test key (private key & corresponding public key)
        var key = RSA.Create(3072);

        // or load from disk (e.g. PEM file)
        // key.ImportFromPem(System.IO.File.ReadAllText("example.pem"));

        // or load from certificate
        // key = new X509Certificate2("example.pfx").GetRSAPrivateKey();

        privateKey = new RsaSecurityKey(key) { KeyId = KeyId };
        
        // alternatively, use X509SecurityKey, which will set the x5t header using the certificate's hash
        // privateKey = new X509SecurityKey(new X509Certificate2("example.pfx"), KeyId);
        
        // load only public key
        publicKey = new RsaSecurityKey(key.ExportParameters(includePrivateParameters: false)) { KeyId = KeyId };
    }

    private string GenerateJwt()
    {
        var handler = new JsonWebTokenHandler();
        var now = DateTime.UtcNow;

        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Claims = new Dictionary<string, object> { { "sub", "336f0f1e54b7406e9bc693efa57a9f6a" } },
            SigningCredentials = new SigningCredentials(privateKey, "RS256")
        });
    }

    private bool ValidateJwt(string jwt)
    {
        var handler = new JsonWebTokenHandler();
        TokenValidationResult result = handler.ValidateToken(jwt, new TokenValidationParameters
        {
            ValidIssuer = "me",
            ValidAudience = "you",
            IssuerSigningKey = publicKey
        });
        
        return result.IsValid;
    }

    private static IEnumerable<Claim> DecodeJwt(string jwt)
    {
        var handler = new JsonWebTokenHandler();
        JsonWebToken token = handler.ReadJsonWebToken(jwt);
        return token.Claims;
    }

    [Fact]
    public void GenerateAndValidateJwt()
    {
        // create
        var jwt = GenerateJwt();
        
        // decode - not for production
        var claims = DecodeJwt(jwt);
        Assert.NotEmpty(claims);
        
        // validate
        Assert.True(ValidateJwt(jwt));
    }
}