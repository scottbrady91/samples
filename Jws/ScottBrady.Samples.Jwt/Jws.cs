using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.Samples.Jwt;

public class Jws
{
    private readonly RSA privateKey;
    private readonly RSA publicKey;
    
    public Jws()
    {
        // create test key (private key & corresponding public key)
        privateKey = RSA.Create(3072);
        publicKey = RSA.Create(privateKey.ExportParameters(false));
    }

    private string GenerateJwt()
    {
        var handler = new JsonWebTokenHandler();
        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            Expires = DateTime.UtcNow.AddDays(1),
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(privateKey), "RS256")
        });
    }

    private bool ValidateJwt(string jwt)
    {
        var handler = new JsonWebTokenHandler();
        var result = handler.ValidateToken(jwt, new TokenValidationParameters
        {
            ValidIssuer = "me",
            ValidAudience = "you",
            IssuerSigningKey = new RsaSecurityKey(publicKey)
        });

        return result.IsValid;
    }

    private static IEnumerable<Claim> DecodeJwt(string jwt)
    {
        var handler = new JsonWebTokenHandler();
        var token = handler.ReadJsonWebToken(jwt);
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