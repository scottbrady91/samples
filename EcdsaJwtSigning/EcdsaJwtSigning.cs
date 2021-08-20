using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace EcdsaJwtSigning
{
    public class EcdsaJwtSigning
    {
        public static TheoryData<ECCurve, string> Curves = new TheoryData<ECCurve, string>
        {
            { ECCurve.NamedCurves.nistP256, "ES256" },
            { ECCurve.NamedCurves.nistP384, "ES384" },
            { ECCurve.NamedCurves.nistP521, "ES512" }
        };
        
        [Theory]
        [MemberData(nameof(Curves))]
        public void CreateAndValidateJwt(ECCurve curve, string algorithm)
        {
            var (privateKey, publicKey) = CreateKeys(curve);

            var jwt = CreateSignedJwt(privateKey, algorithm);
            var isValid = VerifySignedJwt(jwt, publicKey);
            
            isValid.Should().BeTrue();
        }

        private static (ECDsa privateKey, ECDsa publicKey) CreateKeys(ECCurve curve)
        {
            var privateKey = ECDsa.Create(curve);
            var publicKey = ECDsa.Create(privateKey.ExportParameters(false));

            return (privateKey, publicKey);
        }

        private static string CreateSignedJwt(ECDsa key, string algorithm)
        {
            var now = DateTime.UtcNow;
            var handler = new JsonWebTokenHandler();
            return handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                NotBefore = now,
                Expires = now.AddMinutes(30),
                IssuedAt = now,
                Claims = new Dictionary<string, object> { { "sub", "123" } },
                SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), algorithm)
            });
        }

        private static bool VerifySignedJwt(string token, ECDsa key)
        {
            var handler = new JsonWebTokenHandler();

            TokenValidationResult result = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = "me",
                ValidAudience = "you",
                IssuerSigningKey = new ECDsaSecurityKey(key)
            });

            return result.IsValid;
        }
    }
}
