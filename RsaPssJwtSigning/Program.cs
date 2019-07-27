using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady91.BlogExampleCode.RsaPssJwtSigning
{
    public class Program
    {
        private static readonly JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
        private static readonly RsaSecurityKey key = new RsaSecurityKey(RSA.Create(2048));
        private static readonly DateTime now = DateTime.UtcNow;

        private static readonly SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Subject = new ClaimsIdentity(new List<Claim> {new Claim("sub", "scott")}),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSsaPssSha256)
        };

        public static void Main(string[] args)
        {
            // PS256 signing & validation
            var jwt = CreatePssToken();
            ValidatePssToken(jwt);
        }

        private static string CreatePssToken()
        {
            var jwt = handler.CreateEncodedJwt(descriptor);
            Console.WriteLine(jwt);

            return jwt;
        }

        private static void ValidatePssToken(string jwt)
        {
            var claimsPrincipal = handler.ValidateToken(
                jwt,
                new TokenValidationParameters
                {
                    ValidIssuer = descriptor.Issuer, // "me"
                    ValidAudience = descriptor.Audience, // "you
                    IssuerSigningKey = key
                },
                out SecurityToken parsedToken);

            if (!claimsPrincipal.Identity.IsAuthenticated) throw new Exception("It's all gone wrong");
            Console.WriteLine("Token Validated!");
        }

        [Fact]
        public void WhenGeneratedWithDeterministicSignatureScheme_ExpectIdenticalJwts()
        {
            descriptor.SigningCredentials = new SigningCredentials(key, "RS256");

            var token1 = handler.CreateEncodedJwt(descriptor);
            var token2 = handler.CreateEncodedJwt(descriptor);

            Assert.Equal(token1, token2);
        }

        [Fact]
        public void WhenGeneratedWithProbabilisticSignatureScheme_ExpectDifferentJwts()
        {
            descriptor.SigningCredentials = new SigningCredentials(key, "PS256");

            var token1 = handler.CreateEncodedJwt(descriptor);
            var token2 = handler.CreateEncodedJwt(descriptor);

            Assert.NotEqual(token1, token2);
        }
    }
}
