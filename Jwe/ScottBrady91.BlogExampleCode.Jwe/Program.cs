using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady91.BlogExampleCode.Jwe
{
    public class Program
    {
        public static void Main()
        {
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            var handler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = "you",
                Issuer = "me",
                Subject = new ClaimsIdentity(new List<Claim>{new Claim("sub", "scott")}),
                EncryptingCredentials = new X509EncryptingCredentials(new X509Certificate2("key_public.cer"))
            };

            var token = handler.CreateEncodedJwt(tokenDescriptor);

            Console.WriteLine("JWE:");
            Console.WriteLine(token + "\n");

            Console.WriteLine("Press enter to validate token...");
            Console.ReadLine();

            var claimsPrincipal = handler.ValidateToken(
                token,
                new TokenValidationParameters
                {
                    ValidAudience = "you",
                    ValidIssuer = "me",
                    RequireSignedTokens = false,
                    TokenDecryptionKey = new X509SecurityKey(new X509Certificate2("key_private.pfx", "idsrv3test"))
                },
                out SecurityToken securityToken);

            Console.WriteLine("Token validated and read for user: " + claimsPrincipal.FindFirst("sub").Value);
            Console.ReadLine();
        }
    }
}
