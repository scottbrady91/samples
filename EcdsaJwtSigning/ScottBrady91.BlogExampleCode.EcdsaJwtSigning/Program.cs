using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Sec;

namespace ScottBrady91.BlogExampleCode.EcdsaJwtSigning
{
    class Program
    {
        static void Main(string[] args)
        {
            const string privateKey = "c711e5080f2b58260fe19741a7913e8301c1128ec8e80b8009406e5047e6e1ef";
            const string publicKey = "04e33993f0210a4973a94c26667007d1b56fe886e8b3c2afdd66aa9e4937478ad20acfbdc666e3cec3510ce85d40365fc2045e5adb7e675198cf57c6638efa1bdb";

            var privateECDsa = LoadPrivateKey(FromHexString(privateKey));
            var publicECDsa = LoadPublicKey(FromHexString(publicKey));

            var jwt = CreateSignedJwt(privateECDsa);
            var isValid = VerifySignedJwt(publicECDsa, jwt);

            Console.WriteLine(isValid ? "Valid!" : "Not Valid...");
        }
        
        // https://stackoverflow.com/questions/311165/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-and-vice-versa
        private static byte[] FromHexString(string hex)
        {
            var numberChars = hex.Length;
            var hexAsBytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2) 
                hexAsBytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

            return hexAsBytes;
        }

        private static ECDsa LoadPrivateKey(byte[] key)
        {
            var privKeyInt = new Org.BouncyCastle.Math.BigInteger(+1, key);
            var parameters = SecNamedCurves.GetByName("secp256r1");
            var qa = parameters.G.Multiply(privKeyInt);
            var pubKeyX = qa.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned();
            var pubKeyY = qa.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned();

            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.CreateFromFriendlyName("secp256r1"),
                D = privKeyInt.ToByteArrayUnsigned(),
                Q = new ECPoint
                {
                    X = pubKeyX,
                    Y = pubKeyY
                }
            });
        }

        private static ECDsa LoadPublicKey(byte[] key)
        {
            var x = key.Skip(1).Take(32).ToArray();
            var y = key.Skip(33).ToArray();

            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.CreateFromFriendlyName("secp256r1"),
                Q = new ECPoint
                {
                    X = x,
                    Y = y
                }
            });
        }

        private static string CreateSignedJwt(ECDsa eCDsa)
        {
            var now = DateTime.UtcNow;
            var tokenHandler = new JwtSecurityTokenHandler();

            var jwtToken = tokenHandler.CreateJwtSecurityToken(
                issuer: "me",
                audience: "you",
                subject: null,
                notBefore: now,
                expires: now.AddMinutes(30),
                issuedAt: now,
                signingCredentials: new SigningCredentials(new ECDsaSecurityKey(eCDsa), SecurityAlgorithms.EcdsaSha256));

            return tokenHandler.WriteToken(jwtToken);
        }

        private static bool VerifySignedJwt(ECDsa eCDsa, string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var claimsPrincipal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = "me",
                ValidAudience = "you",
                IssuerSigningKey = new ECDsaSecurityKey(eCDsa)
            }, out var parsedToken);

            return claimsPrincipal.Identity.IsAuthenticated;
        }
    }
}
