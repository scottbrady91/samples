using System;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;

namespace ScottBrady91.BlogExampleCode.EddsaJwtSigning
{
    public static class Program
    {
        public static void Main()
        {
            EdDsaWithBouncyCastle();
            EddsaJwt();
        }

        private static void EdDsaWithBouncyCastle()
        {
            // message to sign & verify
            var message = Encoding.UTF8.GetBytes("Bob Loblaw");
            
            // private/public key generation
            var keyPairGenerator = new Ed25519KeyPairGenerator();
            keyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var keyPair = keyPairGenerator.GenerateKeyPair();
            
            var privateKey = (Ed25519PrivateKeyParameters) keyPair.Private;
            var publicKey = (Ed25519PublicKeyParameters) keyPair.Public;

            // keys are 32-bytes each
            var privateKeyBytes = privateKey.GetEncoded();
            var publicKeyBytes = publicKey.GetEncoded();
            Console.WriteLine("Private key = " + Convert.ToBase64String(privateKeyBytes));
            Console.WriteLine("Public key = " + Convert.ToBase64String(publicKeyBytes));
            
            // signature generation
            var signer = new Ed25519Signer();
            signer.Init(true, privateKey);
            signer.BlockUpdate(message, 0, message.Length);

            byte[] signature = signer.GenerateSignature();
            Console.WriteLine("Signature = " + Convert.ToBase64String(signature));

            // signature validation
            var validator = new Ed25519Signer();
            validator.Init(false, publicKey);
            validator.BlockUpdate(message, 0, message.Length);

            bool isValidSignature = validator.VerifySignature(signature);
            Console.WriteLine("Signature is valid: " + isValidSignature);
        }
        
        private static void EddsaJwt()
        {
            // private/public key generation
            var keyPairGenerator = new Ed25519KeyPairGenerator();
            keyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var keyPair = keyPairGenerator.GenerateKeyPair();
            
            var privateKey = (Ed25519PrivateKeyParameters) keyPair.Private;
            var publicKey = (Ed25519PublicKeyParameters) keyPair.Public;

            var handler = new JsonWebTokenHandler();
            
            // create JWT
            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                Subject = new ClaimsIdentity(new[] {new Claim("sub", "123")}),
                
                // using JOSE algorithm "EdDSA"
                SigningCredentials = new SigningCredentials(new EdDsaSecurityKey(privateKey), ExtendedSecurityAlgorithms.EdDsa)
            });
            Console.WriteLine("JWT = " + token);

            // validate JWT
            var result = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = "me",
                ValidAudience = "you",
                IssuerSigningKey = new EdDsaSecurityKey(publicKey)
            });
            Console.WriteLine("Is JWT signature valid: " + result.IsValid);
        }
    }
}