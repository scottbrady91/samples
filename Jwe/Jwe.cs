using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jwe;

public class Jwe
{
    [Fact]
    public void CreateAndValidateJwe()
    {
        var encryptionKey = RSA.Create(3072); // public key for encryption, private key for decryption
        var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); // private key for signing, public key for validation

        var encryptionKid = Guid.NewGuid().ToString("N");
        var signingKid = Guid.NewGuid().ToString("N");

        var privateEncryptionKey = new RsaSecurityKey(encryptionKey) {KeyId = encryptionKid};
        var publicEncryptionKey = new RsaSecurityKey(encryptionKey.ExportParameters(false)) {KeyId = encryptionKid};
        var privateSigningKey = new ECDsaSecurityKey(signingKey) {KeyId = signingKid};
        var publicSigningKey = new ECDsaSecurityKey(ECDsa.Create(signingKey.ExportParameters(false))) {KeyId = signingKid};

        var token = CreateJwe(privateSigningKey, publicEncryptionKey);
        DecryptAndValidateJwe(token, publicSigningKey, privateEncryptionKey).Should().BeTrue();
    }
    
    private static string CreateJwe(SecurityKey signingKey, SecurityKey encryptionKey)
    {
        var handler = new JsonWebTokenHandler();

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Audience = "api1",
            Issuer = "https://idp.example.com",
            Claims = new Dictionary<string, object>{{"sub", "811e790749a24d8a8f766e1a44dca28a"}},
            
            // private key for signing
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.EcdsaSha256),
            
            // public key for encryption
            EncryptingCredentials = new EncryptingCredentials(encryptionKey, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512)
        };

        return handler.CreateToken(tokenDescriptor);
    }
    
    private static bool DecryptAndValidateJwe(string token, SecurityKey signingKey, SecurityKey encryptionKey)
    {
        var handler = new JsonWebTokenHandler();

        TokenValidationResult result = handler.ValidateToken(
            token,
            new TokenValidationParameters
            {
                ValidAudience = "api1",
                ValidIssuer = "https://idp.example.com",

                // public key for signing
                IssuerSigningKey = signingKey,

                // private key for encryption
                TokenDecryptionKey = encryptionKey
            });

        return result.IsValid;
    }
}