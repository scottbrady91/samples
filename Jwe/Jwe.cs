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
        var signingKey = RSA.Create(3072); // private key for signing, public key for validation

        var encryptionKid = Guid.NewGuid().ToString("N");
        var signingKid = Guid.NewGuid().ToString("N");

        var privateEncryptionKey = new RsaSecurityKey(encryptionKey) {KeyId = encryptionKid};
        var publicEncryptionKey = new RsaSecurityKey(encryptionKey.ExportParameters(false)) {KeyId = encryptionKid};
        var privateSigningKey = new RsaSecurityKey(signingKey) {KeyId = signingKid};
        var publicSigningKey = new RsaSecurityKey(signingKey.ExportParameters(false)) {KeyId = signingKid};

        var token = CreateJwe(privateSigningKey, publicEncryptionKey);
        DecryptAndValidateJwe(token, publicSigningKey, privateEncryptionKey).Should().BeTrue();
    }
    
    private static string CreateJwe(SecurityKey signingKey, SecurityKey encryptionKey)
    {
        var handler = new JsonWebTokenHandler();

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Audience = "you",
            Issuer = "me",
            Claims = new Dictionary<string, object>{{"sub", "scott"}},
            
            // private key for signing
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
            
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
                ValidAudience = "you",
                ValidIssuer = "me",

                // public key for signing
                IssuerSigningKey = signingKey,

                // private key for encryption
                TokenDecryptionKey = encryptionKey
            });

        return result.IsValid;
    }
}