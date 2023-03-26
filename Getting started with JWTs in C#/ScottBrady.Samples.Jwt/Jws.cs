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
    private const string KeyId = "8c9b02ba55dc4118a0488558b38dbd2e";
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
        
        // or load from JWK
        // privateKey = new JsonWebKey("{\"alg\":\"RS256\",\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"334703f667abaaf9826239ce88c52856\",\"n\":\"pgapT6UMCwD4x5df2XdgiaJTN4hFtTTjHruRwpqtdCdJijo3fYKtmbuT-xtqKvbaNtH_hkRGD_N8MULSXYTY8HZNfBgZkIvMyRz9gfu_Cu_TtxeeYZsnjnyK1IIXl1pfNOz9co7vq5PISgPW-6Mfsv1sUmFjNhOaA4hoH7gDTyEluo8lj-zswhVt9IFD-zhvlOYaN-4rUbVVy8-kGEhtDAC8kgv-w6XYUQ3a7tQFD3qjQkzxnMIE7zG-h21_CjoqTFQZfu6q1C9W1MIkGFzS9UZwoijPAwpk6OHwPruTg5hfFipktRf5E4DV3LKRF9kSg0ZM_YQF95oiQdDbdK-YS3qXErJqtO-Entep1pqluZS1BQgSqiIJ48-_5b46l_GZkWH2xvls46MlX5gxhkaES8DaWfKDmLaTYup3R-Y_EI3i4vDBMKoMBdS1JKRdoZxO9MY70qMLdQ0QcmgccC6i_PUCpbPvhQHp8lVgQ0T4_fopVCNIWJyaKj-kPN-jsNgh\",\"e\":\"AQAB\",\"d\":\"DFWG2wafLisYkFVf1stOVfND_OZoDVX8QIJ9SeiNVcl8ZmM8T5v3cyoTDI7lFIOJwxRXSB2G2fUEBzHYaH-v0S9swrkUnx8vq8o2UCOIdhLKlvnPd59b8TMx6icvAvzBAXDQxGO3jPbZ5JvD6yZbesPmeflHslMC-Fu4JpEYV9bV03YCe56FmUaXyFgZGY8ABR8SGBEe0T9oPA-1OGObDE76s1vmRZkqyJy_pMoGBTgebFTEh1mHndCDf9Kj4zneX229WLgFIMAuUF6NsJIcvdoFQCM63saWQpI3JfbItYRqYEhjC5y7W-2y7DQGTNafMR8X38-GebhJvHCm4qiXzenbdQIHeEE85BWzHw9M2YlSZ8vMl3zQQMTh1vMZg07eYqwzr1zMYxI8HJAQKB8NR2VDe0XQS7vWouV4KTGvw4BLY0wNAy2vOKbyCEvyiBpYTrGYkpgjspJHbxJMGscq0vm90CsALvWnd4BpKoFBPiCBnshYddZAur6DKLBlNW6R\",\"dp\":\"u5ZWFN_fbfkuUR7vAAAZudu6Wvn68HNgrHNgBilS4ohkUYdf8Mevt460kCmaZUxwjFByVOhULZhLE6zgtmr_Fo7tD-4pYR-ajetXWKYq5m1Kp7o4_BEqtG7XhUuzKWRpgnTQKB26gJSPaKK8diIq7ONb1N_6wwElC3-4H8fOLMlINtebuw26xX4LMSNFfvHlpf-7biHeTKi-pEPcWlSLSpYj1i1larIKTflY8B_VQvkdyhsG9m0R-nkahryKsANx\",\"dq\":\"uSEU5laDj40xRSYu5s5uExtHIaP02YQMDlyhcYEj3W92xF8cUPvJ1DvpNlRDlDHxv8wN74wXyao7IpAgL7vBPTY1V9pbmPW_tdP3SISjkHp9UG0tEg8PQMQhAGh8bq7SFaTc2tRdiDJHKTYvFYFPIJuoLkmKA3K3THHyncsOk9fqOlaSTcQjmI27Z0f4wbt16xvIH_xAitwZ0j17HKv6bF62SNkDUjvVPd9t-3dVTvM4qq9yrtPrESpx206C16sh\",\"p\":\"1dggd6aIYBRcND9f-V64zlspZdKWpSlIqZYX21ltw7i_agFp5pS2fwtkJErSKA20myUohNop5uMxQiTWJeb2nHe_OzGsjG68By_EmP4DEPdyPY-8RZ45wMHYdVvCbfNHCYxuUATbQXH8jMIiuBQq7BZyMUQ-iF3eTY5SzgdY3-ROny7mqCHMDq44XuT26r0p9IkM4Jg9RBlg8fdvbnIuSfqPdSUOPa4I2j8RFEOsVSs0teXNuUmOO-ovXGBwe-P5\",\"q\":\"xsFWgVB6Av0zufrRGhLXfs5oBjg5Bg84qJbnuBSfOGTeHT8PLnu-G9YvwBxsq0KaoyRxLYS8cEPsqXj5eVk6qlzGeJwFHQr07UcpzgcQAgE7aWgLIp-q_BJ1rWg99msggvCHAI8F-WPS9SK1UT3vZqgWLzYiLKQJDgu0cf3fBCMVswHQenuiyRFyEqJYtlN4STZY2uVQQ3zXP0E53YHZjbwj7gO1O0uaDM1OVWfsTJiMXNUHW13Lt7CzlNgeWs9p\",\"qi\":\"gTOcxTsCHkDuDxsePtg0cG40TKBwc72DDsGBJK1OBVVOLT7llQvMwWtRmiXtrkJLNtjSpvKN7taDy3gZQPwrJnUCL5w10orpNkU5-8_nK2tBp4kL7okuGMzr185Vh55NTCtLW02itqBm-_oMjG7CQ_92vQ7xH5BP56whX7naUGrmIqmDbf7cYwLAGf8GywRstrorzug9RHvQMYsiUqWfTY57rmxEH3ZIw-bJ5a2Pkmzb31qCXcX9uc-H0uLXCFLP\"}");
        // publicKey = new JsonWebKey("{\"alg\":\"RS256\",\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"334703f667abaaf9826239ce88c52856\",\"n\":\"pgapT6UMCwD4x5df2XdgiaJTN4hFtTTjHruRwpqtdCdJijo3fYKtmbuT-xtqKvbaNtH_hkRGD_N8MULSXYTY8HZNfBgZkIvMyRz9gfu_Cu_TtxeeYZsnjnyK1IIXl1pfNOz9co7vq5PISgPW-6Mfsv1sUmFjNhOaA4hoH7gDTyEluo8lj-zswhVt9IFD-zhvlOYaN-4rUbVVy8-kGEhtDAC8kgv-w6XYUQ3a7tQFD3qjQkzxnMIE7zG-h21_CjoqTFQZfu6q1C9W1MIkGFzS9UZwoijPAwpk6OHwPruTg5hfFipktRf5E4DV3LKRF9kSg0ZM_YQF95oiQdDbdK-YS3qXErJqtO-Entep1pqluZS1BQgSqiIJ48-_5b46l_GZkWH2xvls46MlX5gxhkaES8DaWfKDmLaTYup3R-Y_EI3i4vDBMKoMBdS1JKRdoZxO9MY70qMLdQ0QcmgccC6i_PUCpbPvhQHp8lVgQ0T4_fopVCNIWJyaKj-kPN-jsNgh\",\"e\":\"AQAB\"}");
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

    [Fact]
    public void GenerateAndValidateSymmetricJwt()
    {
        var secretKey = RandomNumberGenerator.GetBytes(32);

        var handler = new JsonWebTokenHandler();
        var now = DateTime.UtcNow;

        var jwt = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Claims = new Dictionary<string, object> { { "sub", "336f0f1e54b7406e9bc693efa57a9f6a" } },
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secretKey), "HS256")
        });
        
        var result = handler.ValidateToken(jwt, new TokenValidationParameters
        {
            ValidIssuer = "me",
            ValidAudience = "you",
            IssuerSigningKey = new SymmetricSecurityKey(secretKey)
        });

        Assert.True(result.IsValid);
    }
}