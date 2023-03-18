using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace RsaKeyLoading
{
    public class RsaKeyLoading
    {
        private readonly byte[] data = Encoding.UTF8.GetBytes("dooooooooooooom");

        [Fact]
        public void CreateNewKey()
        {
            var key = RSA.Create(3072);

            Verify(key);
        }

        [Fact]
        public void LoadJsonWebKeyFromParameters()
        {
            // Example RSA JWK
            // {
            //   "alg": "RS256",
            //   "kty": "RSA",
            //   "use": "sig",
            //   "kid": "334703f667abaaf9826239ce88c52856",
            //   "n": "pgapT6UMCwD4x5df2XdgiaJTN4hFtTTjHruRwpqtdCdJijo3fYKtmbuT-xtqKvbaNtH_hkRGD_N8MULSXYTY8HZNfBgZkIvMyRz9gfu_Cu_TtxeeYZsnjnyK1IIXl1pfNOz9co7vq5PISgPW-6Mfsv1sUmFjNhOaA4hoH7gDTyEluo8lj-zswhVt9IFD-zhvlOYaN-4rUbVVy8-kGEhtDAC8kgv-w6XYUQ3a7tQFD3qjQkzxnMIE7zG-h21_CjoqTFQZfu6q1C9W1MIkGFzS9UZwoijPAwpk6OHwPruTg5hfFipktRf5E4DV3LKRF9kSg0ZM_YQF95oiQdDbdK-YS3qXErJqtO-Entep1pqluZS1BQgSqiIJ48-_5b46l_GZkWH2xvls46MlX5gxhkaES8DaWfKDmLaTYup3R-Y_EI3i4vDBMKoMBdS1JKRdoZxO9MY70qMLdQ0QcmgccC6i_PUCpbPvhQHp8lVgQ0T4_fopVCNIWJyaKj-kPN-jsNgh",
            //   "e": "AQAB",
            //   "d": "DFWG2wafLisYkFVf1stOVfND_OZoDVX8QIJ9SeiNVcl8ZmM8T5v3cyoTDI7lFIOJwxRXSB2G2fUEBzHYaH-v0S9swrkUnx8vq8o2UCOIdhLKlvnPd59b8TMx6icvAvzBAXDQxGO3jPbZ5JvD6yZbesPmeflHslMC-Fu4JpEYV9bV03YCe56FmUaXyFgZGY8ABR8SGBEe0T9oPA-1OGObDE76s1vmRZkqyJy_pMoGBTgebFTEh1mHndCDf9Kj4zneX229WLgFIMAuUF6NsJIcvdoFQCM63saWQpI3JfbItYRqYEhjC5y7W-2y7DQGTNafMR8X38-GebhJvHCm4qiXzenbdQIHeEE85BWzHw9M2YlSZ8vMl3zQQMTh1vMZg07eYqwzr1zMYxI8HJAQKB8NR2VDe0XQS7vWouV4KTGvw4BLY0wNAy2vOKbyCEvyiBpYTrGYkpgjspJHbxJMGscq0vm90CsALvWnd4BpKoFBPiCBnshYddZAur6DKLBlNW6R",
            //   "dp": "u5ZWFN_fbfkuUR7vAAAZudu6Wvn68HNgrHNgBilS4ohkUYdf8Mevt460kCmaZUxwjFByVOhULZhLE6zgtmr_Fo7tD-4pYR-ajetXWKYq5m1Kp7o4_BEqtG7XhUuzKWRpgnTQKB26gJSPaKK8diIq7ONb1N_6wwElC3-4H8fOLMlINtebuw26xX4LMSNFfvHlpf-7biHeTKi-pEPcWlSLSpYj1i1larIKTflY8B_VQvkdyhsG9m0R-nkahryKsANx",
            //   "dq": "uSEU5laDj40xRSYu5s5uExtHIaP02YQMDlyhcYEj3W92xF8cUPvJ1DvpNlRDlDHxv8wN74wXyao7IpAgL7vBPTY1V9pbmPW_tdP3SISjkHp9UG0tEg8PQMQhAGh8bq7SFaTc2tRdiDJHKTYvFYFPIJuoLkmKA3K3THHyncsOk9fqOlaSTcQjmI27Z0f4wbt16xvIH_xAitwZ0j17HKv6bF62SNkDUjvVPd9t-3dVTvM4qq9yrtPrESpx206C16sh",
            //   "p": "1dggd6aIYBRcND9f-V64zlspZdKWpSlIqZYX21ltw7i_agFp5pS2fwtkJErSKA20myUohNop5uMxQiTWJeb2nHe_OzGsjG68By_EmP4DEPdyPY-8RZ45wMHYdVvCbfNHCYxuUATbQXH8jMIiuBQq7BZyMUQ-iF3eTY5SzgdY3-ROny7mqCHMDq44XuT26r0p9IkM4Jg9RBlg8fdvbnIuSfqPdSUOPa4I2j8RFEOsVSs0teXNuUmOO-ovXGBwe-P5",
            //   "q": "xsFWgVB6Av0zufrRGhLXfs5oBjg5Bg84qJbnuBSfOGTeHT8PLnu-G9YvwBxsq0KaoyRxLYS8cEPsqXj5eVk6qlzGeJwFHQr07UcpzgcQAgE7aWgLIp-q_BJ1rWg99msggvCHAI8F-WPS9SK1UT3vZqgWLzYiLKQJDgu0cf3fBCMVswHQenuiyRFyEqJYtlN4STZY2uVQQ3zXP0E53YHZjbwj7gO1O0uaDM1OVWfsTJiMXNUHW13Lt7CzlNgeWs9p",
            //   "qi": "gTOcxTsCHkDuDxsePtg0cG40TKBwc72DDsGBJK1OBVVOLT7llQvMwWtRmiXtrkJLNtjSpvKN7taDy3gZQPwrJnUCL5w10orpNkU5-8_nK2tBp4kL7okuGMzr185Vh55NTCtLW02itqBm-_oMjG7CQ_92vQ7xH5BP56whX7naUGrmIqmDbf7cYwLAGf8GywRstrorzug9RHvQMYsiUqWfTY57rmxEH3ZIw-bJ5a2Pkmzb31qCXcX9uc-H0uLXCFLP",
            // }

            var rsaParameters = new RSAParameters
            {
                // PUBLIC KEY PARAMETERS
                // n parameter - public modulus
                Modulus = Base64UrlEncoder.DecodeBytes("pgapT6UMCwD4x5df2XdgiaJTN4hFtTTjHruRwpqtdCdJijo3fYKtmbuT-xtqKvbaNtH_hkRGD_N8MULSXYTY8HZNfBgZkIvMyRz9gfu_Cu_TtxeeYZsnjnyK1IIXl1pfNOz9co7vq5PISgPW-6Mfsv1sUmFjNhOaA4hoH7gDTyEluo8lj-zswhVt9IFD-zhvlOYaN-4rUbVVy8-kGEhtDAC8kgv-w6XYUQ3a7tQFD3qjQkzxnMIE7zG-h21_CjoqTFQZfu6q1C9W1MIkGFzS9UZwoijPAwpk6OHwPruTg5hfFipktRf5E4DV3LKRF9kSg0ZM_YQF95oiQdDbdK-YS3qXErJqtO-Entep1pqluZS1BQgSqiIJ48-_5b46l_GZkWH2xvls46MlX5gxhkaES8DaWfKDmLaTYup3R-Y_EI3i4vDBMKoMBdS1JKRdoZxO9MY70qMLdQ0QcmgccC6i_PUCpbPvhQHp8lVgQ0T4_fopVCNIWJyaKj-kPN-jsNgh"),
                // e parameter - public exponent
                Exponent = Base64UrlEncoder.DecodeBytes("AQAB"),
                
                // PRIVATE KEY PARAMETERS
                // d parameter - the private exponent value for the RSA key 
                D = Base64UrlEncoder.DecodeBytes("DFWG2wafLisYkFVf1stOVfND_OZoDVX8QIJ9SeiNVcl8ZmM8T5v3cyoTDI7lFIOJwxRXSB2G2fUEBzHYaH-v0S9swrkUnx8vq8o2UCOIdhLKlvnPd59b8TMx6icvAvzBAXDQxGO3jPbZ5JvD6yZbesPmeflHslMC-Fu4JpEYV9bV03YCe56FmUaXyFgZGY8ABR8SGBEe0T9oPA-1OGObDE76s1vmRZkqyJy_pMoGBTgebFTEh1mHndCDf9Kj4zneX229WLgFIMAuUF6NsJIcvdoFQCM63saWQpI3JfbItYRqYEhjC5y7W-2y7DQGTNafMR8X38-GebhJvHCm4qiXzenbdQIHeEE85BWzHw9M2YlSZ8vMl3zQQMTh1vMZg07eYqwzr1zMYxI8HJAQKB8NR2VDe0XQS7vWouV4KTGvw4BLY0wNAy2vOKbyCEvyiBpYTrGYkpgjspJHbxJMGscq0vm90CsALvWnd4BpKoFBPiCBnshYddZAur6DKLBlNW6R"),
                // dp parameter - CRT exponent of the first factor
                DP = Base64UrlEncoder.DecodeBytes("u5ZWFN_fbfkuUR7vAAAZudu6Wvn68HNgrHNgBilS4ohkUYdf8Mevt460kCmaZUxwjFByVOhULZhLE6zgtmr_Fo7tD-4pYR-ajetXWKYq5m1Kp7o4_BEqtG7XhUuzKWRpgnTQKB26gJSPaKK8diIq7ONb1N_6wwElC3-4H8fOLMlINtebuw26xX4LMSNFfvHlpf-7biHeTKi-pEPcWlSLSpYj1i1larIKTflY8B_VQvkdyhsG9m0R-nkahryKsANx"),
                // dq parameter - CRT exponent of the second factor
                DQ = Base64UrlEncoder.DecodeBytes("uSEU5laDj40xRSYu5s5uExtHIaP02YQMDlyhcYEj3W92xF8cUPvJ1DvpNlRDlDHxv8wN74wXyao7IpAgL7vBPTY1V9pbmPW_tdP3SISjkHp9UG0tEg8PQMQhAGh8bq7SFaTc2tRdiDJHKTYvFYFPIJuoLkmKA3K3THHyncsOk9fqOlaSTcQjmI27Z0f4wbt16xvIH_xAitwZ0j17HKv6bF62SNkDUjvVPd9t-3dVTvM4qq9yrtPrESpx206C16sh"),
                // p parameter - first prime factor
                P = Base64UrlEncoder.DecodeBytes("1dggd6aIYBRcND9f-V64zlspZdKWpSlIqZYX21ltw7i_agFp5pS2fwtkJErSKA20myUohNop5uMxQiTWJeb2nHe_OzGsjG68By_EmP4DEPdyPY-8RZ45wMHYdVvCbfNHCYxuUATbQXH8jMIiuBQq7BZyMUQ-iF3eTY5SzgdY3-ROny7mqCHMDq44XuT26r0p9IkM4Jg9RBlg8fdvbnIuSfqPdSUOPa4I2j8RFEOsVSs0teXNuUmOO-ovXGBwe-P5"),
                // q parameter - second prime factor
                Q = Base64UrlEncoder.DecodeBytes("xsFWgVB6Av0zufrRGhLXfs5oBjg5Bg84qJbnuBSfOGTeHT8PLnu-G9YvwBxsq0KaoyRxLYS8cEPsqXj5eVk6qlzGeJwFHQr07UcpzgcQAgE7aWgLIp-q_BJ1rWg99msggvCHAI8F-WPS9SK1UT3vZqgWLzYiLKQJDgu0cf3fBCMVswHQenuiyRFyEqJYtlN4STZY2uVQQ3zXP0E53YHZjbwj7gO1O0uaDM1OVWfsTJiMXNUHW13Lt7CzlNgeWs9p"),
                // qi parameter - CRT coefficient of the second factor
                InverseQ = Base64UrlEncoder.DecodeBytes("gTOcxTsCHkDuDxsePtg0cG40TKBwc72DDsGBJK1OBVVOLT7llQvMwWtRmiXtrkJLNtjSpvKN7taDy3gZQPwrJnUCL5w10orpNkU5-8_nK2tBp4kL7okuGMzr185Vh55NTCtLW02itqBm-_oMjG7CQ_92vQ7xH5BP56whX7naUGrmIqmDbf7cYwLAGf8GywRstrorzug9RHvQMYsiUqWfTY57rmxEH3ZIw-bJ5a2Pkmzb31qCXcX9uc-H0uLXCFLP")
            };

            var key = RSA.Create(rsaParameters);
            
            Verify(key);
        }

        [Fact]
        public void LoadJsonWebKeyFromIdentityModel()
        {
            //   "alg": "RS256",
            //   "kty": "RSA",
            //   "use": "sig",
            //   "kid": "334703f667abaaf9826239ce88c52856"
            //   "n": "pgapT6UMCwD4x5df2XdgiaJTN4hFtTTjHruRwpqtdCdJijo3fYKtmbuT-xtqKvbaNtH_hkRGD_N8MULSXYTY8HZNfBgZkIvMyRz9gfu_Cu_TtxeeYZsnjnyK1IIXl1pfNOz9co7vq5PISgPW-6Mfsv1sUmFjNhOaA4hoH7gDTyEluo8lj-zswhVt9IFD-zhvlOYaN-4rUbVVy8-kGEhtDAC8kgv-w6XYUQ3a7tQFD3qjQkzxnMIE7zG-h21_CjoqTFQZfu6q1C9W1MIkGFzS9UZwoijPAwpk6OHwPruTg5hfFipktRf5E4DV3LKRF9kSg0ZM_YQF95oiQdDbdK-YS3qXErJqtO-Entep1pqluZS1BQgSqiIJ48-_5b46l_GZkWH2xvls46MlX5gxhkaES8DaWfKDmLaTYup3R-Y_EI3i4vDBMKoMBdS1JKRdoZxO9MY70qMLdQ0QcmgccC6i_PUCpbPvhQHp8lVgQ0T4_fopVCNIWJyaKj-kPN-jsNgh",
            //   "e": "AQAB",
            const string json = "{\"alg\":\"RS256\",\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"334703f667abaaf9826239ce88c52856\",\"n\":\"pgapT6UMCwD4x5df2XdgiaJTN4hFtTTjHruRwpqtdCdJijo3fYKtmbuT-xtqKvbaNtH_hkRGD_N8MULSXYTY8HZNfBgZkIvMyRz9gfu_Cu_TtxeeYZsnjnyK1IIXl1pfNOz9co7vq5PISgPW-6Mfsv1sUmFjNhOaA4hoH7gDTyEluo8lj-zswhVt9IFD-zhvlOYaN-4rUbVVy8-kGEhtDAC8kgv-w6XYUQ3a7tQFD3qjQkzxnMIE7zG-h21_CjoqTFQZfu6q1C9W1MIkGFzS9UZwoijPAwpk6OHwPruTg5hfFipktRf5E4DV3LKRF9kSg0ZM_YQF95oiQdDbdK-YS3qXErJqtO-Entep1pqluZS1BQgSqiIJ48-_5b46l_GZkWH2xvls46MlX5gxhkaES8DaWfKDmLaTYup3R-Y_EI3i4vDBMKoMBdS1JKRdoZxO9MY70qMLdQ0QcmgccC6i_PUCpbPvhQHp8lVgQ0T4_fopVCNIWJyaKj-kPN-jsNgh\",\"e\":\"AQAB\",\"d\":\"DFWG2wafLisYkFVf1stOVfND_OZoDVX8QIJ9SeiNVcl8ZmM8T5v3cyoTDI7lFIOJwxRXSB2G2fUEBzHYaH-v0S9swrkUnx8vq8o2UCOIdhLKlvnPd59b8TMx6icvAvzBAXDQxGO3jPbZ5JvD6yZbesPmeflHslMC-Fu4JpEYV9bV03YCe56FmUaXyFgZGY8ABR8SGBEe0T9oPA-1OGObDE76s1vmRZkqyJy_pMoGBTgebFTEh1mHndCDf9Kj4zneX229WLgFIMAuUF6NsJIcvdoFQCM63saWQpI3JfbItYRqYEhjC5y7W-2y7DQGTNafMR8X38-GebhJvHCm4qiXzenbdQIHeEE85BWzHw9M2YlSZ8vMl3zQQMTh1vMZg07eYqwzr1zMYxI8HJAQKB8NR2VDe0XQS7vWouV4KTGvw4BLY0wNAy2vOKbyCEvyiBpYTrGYkpgjspJHbxJMGscq0vm90CsALvWnd4BpKoFBPiCBnshYddZAur6DKLBlNW6R\",\"dp\":\"u5ZWFN_fbfkuUR7vAAAZudu6Wvn68HNgrHNgBilS4ohkUYdf8Mevt460kCmaZUxwjFByVOhULZhLE6zgtmr_Fo7tD-4pYR-ajetXWKYq5m1Kp7o4_BEqtG7XhUuzKWRpgnTQKB26gJSPaKK8diIq7ONb1N_6wwElC3-4H8fOLMlINtebuw26xX4LMSNFfvHlpf-7biHeTKi-pEPcWlSLSpYj1i1larIKTflY8B_VQvkdyhsG9m0R-nkahryKsANx\",\"dq\":\"uSEU5laDj40xRSYu5s5uExtHIaP02YQMDlyhcYEj3W92xF8cUPvJ1DvpNlRDlDHxv8wN74wXyao7IpAgL7vBPTY1V9pbmPW_tdP3SISjkHp9UG0tEg8PQMQhAGh8bq7SFaTc2tRdiDJHKTYvFYFPIJuoLkmKA3K3THHyncsOk9fqOlaSTcQjmI27Z0f4wbt16xvIH_xAitwZ0j17HKv6bF62SNkDUjvVPd9t-3dVTvM4qq9yrtPrESpx206C16sh\",\"p\":\"1dggd6aIYBRcND9f-V64zlspZdKWpSlIqZYX21ltw7i_agFp5pS2fwtkJErSKA20myUohNop5uMxQiTWJeb2nHe_OzGsjG68By_EmP4DEPdyPY-8RZ45wMHYdVvCbfNHCYxuUATbQXH8jMIiuBQq7BZyMUQ-iF3eTY5SzgdY3-ROny7mqCHMDq44XuT26r0p9IkM4Jg9RBlg8fdvbnIuSfqPdSUOPa4I2j8RFEOsVSs0teXNuUmOO-ovXGBwe-P5\",\"q\":\"xsFWgVB6Av0zufrRGhLXfs5oBjg5Bg84qJbnuBSfOGTeHT8PLnu-G9YvwBxsq0KaoyRxLYS8cEPsqXj5eVk6qlzGeJwFHQr07UcpzgcQAgE7aWgLIp-q_BJ1rWg99msggvCHAI8F-WPS9SK1UT3vZqgWLzYiLKQJDgu0cf3fBCMVswHQenuiyRFyEqJYtlN4STZY2uVQQ3zXP0E53YHZjbwj7gO1O0uaDM1OVWfsTJiMXNUHW13Lt7CzlNgeWs9p\",\"qi\":\"gTOcxTsCHkDuDxsePtg0cG40TKBwc72DDsGBJK1OBVVOLT7llQvMwWtRmiXtrkJLNtjSpvKN7taDy3gZQPwrJnUCL5w10orpNkU5-8_nK2tBp4kL7okuGMzr185Vh55NTCtLW02itqBm-_oMjG7CQ_92vQ7xH5BP56whX7naUGrmIqmDbf7cYwLAGf8GywRstrorzug9RHvQMYsiUqWfTY57rmxEH3ZIw-bJ5a2Pkmzb31qCXcX9uc-H0uLXCFLP\"}";

            IdentityModelEventSource.ShowPII = true;
            var jsonWebKey = new JsonWebKey(json);
            // var rsaParameters = jsonWebKey.CreateRsaParameters(); // is internal 😭 
            
            var rsaParameters = new RSAParameters
            {
                // PUBLIC KEY PARAMETERS
                // n parameter - public modulus
                Modulus = Base64UrlEncoder.DecodeBytes(jsonWebKey.N),
                // e parameter - public exponent
                Exponent = Base64UrlEncoder.DecodeBytes(jsonWebKey.E),
                
                // PRIVATE KEY PARAMETERS
                // d parameter - the private exponent value for the RSA key 
                D = Base64UrlEncoder.DecodeBytes(jsonWebKey.D),
                // dp parameter - CRT exponent of the first factor
                DP = Base64UrlEncoder.DecodeBytes(jsonWebKey.DP),
                // dq parameter - CRT exponent of the second factor
                DQ = Base64UrlEncoder.DecodeBytes(jsonWebKey.DQ),
                // p parameter - first prime factor
                P = Base64UrlEncoder.DecodeBytes(jsonWebKey.P),
                // q parameter - second prime factor
                Q = Base64UrlEncoder.DecodeBytes(jsonWebKey.Q),
                // qi parameter - CRT coefficient of the second factor
                InverseQ = Base64UrlEncoder.DecodeBytes(jsonWebKey.QI)
            };

            var key = RSA.Create(rsaParameters);
            
            Verify(key);
        }

        [Fact]
        public void LoadFromX509()
        {
            // testing against in-memory certificate (HashAlgorithmName and RSASignaturePadding are only used in certificate signing)
            X509Certificate2 cert = new CertificateRequest("cn=Test", RSA.Create(3072), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                .CreateSelfSigned(DateTime.UtcNow.AddDays(-2), DateTime.UtcNow.AddDays(2));

            var key = cert.GetRSAPrivateKey();
            // var publicKey = cert.GetRSAPublicKey();

            Verify(key);
        }

        [Fact]
        public void LoadFromPem()
        {
            var key = RSA.Create();
            
            // PKCS#1 (BEGIN RSA PRIVATE KEY) $openssl genrsa -out key-pkcs1.pem 3072)
            key.ImportFromPem(File.ReadAllText("key-pkcs1.pem"));
            Verify(key);
            
            // PKCS#8 (BEGIN PRIVATE KEY) $openssl genpkey -algorithm RSA -out key-pkcs8.pem -pkeyopt rsa_keygen_bits:3072
            key.ImportFromPem(File.ReadAllText("key-pkcs8.pem"));
            Verify(key);
        }
        
        
        private void Verify(RSA key)
        {
            // (RSASSA-PKCS1-v1_5 using SHA-256)
            var hashingAlgorithm = HashAlgorithmName.SHA256;
            var signaturePadding = RSASignaturePadding.Pkcs1;
            
            // create signature with private key
            var signature = key.SignData(data, hashingAlgorithm, signaturePadding);
            
            // validate signature with public key
            var publicKey = RSA.Create(key.ExportParameters(includePrivateParameters: false));
            publicKey.VerifyData(data, signature, hashingAlgorithm, signaturePadding);
        }
    }
}