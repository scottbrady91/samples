using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace EcdsaKeyLoading
{
    public class EcdsaKeyLoading
    {
        private readonly byte[] data = Encoding.UTF8.GetBytes("dooooooooooooom");
        
        [Fact] // OPTION 1: Have .NET generate an EC key for you
        public void CreateNewKey()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Verify(key);
        }
        
        [Fact] // OPTION 2: Load an EC from a JWK
        public void LoadKeyFromParameters()
        {
            // {
            //   "kty": "EC",
            //   "crv": "P-256",
            //   "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            //   "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            //   "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
            //   "use: "sig",
            //   "kid": "my EC key"
            // }

            const string crv = "P-256";
            const string d = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";
            const string x = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
            const string y = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
            
            // parse curve from JOSE format
            // https://www.iana.org/assignments/jose/jose.xhtml#web-key-elliptic-curve
            var curve = crv switch
            {
                "P-256" => ECCurve.NamedCurves.nistP256,
                "P-384" => ECCurve.NamedCurves.nistP384,
                "P-521" => ECCurve.NamedCurves.nistP521,
                _ => throw new NotSupportedException()
            };

            using var key = ECDsa.Create(new ECParameters
            {
                Curve = curve,
                D = Base64UrlEncoder.DecodeBytes(d), // optional private key
                Q = new ECPoint
                {
                    X = Base64UrlEncoder.DecodeBytes(x),
                    Y = Base64UrlEncoder.DecodeBytes(y)
                }
            });
            
            Verify(key);
        }
        
        [Fact] // OPTION 3: Load an EC from an X.509
        public void LoadFromX509()
        {
            var cert = new CertificateRequest("cn=Test", ECDsa.Create(ECCurve.NamedCurves.nistP256), HashAlgorithmName.SHA256)
                .CreateSelfSigned(DateTime.UtcNow.AddDays(-2), DateTime.UtcNow.AddDays(2));
            using var key = cert.GetECDsaPrivateKey();
            
            Verify(key);
        }
        
        [Fact] // OPTION 4: Load an EC from hex string
        public void LoadFromHex()
        {
            const string privateKey = "c711e5080f2b58260fe19741a7913e8301c1128ec8e80b8009406e5047e6e1ef";
            const string publicKey = "04e33993f0210a4973a94c26667007d1b56fe886e8b3c2afdd66aa9e4937478ad20acfbdc666e3cec3510ce85d40365fc2045e5adb7e675198cf57c6638efa1bdb";
            
#if NET5_0_OR_GREATER
            var privateKeyBytes = Convert.FromHexString(privateKey);
            var publicKeyBytes = Convert.FromHexString(publicKey);
#else
            var privateKeyBytes = FromHexString(privateKey);
            var publicKeyBytes = FromHexString(publicKey);
#endif
            
            using var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privateKeyBytes,
                Q = new ECPoint
                {
                    X = publicKeyBytes.Skip(1).Take(32).ToArray(),
                    Y = publicKeyBytes.Skip(33).ToArray()
                }
            });

            Verify(key);
        }
        
        private void Verify(ECDsa key)
        {
            // create signature (ECDSA P-256 with SHA-256)
            var signature = key.SignData(data, HashAlgorithmName.SHA256);
            
            // validate signature with public key
            using var pubKey = ECDsa.Create(key.ExportParameters(false));
            pubKey.VerifyData(data, signature, HashAlgorithmName.SHA256).Should().BeTrue();
        }
        
        private static byte[] FromHexString(string hex) {
            var numberChars = hex.Length;
            var hexAsBytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2)
                hexAsBytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

            return hexAsBytes;
        }
    }
}