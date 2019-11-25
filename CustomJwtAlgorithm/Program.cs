using System;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace ScottBrady91.BlogExampleCode.CustomJwtAlgorithm
{
    public class Program
    {
        public static void Main()
        {
            X9ECParameters secp256k1 = ECNamedCurveTable.GetByName("secp256k1");
            ECDomainParameters domainParams = new ECDomainParameters(secp256k1.Curve, secp256k1.G, secp256k1.N, secp256k1.H, secp256k1.GetSeed());

            var point = secp256k1.Curve.CreatePoint(
                new BigInteger(1, Base64UrlEncoder.DecodeBytes("qTx9ZWn9A6eCT0AXbFAY7kPycIsMDix7ywNg9ALAz3U")),
                new BigInteger(1, Base64UrlEncoder.DecodeBytes("6c373eX_qcg4AYlLD5obBAabYrUNd1WVJbTtwUhllFw")));
            
            var handler = new JsonWebTokenHandler();
            var result = handler.ValidateToken(
                "eyJraWQiOiIxMjMiLCJhbGciOiJFUzI1NksifQ.eyJhdWQiOiJ5b3UiLCJzdWIiOiJib2IiLCJpc3MiOiJtZSIsImV4cCI6NjE1MzgwNTQ0MDB9.lgIe5Ca_skeih7vpZBSU-NrVPza4eG0rjv_z-vTIzyXPRsuxAERHbIGs4VtKFs0CZo3Y-v0mVA9fsxZVgwUg9Q",
                new TokenValidationParameters
                {
                    ValidIssuer = "me",
                    ValidAudience = "you",
                    IssuerSigningKey = new BouncyCastleEcdsaSecurityKey
                    {
                        KeyId = "123",
                        KeyParameters = new ECPublicKeyParameters(point, domainParams),
                        CryptoProviderFactory = new CryptoProviderFactory {CustomCryptoProvider = new CustomCryptoProvider()}
                    }
                });

            Console.WriteLine(result.IsValid);
        }
    }

    public class CustomCryptoProvider : ICryptoProvider
    {
        public bool IsSupportedAlgorithm(string algorithm, params object[] args) => algorithm == "ES256K";
        
        public object Create(string algorithm, params object[] args)
        {
            if (algorithm == "ES256K") return new CustomSignatureProvider(args[0] as BouncyCastleEcdsaSecurityKey, algorithm);
            throw new NotSupportedException();
        }

        public void Release(object cryptoInstance)
        {
            if (cryptoInstance is IDisposable disposableObject)
                disposableObject.Dispose();
        }
    }

    public class CustomSignatureProvider : SignatureProvider {
        public CustomSignatureProvider(BouncyCastleEcdsaSecurityKey key, string algorithm) : base(key, algorithm) { }

        protected override void Dispose(bool disposing) { }

        public override byte[] Sign(byte[] input)
        {
            throw new NotImplementedException();
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            var ecDsaSigner = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
            BouncyCastleEcdsaSecurityKey key = Key as BouncyCastleEcdsaSecurityKey;

            ecDsaSigner.Init(false, key.KeyParameters);

            byte[] hashedInput;

            using (var hasher = SHA256.Create())
            {
                hashedInput = hasher.ComputeHash(input);
            }

            var r = new BigInteger(1, signature.Take(32).ToArray());
            var s = new BigInteger(1, signature.Skip(32).ToArray());

            return ecDsaSigner.VerifySignature(hashedInput, r, s);
        }
    }

    public class BouncyCastleEcdsaSecurityKey : AsymmetricSecurityKey
    {
        public ECKeyParameters KeyParameters { get; set; }
        public override int KeySize { get; }

        [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus.")]
        public override bool HasPrivateKey => KeyParameters.IsPrivate;
        public override PrivateKeyStatus PrivateKeyStatus => KeyParameters.IsPrivate ? PrivateKeyStatus.Exists : PrivateKeyStatus.Unknown;
    }
}
