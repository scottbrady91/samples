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
                new BigInteger(1, Base64UrlEncoder.DecodeBytes("A3hkIubgDggcoHzmVdXIm11gZ7UMaOa71JVf1eCifD8")),
                new BigInteger(1, Base64UrlEncoder.DecodeBytes("ejpRwmCvNMdXMOjR2DodOt09OLPgNUrcKA9hBslaFU0")));
            
            var handler = new JsonWebTokenHandler();

            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                SigningCredentials = new SigningCredentials(new BouncyCastleEcdsaSecurityKey(
                    new ECPrivateKeyParameters(new BigInteger(1, Base64UrlEncoder.DecodeBytes("e8HThqO0wR_Qw4pNIb80Cs0mYuCSqT6BSQj-o-tKTrg")), domainParams)), "ES256K")
            });
            Console.WriteLine(token);

             var result = handler.ValidateToken(
                token,
                new TokenValidationParameters
                {
                    ValidIssuer = "me",
                    ValidAudience = "you",
                    IssuerSigningKey = new BouncyCastleEcdsaSecurityKey(
                        new ECPublicKeyParameters(point, domainParams)) {KeyId = "123"}
                });

            Console.WriteLine($"Is signature valid: {result.IsValid}");
        }
    }

    public class CustomCryptoProvider : ICryptoProvider
    {
        public bool IsSupportedAlgorithm(string algorithm, params object[] args) => algorithm == "ES256K";
        
        public object Create(string algorithm, params object[] args)
        {
            if (algorithm == "ES256K"
                && args[0] is BouncyCastleEcdsaSecurityKey key)
            {
                return new CustomSignatureProvider(key, algorithm);
            }

            throw new NotSupportedException();
        }

        public void Release(object cryptoInstance)
        {
            if (cryptoInstance is IDisposable disposableObject)
                disposableObject.Dispose();
        }
    }

    public class CustomSignatureProvider : SignatureProvider 
    {
        public CustomSignatureProvider(BouncyCastleEcdsaSecurityKey key, string algorithm) 
            : base(key, algorithm) { }

        protected override void Dispose(bool disposing) { }

        public override byte[] Sign(byte[] input)
        {
            var ecDsaSigner = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
            BouncyCastleEcdsaSecurityKey key = Key as BouncyCastleEcdsaSecurityKey;
            
            ecDsaSigner.Init(true, key.KeyParameters);
            
            byte[] hashedInput;
            using (var hasher = SHA256.Create())
            {
                hashedInput = hasher.ComputeHash(input);
            }

            var output = ecDsaSigner.GenerateSignature(hashedInput);
            
            var r = output[0].ToByteArrayUnsigned();
            var s = output[1].ToByteArrayUnsigned();

            var signature = new byte[r.Length + s.Length];
            r.CopyTo(signature, 0);
            s.CopyTo(signature, r.Length);

            return signature;
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
        public BouncyCastleEcdsaSecurityKey(ECKeyParameters keyParameters)
        {
            KeyParameters = keyParameters;
            CryptoProviderFactory.CustomCryptoProvider = new CustomCryptoProvider();
        }

        public ECKeyParameters KeyParameters { get; }
        public override int KeySize => throw new NotImplementedException();

        [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus.")]
        public override bool HasPrivateKey => KeyParameters.IsPrivate;

        public override PrivateKeyStatus PrivateKeyStatus => KeyParameters.IsPrivate ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;
    }
}
