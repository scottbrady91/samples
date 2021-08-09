using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace XmlSigning
{
    public class Program
    {
        public static void Main()
        {
            const string text = "<message><content>Just remember ALL CAPS when you spell the man name</content></message>";
            var xml = new XmlDocument {PreserveWhitespace = true, XmlResolver = null};
            xml.LoadXml(text);
            
            // register custom signing algorithm
            CryptoConfig.AddAlgorithm(typeof(Ecdsa256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");

            
            // RSASSA-PKCS1-v1_5 using SHA-256
            // const string signingAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            // var rsa = RSA.Create(3072);
            // var cert = new CertificateRequest("CN=test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            //     .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(-2));
            // var pubCert = new X509Certificate2(cert.Export(X509ContentType.Cert));

            
            // ECDSA using P-256 and SHA-256
            const string signingAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
            var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var cert = new CertificateRequest("CN=test", ecdsa, HashAlgorithmName.SHA256)
                .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(-2));
            var pubCert = new X509Certificate2(cert.Export(X509ContentType.Cert));

            
            var signedXml = SignXml(xml.DocumentElement, cert, signingAlgorithm);
            xml.DocumentElement?.AppendChild(signedXml);
            
            Console.WriteLine(xml.OuterXml);
            
            Console.WriteLine("Valid signature? " + ValidateSignature(xml.DocumentElement, pubCert));
        }

        private static XmlElement SignXml(XmlElement xml, X509Certificate2 cert, string signatureMethod)
        {
            // X509Certificate2.PrivateKey is being deprecated
            var key = (AsymmetricAlgorithm) cert.GetRSAPrivateKey() ?? cert.GetECDsaPrivateKey();
            
            // set key, signing algorithm, and canonicalization method
            var signedXml = new SignedXml(xml) {SigningKey = key};
            signedXml.SignedInfo.SignatureMethod = signatureMethod;
            signedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";

            // sign whole document using "SAML style" transforms
            var reference = new Reference {Uri = string.Empty}; 
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);

            // OPTIONAL: embed the public key in the XML.
            // This MUST NOT be trusted during validation (used for debugging only)
            /*var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));
            signedXml.KeyInfo = keyInfo;*/

            // create signature
            signedXml.ComputeSignature();
            
            // get signature XML element
            return signedXml.GetXml();
        }

        private static bool ValidateSignature(XmlElement xml, X509Certificate2 cert)
        {
            var signedXml = new SignedXml(xml);

            // double check the schema
            // usually we would validate using XPath
            var signatureElement = xml.GetElementsByTagName("Signature");
            if (signatureElement.Count != 1)
                throw new InvalidOperationException("Too many signatures!");
            
            signedXml.LoadXml((XmlElement) signatureElement[0]);
            
            // validate references here!
            if ((signedXml.SignedInfo.References[0] as Reference)?.Uri != "")
                throw new InvalidOperationException("Check your references!");

            return signedXml.CheckSignature((AsymmetricAlgorithm) cert.GetRSAPublicKey() ?? cert.GetECDsaPublicKey());
        }
    }

    public class Ecdsa256SignatureDescription : SignatureDescription
    {
        public Ecdsa256SignatureDescription()
        {
            KeyAlgorithm = typeof(ECDsa).AssemblyQualifiedName;
        }
        
        public override HashAlgorithm CreateDigest() => SHA256.Create();

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 256) throw new InvalidOperationException("Requires EC key using P-256");
            return new EcdsaSignatureFormatter(ecdsa);
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 256) throw new InvalidOperationException("Requires EC key using P-256");
            return new EcdsaSignatureDeformatter(ecdsa);
        }
    }

    public class EcdsaSignatureFormatter : AsymmetricSignatureFormatter
    {
        private ECDsa key;

        public EcdsaSignatureFormatter(ECDsa key) => this.key = key;

        public override void SetKey(AsymmetricAlgorithm key) => this.key = key as ECDsa;
        
        public override void SetHashAlgorithm(string strName) { }

        public override byte[] CreateSignature(byte[] rgbHash) => key.SignHash(rgbHash);
    }

    public class EcdsaSignatureDeformatter : AsymmetricSignatureDeformatter
    {
        private ECDsa key;

        public EcdsaSignatureDeformatter(ECDsa key) => this.key = key;

        public override void SetKey(AsymmetricAlgorithm key) => this.key = key as ECDsa;
        
        public override void SetHashAlgorithm(string strName) { }

        public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature) => key.VerifyHash(rgbHash, rgbSignature);
    }
}
