using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace EcdsaXmlSigning
{
    public class Program
    {
        public static void Main()
        {
            const string xml = "<message>Just remember ALL CAPS when you spell the man name</message>";
            var xmlDoc = new XmlDocument {PreserveWhitespace = true};
            xmlDoc.LoadXml(xml);

            var rsa = RSA.Create(3072);
            var cert = new CertificateRequest("CN=test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(-2));
            var pubCert = new X509Certificate2(cert.Export(X509ContentType.Cert));

            var signedXml = SignXml(xmlDoc.DocumentElement, cert, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            xmlDoc.DocumentElement?.AppendChild(signedXml);
            
            Console.WriteLine(xmlDoc.OuterXml);
            
            Console.WriteLine("Valid signature? " +ValidateSignature(xmlDoc.DocumentElement, pubCert));
        }

        private static XmlElement SignXml(XmlElement xml, X509Certificate2 cert, string signatureMethod)
        {
            var signedXml = new SignedXml(xml) {SigningKey = cert.PrivateKey};
            signedXml.SignedInfo.SignatureMethod = signatureMethod;
            signedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";

            var reference = new Reference {Uri = string.Empty}; // sign whole document
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);

            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));
            signedXml.KeyInfo = keyInfo;
            
            signedXml.ComputeSignature();
            
            return signedXml.GetXml();
        }

        private static bool ValidateSignature(XmlElement xml, X509Certificate2 cert)
        {
            var signedXml = new SignedXml(xml);

            var signatureElement = xml.GetElementsByTagName("Signature");
            signedXml.LoadXml((XmlElement) signatureElement[0]);
            
            // validate references here!
            if ((signedXml.SignedInfo.References[0] as Reference)?.Uri != "")
                throw new InvalidOperationException("Check your references!");
            
            return signedXml.CheckSignature(cert, true);
        }
    }
}
