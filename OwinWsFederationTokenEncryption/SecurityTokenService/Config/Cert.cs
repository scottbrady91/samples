using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace SecurityTokenService.Config
{
    internal static class Cert
    {
        // Private Key used to sign outbound tokens
        public static X509Certificate2 LoadSigning()
        {
            var assembly = typeof(Cert).Assembly;
            using (var stream = assembly.GetManifestResourceStream(
                "SecurityTokenService.Config.idsrv3test.pfx"))
            {
                return new X509Certificate2(ReadStream(stream), "idsrv3test");
            }
        }

        // Public Key used to encrypt outbound tokens
        public static X509Certificate2 LoadEncrypting()
        {
            var assembly = typeof(Cert).Assembly;
            using (var stream = assembly.GetManifestResourceStream(
                "SecurityTokenService.Config.ScottBrady91.cer"))
            {
                return new X509Certificate2(ReadStream(stream));
            }
        }

        private static byte[] ReadStream(Stream input)
        {
            var buffer = new byte[16 * 1024];
            using (var ms = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }
    }
}