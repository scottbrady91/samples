using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Client.Config
{
    internal static class Cert
    {
        // Private Key used to decrypt incoming tokens
        public static X509Certificate2 LoadEncrypting()
        {
            var assembly = typeof(Cert).Assembly;
            using (var stream = assembly.GetManifestResourceStream(
                "Client.Config.ScottBrady91.pfx"))
            {
                return new X509Certificate2(ReadStream(stream), "password");
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