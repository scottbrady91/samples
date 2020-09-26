using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Sodium;

namespace ScottBrady.Samples.XChaCha20Poly1305
{
    public class Program
    {
        public static void Main()
        {
            var key = new byte[32];
            RandomNumberGenerator.Create().GetBytes(key);
            Console.WriteLine($"Key: {Convert.ToBase64String(key)}");
            
            var nonce = new byte[24];
            RandomNumberGenerator.Create().GetBytes(nonce);
            Console.WriteLine($"Nonce (IV): {Convert.ToBase64String(nonce)}");

            const string message = "Got more soul than a sock with a hole";
            
            
            
            UsingLibsodium(key, nonce, Encoding.UTF8.GetBytes(message));
        }

        /// <summary>
        /// XChaCha20-Poly1305 in .NET using libsodium
        /// https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
        /// </summary>
        public static void UsingLibsodium(byte[] key, byte[] nonce, byte[] plaintext)
        {
            // crypto_aead_xchacha20poly1305_ietf_encrypt
            var ciphertext = SecretAeadXChaCha20Poly1305.Encrypt(plaintext, nonce, key);
            
            // crypto_aead_xchacha20poly1305_ietf_decrypt
            var decyptedPlaintext = SecretAeadXChaCha20Poly1305.Decrypt(ciphertext, nonce, key);
            Console.WriteLine($"Decrypted message: {Encoding.UTF8.GetString(decyptedPlaintext)}");
        }

        // "Rolling your own crypto" with XChaCha20-Poly1305 in .NET
        public static void UsingBouncyCastle()
        {
            
        }
    }
}