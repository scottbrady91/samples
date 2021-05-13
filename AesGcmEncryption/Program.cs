using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace AesGcmEncryption
{
    public class Program
    {
        public static void Main()
        {
            var plaintextBytes = new byte[8192];
            RandomNumberGenerator.Fill(plaintextBytes);
            var plaintext = Convert.ToBase64String(plaintextBytes);

            var key = new byte[32];
            RandomNumberGenerator.Fill(key);

            var (ciphertext, nonce, tag) = EncryptWithNet(plaintext, key);
            // var (ciphertext, nonce, tag) = EncryptWithBouncyCastle(plaintext, key);
            var decryptedPlaintext = DecryptWithNet(ciphertext, nonce, tag, key);
            // var decryptedPlaintext = DecryptWithBouncyCastle(ciphertext, nonce, tag, key);
            
            if (decryptedPlaintext.Equals(plaintext)) Console.WriteLine("Decryption succesful!");
            else Console.WriteLine("Error!");
        }

        private static (byte[] ciphertext, byte[] nonce, byte[] tag) EncryptWithNet(string plaintext, byte[] key)
        {
            using (var aes = new AesGcm(key))
            {
                var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
                RandomNumberGenerator.Fill(nonce);

                var tag = new byte[AesGcm.TagByteSizes.MaxSize];

                var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                var ciphertext = new byte[plaintextBytes.Length];

                aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

                return (ciphertext, nonce, tag);
            }
        }

        private static string DecryptWithNet(byte[] ciphertext, byte[] nonce, byte[] tag, byte[] key)
        {
            using (var aes = new AesGcm(key))
            {
                var plaintextBytes = new byte[ciphertext.Length];

                aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);

                return Encoding.UTF8.GetString(plaintextBytes);
            }
        }
        
        private static (byte[] ciphertext, byte[] nonce, byte[] tag) EncryptWithBouncyCastle(string plaintext, byte[] key)
        {
            const int nonceLength = 12; // in bytes
            const int tagLength = 16; // in bytes
            
            var nonce = new byte[nonceLength];
            RandomNumberGenerator.Fill(nonce);
            
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var bouncyCastleCiphertext = new byte[plaintextBytes.Length + tagLength];
            
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), tagLength * 8, nonce);
            cipher.Init(true, parameters);
            
            var offset = cipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, bouncyCastleCiphertext, 0);
            cipher.DoFinal(bouncyCastleCiphertext, offset);

            // Bouncy Castle includes the authentication tag in the ciphertext
            var ciphertext = new byte[plaintextBytes.Length];
            var tag = new byte[tagLength];
            Buffer.BlockCopy(bouncyCastleCiphertext, 0, ciphertext, 0, plaintextBytes.Length);
            Buffer.BlockCopy(bouncyCastleCiphertext, plaintextBytes.Length, tag, 0, tagLength);

            return (ciphertext, nonce, tag);
        }

        private static string DecryptWithBouncyCastle(byte[] ciphertext, byte[] nonce, byte[] tag, byte[] key)
        {
            var plaintextBytes = new byte[ciphertext.Length];

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), tag.Length * 8, nonce);
            cipher.Init(false, parameters);

            var bouncyCastleCiphertext = ciphertext.Concat(tag).ToArray();

            var offset = cipher.ProcessBytes(bouncyCastleCiphertext, 0, bouncyCastleCiphertext.Length, plaintextBytes, 0);
            cipher.DoFinal(plaintextBytes, offset);

            return Encoding.UTF8.GetString(plaintextBytes);
        }
    }
}
