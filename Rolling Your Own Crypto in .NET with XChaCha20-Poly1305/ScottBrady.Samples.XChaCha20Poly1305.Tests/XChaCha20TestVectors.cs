using System;
using FluentAssertions;
using Sodium;
using Xunit;

namespace ScottBrady.Samples.XChaCha20Poly1305.Tests
{
    public class XChaCha20TestVectors
    {
        private const string PlaintextHex = @"4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
        private const string CipherTextHex = @"bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e";
            
        private const string AadHex = @"50515253c0c1c2c3c4c5c6c7"; // 12 bytes
        private const string KeyHex = @"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"; // 32 bytes
        private const string IvHex = @"404142434445464748494a4b4c4d4e4f5051525354555657"; // 24-bytes
        private const string Tag = "c0875924c1c7987947deafd8780acf49"; // 16-bytes

        private readonly byte[] testCiphertext;
        
        public XChaCha20TestVectors()
        {
            var plaintext = HexToBytes(PlaintextHex);
            
            testCiphertext = new byte[plaintext.Length + 16];
            Array.Copy(HexToBytes(CipherTextHex), 0, testCiphertext, 0, plaintext.Length);
            Array.Copy(HexToBytes(Tag), 0, testCiphertext, plaintext.Length, 16);
        }
        
        [Fact]
        public void Encrypt_WithTestVectors_ExpectCorrectCipherText()
        {
            var plaintext = HexToBytes(PlaintextHex);
            var nonce = HexToBytes(IvHex);
            var key = HexToBytes(KeyHex);
            var aad = HexToBytes(AadHex);

            var ciphertext = BouncyDancing.Encrypt(key, nonce, plaintext, aad);

            ciphertext.Should().BeEquivalentTo(SecretAeadXChaCha20Poly1305.Encrypt(plaintext, nonce, key, aad));
            ciphertext.Should().BeEquivalentTo(testCiphertext);
        }

        [Fact]
        public void Decrypt_WithTestVectors_ExpectCorrectPlainText()
        {
            var expectedPlaintext = HexToBytes(PlaintextHex);
            var nonce = HexToBytes(IvHex);
            var key = HexToBytes(KeyHex);
            var aad = HexToBytes(AadHex);
            
            var plaintext = BouncyDancing.Decrypt(key, nonce, testCiphertext, aad);

            plaintext.Should().BeEquivalentTo(expectedPlaintext);
            plaintext.Should().BeEquivalentTo(SecretAeadXChaCha20Poly1305.Decrypt(testCiphertext, nonce, key, aad));
        }
        
        private static byte[] HexToBytes(string hex)
        {
            var hexAsBytes = new byte[hex.Length / 2];

            for (var i = 0; i < hex.Length; i += 2) {
                hexAsBytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return hexAsBytes;
        }
    }
}