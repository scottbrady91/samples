using System;
using System.Linq;
using Xunit;

namespace ScottBrady.Samples.XChaCha20Poly1305.Tests
{
    public class TestVectors
    {
        [Fact]
        public void A31()
        {
            var plaintextHex = @"4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
            var cipherTextHex = @"bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e";
            
            var aadHex = @"50515253c0c1c2c3c4c5c6c7"; // 12 bytes
            var keyHex = @"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"; // 32 bytes
            var ivHex = @"404142434445464748494a4b4c4d4e4f5051525354555657"; // 24-bytes nonce 🙄
            var fixedPart = @"00000000";
            var polyKey = "7b191f80f361f099094f6f4b8fb97df847cc6873a8f2b190dd73807183f907d5";

            var plaintext = HexToBytes(plaintextHex);
            var nonce = HexToBytes(ivHex);
            var key = HexToBytes(keyHex);

            var expectedCipherText = HexToBytes(cipherTextHex);
            var cipherText = BouncyDancing.Encrypt(plaintext, nonce, key);

            Assert.True(expectedCipherText.SequenceEqual(cipherText));
        }
        
        private byte[] HexToBytes(string hex)
        {
            var hexAsBytes = new byte[hex.Length / 2];

            for (var i = 0; i < hex.Length; i += 2) {
                hexAsBytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return hexAsBytes;
        }
        
        [Fact]
        public void HChaCha_TestVector()
        {
            var key = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
            };

            var nonce = new byte[] {0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59, 0x27};

            var output = BouncyDancing.HChaCha20(key, nonce);

            Assert.Equal(32, output.Length);

            var expected = HexToBytes("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
            Assert.Equal(expected, output);
        }
    }
}