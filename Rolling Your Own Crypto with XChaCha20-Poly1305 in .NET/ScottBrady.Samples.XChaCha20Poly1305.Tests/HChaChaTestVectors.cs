using System;
using FluentAssertions;
using Xunit;

namespace ScottBrady.Samples.XChaCha20Poly1305.Tests
{
    /// <summary>
    /// Test vectors from https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03#section-2.2.1
    /// </summary>
    public class HChaChaTestVectors
    {
        private readonly byte[] key =
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };

        private readonly byte[] nonce = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59, 0x27};
        
        [Fact]
        public void CreateInitialState_WithTestVectors_ExpectCorrectInitialState()
        {
            var expectedInitialState = new uint[]
            {
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                0x09000000, 0x4a000000, 0x00000000, 0x27594131
            };
            
            var initialState = BouncyDancing.HChaCha20.CreateInitialState(key, nonce);

            initialState.Should().BeEquivalentTo(expectedInitialState);
        }

        [Fact]
        public void PerformRounds_WithTestVectors_ExpectCorrectState()
        {
            var state = new uint[]
            {
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                0x09000000, 0x4a000000, 0x00000000, 0x27594131
            };

            var expectedState = new uint[]
            {
                0x423b4182, 0xfe7bb227, 0x50420ed3, 0x737d878a,
                0x0aa76448, 0x7954cdf3, 0x846acd37, 0x7b3c58ad,
                0x77e35583, 0x83e77c12, 0xe0076a2d, 0xbc6cd0e5,
                0xd5e4f9a0, 0x53a8748a, 0x13c42ec1, 0xdcecd326
            };

            BouncyDancing.HChaCha20.PerformRounds(state);

            state.Should().BeEquivalentTo(expectedState);
        }

        [Fact]
        public void CreateSubkey_WithTestVectors_ExpectCorrectSubkey()
        {
            var expectedSubkey = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc";
            var expectedSubkeyBytes = HexToBytes(expectedSubkey);
            
            var subKey = BouncyDancing.HChaCha20.CreateSubkey(key, nonce);

            subKey.Should().BeEquivalentTo(expectedSubkeyBytes);
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