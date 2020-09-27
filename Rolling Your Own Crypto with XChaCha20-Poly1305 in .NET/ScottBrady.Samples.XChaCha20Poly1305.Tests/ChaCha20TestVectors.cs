using FluentAssertions;
using Xunit;

namespace ScottBrady.Samples.XChaCha20Poly1305.Tests
{
    public class ChaCha20BlockFunctionTestVectors
    {
        
        /// <summary>
        /// Test vector from https://tools.ietf.org/html/rfc8439#section-2.2.1
        /// </summary>
        [Fact]
        public void QuarterRound_WithTestVectors_ExpectCorrectState()
        {
            var state = new uint[] {0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567};
            var expectedState = new uint[] {0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb};

            BouncyDancing.ChaCha20.QuarterRound(ref state[0], ref state[1], ref state[2], ref state[3]);

            state.Should().BeEquivalentTo(expectedState);
        }
    }
}