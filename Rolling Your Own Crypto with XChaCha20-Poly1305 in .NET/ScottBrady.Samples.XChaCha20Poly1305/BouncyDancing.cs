using System;
using System.Buffers.Binary;
using System.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace ScottBrady.Samples.XChaCha20Poly1305
{
    public static class BouncyDancing
    {
        public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad = null) 
            => XChaCha20Poly1305(true, key, nonce, plaintext, aad);

        public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad = null) 
            => XChaCha20Poly1305(false, key, nonce, ciphertext, aad);

        private static byte[] XChaCha20Poly1305(bool isEncryption, byte[] key, byte[] nonce, byte[] message, byte[] aad = null)
        {
            if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes", nameof(key));
            if (nonce.Length != 24) throw new ArgumentException("Nonce must be 24 bytes", nameof(nonce));

            // subkey (hchacha20(key, nonce[0:15]))
            var subkey = HChaCha20.CreateSubkey(key, nonce); // TODO: parse nonce bytes to pass through here instead
            
            // nonce (chacha20_nonce = "\x00\x00\x00\x00" + nonce[16:23])
            var chaChaNonce = new byte[12];
            Array.Copy(new byte[] {0, 0, 0, 0}, chaChaNonce, 4);
            Array.Copy(nonce, 16, chaChaNonce, 4, 8);
            
            // chacha20_encrypt(subkey, chacha20_nonce, plaintext, blk_ctr)
            var outputLength = message.Length;
            if (isEncryption) outputLength += 16;
            else outputLength -= 16;
            
            var output = new byte[outputLength];
            var keyMaterial = new KeyParameter(subkey);
            var parameters = new ParametersWithIV(keyMaterial, chaChaNonce);
            
            var chaCha20Poly1305 = new ChaCha20Poly1305();
            chaCha20Poly1305.Init(isEncryption, parameters);
            
            // if aditional data present
            if (aad != null) chaCha20Poly1305.ProcessAadBytes(aad, 0, aad.Length);

            var len = chaCha20Poly1305.ProcessBytes(message, 0, message.Length, output, 0);
            chaCha20Poly1305.DoFinal(output, len);

            return output;
        }

        public static class HChaCha20
        {
            public static byte[] CreateSubkey(byte[] key, byte[] nonce)
            {
                var state = CreateInitialState(key, nonce);
                PerformRounds(state);

                return FromUint32LittleEndian(new[]
                {
                    state[0], state[1], state[2], state[3],
                    state[12], state[13], state[14], state[15],
                }, 32);
            }
            
            public static uint[] CreateInitialState(byte[] key, byte[] nonce)
            {
                var state = new uint[16];

                // set HChaCha20 constant
                var constant = new uint[] {0x61707865, 0x3320646E, 0x79622D32, 0x6B206574};
                Array.Copy(constant, state, constant.Length);
                
                // set key
                var keyState = ToUint32LittleEndian(key, 8);
                Array.Copy(keyState, 0, state, 4, keyState.Length);

                // set nonce
                var nonceState = ToUint32LittleEndian(nonce, 4);
                Array.Copy(nonceState, 0, state, state.Length - 4, nonceState.Length);

                return state;
            }

            public static void PerformRounds(uint[] state)
            {
                for (var i = 0; i < 10; i++)
                {
                    ChaCha20.QuarterRound(ref state[0], ref state[4], ref state[8], ref state[12]);
                    ChaCha20.QuarterRound(ref state[1], ref state[5], ref state[9], ref state[13]);
                    ChaCha20.QuarterRound(ref state[2], ref state[6], ref state[10], ref state[14]);
                    ChaCha20.QuarterRound(ref state[3], ref state[7], ref state[11], ref state[15]);
                    ChaCha20.QuarterRound(ref state[0], ref state[5], ref state[10], ref state[15]);
                    ChaCha20.QuarterRound(ref state[1], ref state[6], ref state[11], ref state[12]);
                    ChaCha20.QuarterRound(ref state[2], ref state[7], ref state[8], ref state[13]);
                    ChaCha20.QuarterRound(ref state[3], ref state[4], ref state[9], ref state[14]);
                }
            }

            private static uint[] ToUint32LittleEndian(byte[] bytes, int outputLength)
            {
                var pos = 0;
                var output = new uint[outputLength];

                using (var ms = new MemoryStream(bytes))
                {
                    while (pos != outputLength)
                    {
                        var temp = new byte[4];
                        ms.Read(temp, 0, 4);
                        output[pos] = BinaryPrimitives.ReadUInt32LittleEndian(temp);
                        pos += 1;
                    }
                }

                return output;
            }
            
            private static byte[] FromUint32LittleEndian(uint[] input, int outputLength)
            {
                var output = new byte[outputLength];
            
                for (var i = 0; i < input.Length; i++)
                {
                    var u = input[i];
                    var temp = new byte[4];
                    BinaryPrimitives.WriteUInt32LittleEndian(temp, u);
                    Array.Copy(temp, 0, output, i * 4, temp.Length);
                }

                return output;
            }
        }

        /// <summary>
        /// Adapted from https://github.com/daviddesmet/NaCl.Core
        /// </summary>
        public static class ChaCha20
        {
            public static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
            {
                a += b; d = RotateLeft(d ^ a, 16);
                c += d; b = RotateLeft(b ^ c, 12);
                a += b; d = RotateLeft(d ^ a, 8);
                c += d; b = RotateLeft(b ^ c, 7);
            }
        
            private static uint RotateLeft(uint value, int offset)
            {
                return (value << offset) | (value >> (32 - offset));
            }
        }
    }
}