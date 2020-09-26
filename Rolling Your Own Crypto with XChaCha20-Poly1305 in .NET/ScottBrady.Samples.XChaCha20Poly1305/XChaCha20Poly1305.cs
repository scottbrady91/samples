using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace ScottBrady.Samples.XChaCha20Poly1305
{
    public static class BouncyDancing
    {
        public static byte[] Encrypt(byte[] plaintext, Span<byte> nonce, byte[] key)
        {
            if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes", nameof(key));

            var subkey = HChaCha20(key, nonce.ToArray());
            var chaChaNonce = new byte[12];
            Array.Copy(new byte[] {0, 0, 0, 0}, chaChaNonce, 4);

            var finalBytes = nonce.Slice(16, 8).ToArray();
            Array.Copy(finalBytes, 0, chaChaNonce, 4, 8);
            
            var ciphertext = new byte[plaintext.Length];
            var keyMaterial = new KeyParameter(subkey);
            var parameters = new ParametersWithIV(keyMaterial, chaChaNonce);

            var chaCha20Poly1305 = new ChaCha20Poly1305();
            chaCha20Poly1305.Init(true, parameters);
            var len = chaCha20Poly1305.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
            chaCha20Poly1305.DoFinal(ciphertext, ciphertext.Length - len);

            return ciphertext;

            /*var engine = new ChaChaEngine();
            engine.Init(true, parameters);
            
            engine.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);

            var poly = new Poly1305();
            poly.Init(keyMaterial);
            poly.BlockUpdate(header, 0, header.Length);
            poly.DoFinal(ciphertext, plaintextBytes.Length);*/
        }

        public static byte[] HChaCha20(byte[] key, byte[] nonce)
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

            var expectedInitialState = new uint[]
            {
                0x61707865,
                0x3320646e,
                0x79622d32,
                0x6b206574,
                0x03020100,
                0x07060504,
                0x0b0a0908,
                0x0f0e0d0c,
                0x13121110,
                0x17161514,
                0x1b1a1918,
                0x1f1e1d1c,
                0x09000000,
                0x4a000000,
                0x00000000,
                0x27594131
            };
            
            // 20 rounds (10 column rounds interleaved with 10 "diagonal rounds")
            ShuffleState(state);

            var expectedState = new uint[]
            {
                0x423b4182,
                0xfe7bb227,
                0x50420ed3,
                0x737d878a,
                0x0aa76448,
                0x7954cdf3,
                0x846acd37,
                0x7b3c58ad,
                0x77e35583,
                0x83e77c12,
                0xe0076a2d,
                0xbc6cd0e5,
                0xd5e4f9a0,
                0x53a8748a,
                0x13c42ec1,
                0xdcecd326
            };

            var subkey = FromUint32LittleEndian(new uint[]
            {
                state[0],
                state[1],
                state[2],
                state[3],
                state[12],
                state[13],
                state[14],
                state[15],
            }, 32);
            
            return subkey;
        }
        
        public static void ShuffleState(Span<uint> state)
        {
            for (var i = 0; i < 10; i++)
            {
                QuarterRound(ref state[0], ref state[4], ref state[8], ref state[12]);
                QuarterRound(ref state[1], ref state[5], ref state[9], ref state[13]);
                QuarterRound(ref state[2], ref state[6], ref state[10], ref state[14]);
                QuarterRound(ref state[3], ref state[7], ref state[11], ref state[15]);
                QuarterRound(ref state[0], ref state[5], ref state[10], ref state[15]);
                QuarterRound(ref state[1], ref state[6], ref state[11], ref state[12]);
                QuarterRound(ref state[2], ref state[7], ref state[8], ref state[13]);
                QuarterRound(ref state[3], ref state[4], ref state[9], ref state[14]);
            }
        }

        public static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b;
            d = RotateLeft(d ^ a, 16);
            c += d;
            b = RotateLeft(b ^ c, 12);
            a += b;
            d = RotateLeft(d ^ a, 8);
            c += d;
            b = RotateLeft(b ^ c, 7);
        }
        
        public static uint RotateLeft(uint value, int offset)
        {
            return (value << offset) | (value >> (32 - offset));
        }

        public static uint[] ToUint32LittleEndian(byte[] bytes, int length)
        {
            var pos = 0;
            var output = new uint[length];

            using (var ms = new MemoryStream(bytes))
            {
                while (pos != length)
                {
                    var temp = new byte[4];
                    ms.Read(temp, 0, 4);
                    output[pos] = BinaryPrimitives.ReadUInt32LittleEndian(temp);
                    pos += 1;
                }
            }

            return output;
        }

        public static byte[] FromUint32LittleEndian(uint[] input, int length)
        {
            var output = new byte[length];

            var len = sizeof(int);
            
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
}