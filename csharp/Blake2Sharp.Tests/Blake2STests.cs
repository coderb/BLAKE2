// BLAKE2 reference source code package - C# implementation
// Blake2S tests: vectors sourced from C reference implementation (blake2s-ref.c).

using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Blake2Sharp.Tests
{
    [TestClass]
    public class Blake2STests
    {
        // 256-byte input buffer: buf[i] = i
        private static readonly byte[] Input256 =
            Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

        // 32-byte key: key[i] = i
        private static readonly byte[] Key32 =
            Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

        [TestMethod]
        public void UnkeyedVectors()
        {
            for (int len = 0; len < Blake2STestVectors.UnkeyedBlake2S.Length; len++)
            {
                var hash = Blake2S.ComputeHash(Input256, 0, len);
                string actual = BitConverter.ToString(hash).Replace("-", "");
                Assert.AreEqual(Blake2STestVectors.UnkeyedBlake2S[len], actual,
                    "Unkeyed vector mismatch at len=" + len);
            }
        }

        [TestMethod]
        public void KeyedVectors()
        {
            var config = new Blake2SConfig { Key = Key32 };
            for (int len = 0; len < Blake2STestVectors.KeyedBlake2S.Length; len++)
            {
                var hash = Blake2S.ComputeHash(Input256, 0, len, config);
                string actual = BitConverter.ToString(hash).Replace("-", "");
                Assert.AreEqual(Blake2STestVectors.KeyedBlake2S[len], actual,
                    "Keyed vector mismatch at len=" + len);
            }
        }

        [TestMethod]
        public void StreamingSplits()
        {
            // Verify that splitting input across multiple Update calls produces
            // the same hash as a single call — for all lengths up to 256 and
            // all pairs of split points.
            var hasher = Blake2S.Create();
            for (int len = 0; len <= 256; len++)
            {
                hasher.Init();
                hasher.Update(Input256, 0, len);
                string hash0 = BitConverter.ToString(hasher.Finish()).Replace("-", "");

                for (int split1 = 0; split1 <= len; split1++)
                {
                    for (int split2 = split1; split2 <= len; split2++)
                    {
                        hasher.Init();
                        hasher.Update(Input256, 0, split1);
                        hasher.Update(Input256, split1, split2 - split1);
                        hasher.Update(Input256, split2, len - split2);
                        string hash1 = BitConverter.ToString(hasher.Finish()).Replace("-", "");
                        if (hash0 != hash1)
                            Assert.Fail(string.Format("Streaming split mismatch at len={0} split1={1} split2={2}", len, split1, split2));
                    }
                }
            }
        }
    }
}
