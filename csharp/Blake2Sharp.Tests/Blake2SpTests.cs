// BLAKE2 reference source code package - C# implementation
// Blake2Sp tests: vectors sourced from C reference implementation (blake2sp-ref.c).

using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Blake2Sharp.Tests
{
    [TestClass]
    public class Blake2SpTests
    {
        // 256-byte input buffer: buf[i] = i  (matches C selftest)
        private static readonly byte[] Input256 =
            Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

        // 32-byte key: key[i] = i  (matches C selftest)
        private static readonly byte[] Key32 =
            Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

        [TestMethod]
        public void UnkeyedVectors()
        {
            for (int len = 0; len < Blake2SpTestVectors.UnkeyedBlake2Sp.Length; len++)
            {
                var hash = Blake2Sp.ComputeHash(Input256, 0, len);
                string actual = BitConverter.ToString(hash).Replace("-", "");
                Assert.AreEqual(Blake2SpTestVectors.UnkeyedBlake2Sp[len], actual,
                    "Unkeyed vector mismatch at len=" + len);
            }
        }

        [TestMethod]
        public void KeyedVectors()
        {
            var config = new Blake2SConfig { Key = Key32 };
            for (int len = 0; len < Blake2SpTestVectors.KeyedBlake2Sp.Length; len++)
            {
                var hash = Blake2Sp.ComputeHash(Input256, 0, len, config);
                string actual = BitConverter.ToString(hash).Replace("-", "");
                Assert.AreEqual(Blake2SpTestVectors.KeyedBlake2Sp[len], actual,
                    "Keyed vector mismatch at len=" + len);
            }
        }

        [TestMethod]
        public void StreamingSplits()
        {
            // Verify that splitting input across multiple Update calls produces
            // the same hash as a single call.
            // We test lengths 0..511 (covers all buffer boundary cases)
            // with two split points — enough to catch stripe-boundary bugs.
            var hasher = Blake2Sp.Create();

            // Use a longer input to exercise multi-stripe paths.
            byte[] input = Enumerable.Range(0, 512).Select(i => (byte)i).ToArray();

            for (int len = 0; len <= 512; len++)
            {
                hasher.Init();
                hasher.Update(input, 0, len);
                string hash0 = BitConverter.ToString(hasher.Finish()).Replace("-", "");

                // Test single split at every byte position.
                for (int split = 0; split <= len; split++)
                {
                    hasher.Init();
                    hasher.Update(input, 0, split);
                    hasher.Update(input, split, len - split);
                    string hash1 = BitConverter.ToString(hasher.Finish()).Replace("-", "");
                    if (hash0 != hash1)
                        Assert.Fail(string.Format(
                            "Single-split mismatch at len={0} split={1}", len, split));
                }
            }
        }

        [TestMethod]
        public void StreamingSplitsKeyed()
        {
            // Same as StreamingSplits but with a key, to cover the keyed-leaf path.
            var config = new Blake2SConfig { Key = Key32 };
            var hasher = Blake2Sp.Create(config);
            byte[] input = Enumerable.Range(0, 512).Select(i => (byte)i).ToArray();

            for (int len = 0; len <= 512; len++)
            {
                hasher.Init();
                hasher.Update(input, 0, len);
                string hash0 = BitConverter.ToString(hasher.Finish()).Replace("-", "");

                for (int split = 0; split <= len; split++)
                {
                    hasher.Init();
                    hasher.Update(input, 0, split);
                    hasher.Update(input, split, len - split);
                    string hash1 = BitConverter.ToString(hasher.Finish()).Replace("-", "");
                    if (hash0 != hash1)
                        Assert.Fail(string.Format(
                            "Keyed single-split mismatch at len={0} split={1}", len, split));
                }
            }
        }
    }
}
