// BLAKE2 reference source code package - C# implementation

// Written in 2012 by Christian Winnerlein  <codesinchaos@gmail.com>

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

using System;

namespace Blake2Sharp
{
	internal static class Blake2IvBuilder
	{
		private static readonly Blake2BTreeConfig SequentialTreeConfig = new Blake2BTreeConfig() { IntermediateHashSize = 0, LeafSize = 0, FanOut = 1, MaxHeight = 1 };

		// BLAKE2s parameter block layout (8 x uint32 = 32 bytes):
		//   word[0]: digest_length | (key_length<<8) | (fanout<<16) | (depth<<24)
		//   word[1]: leaf_length
		//   word[2]: node_offset
		//   word[3]: (xof_length[0:15]) | (node_depth<<16) | (inner_length<<24)
		//   word[4..5]: salt (8 bytes)
		//   word[6..7]: personalization (8 bytes)
		public static uint[] ConfigS(Blake2SConfig config, Blake2STreeConfig treeConfig)
		{
			bool isSequential = treeConfig == null;
			if (isSequential)
				treeConfig = Blake2STreeConfig.Sequential;
			var rawConfig = new uint[8];

			// digest length
			if (config.OutputSizeInBytes <= 0 || config.OutputSizeInBytes > 32)
				throw new ArgumentOutOfRangeException("config.OutputSize");
			rawConfig[0] |= (uint)config.OutputSizeInBytes;

			// key length
			if (config.Key != null)
			{
				if (config.Key.Length > 32)
					throw new ArgumentException("Key too long", "config.Key");
				rawConfig[0] |= (uint)(config.Key.Length << 8);
			}

			// fanout
			rawConfig[0] |= (uint)treeConfig.FanOut << 16;
			// depth
			rawConfig[0] |= (uint)treeConfig.MaxHeight << 24;
			// leaf length
			rawConfig[1] = (uint)treeConfig.LeafSize;
			// node_offset (word[2]) and node_depth (bits 16-23 of word[3]) default to 0;
			// patch afterwards with ConfigSSetNode() if needed.
			// inner length
			if (!isSequential && (treeConfig.IntermediateHashSize <= 0 || treeConfig.IntermediateHashSize > 32))
				throw new ArgumentOutOfRangeException("treeConfig.IntermediateHashSize");
			rawConfig[3] |= (uint)treeConfig.IntermediateHashSize << 24;

			// salt (8 bytes)
			if (config.Salt != null)
			{
				if (config.Salt.Length != 8)
					throw new ArgumentException("Salt must be exactly 8 bytes");
				rawConfig[4] = Blake2SCore.BytesToUInt32(config.Salt, 0);
				rawConfig[5] = Blake2SCore.BytesToUInt32(config.Salt, 4);
			}

			// personalization (8 bytes)
			if (config.Personalization != null)
			{
				if (config.Personalization.Length != 8)
					throw new ArgumentException("Personalization must be exactly 8 bytes");
				rawConfig[6] = Blake2SCore.BytesToUInt32(config.Personalization, 0);
				rawConfig[7] = Blake2SCore.BytesToUInt32(config.Personalization, 4);
			}

			return rawConfig;
		}

		// Patch a pre-built config word array for a specific tree node (depth + offset).
		public static void ConfigSSetNode(uint[] rawConfig, byte depth, uint nodeOffset)
		{
			rawConfig[2] = nodeOffset;
			// Keep inner_length (bits 24-31), clear node_depth (bits 16-23), set new depth
			rawConfig[3] = (rawConfig[3] & 0xFF000000u) | ((uint)depth << 16);
		}

		public static ulong[] ConfigB(Blake2BConfig config, Blake2BTreeConfig treeConfig)
		{
			bool isSequential = treeConfig == null;
			if (isSequential)
				treeConfig = SequentialTreeConfig;
			var rawConfig = new ulong[8];
			var result = new ulong[8];

			//digest length
			if (config.OutputSizeInBytes <= 0 | config.OutputSizeInBytes > 64)
				throw new ArgumentOutOfRangeException("config.OutputSize");
			rawConfig[0] |= (ulong)(uint)config.OutputSizeInBytes;

			//Key length
			if (config.Key != null)
			{
				if (config.Key.Length > 64)
					throw new ArgumentException("config.Key", "Key too long");
				rawConfig[0] |= (ulong)((uint)config.Key.Length << 8);
			}
			// FanOut
			rawConfig[0] |= (uint)treeConfig.FanOut << 16;
			// Depth
			rawConfig[0] |= (uint)treeConfig.MaxHeight << 24;
			// Leaf length
			rawConfig[0] |= ((ulong)(uint)treeConfig.LeafSize) << 32;
			// Inner length
			if (!isSequential && (treeConfig.IntermediateHashSize <= 0 || treeConfig.IntermediateHashSize > 64))
				throw new ArgumentOutOfRangeException("treeConfig.TreeIntermediateHashSize");
			rawConfig[2] |= (uint)treeConfig.IntermediateHashSize << 8;
			// Salt
			if (config.Salt != null)
			{
				if (config.Salt.Length != 16)
					throw new ArgumentException("config.Salt has invalid length");
				rawConfig[4] = Blake2BCore.BytesToUInt64(config.Salt, 0);
				rawConfig[5] = Blake2BCore.BytesToUInt64(config.Salt, 8);
			}
			// Personalization
			if (config.Personalization != null)
			{
				if (config.Personalization.Length != 16)
					throw new ArgumentException("config.Personalization has invalid length");
				rawConfig[6] = Blake2BCore.BytesToUInt64(config.Personalization, 0);
				rawConfig[7] = Blake2BCore.BytesToUInt64(config.Personalization, 8);
			}

			return rawConfig;
		}

		public static void ConfigBSetNode(ulong[] rawConfig, byte depth, ulong nodeOffset)
		{
			rawConfig[1] = nodeOffset;
			rawConfig[2] = (rawConfig[2] & ~0xFFul) | depth;
		}
	}
}
