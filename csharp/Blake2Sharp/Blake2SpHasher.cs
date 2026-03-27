// BLAKE2 reference source code package - C# implementation

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

using System;

namespace Blake2Sharp
{
	// BLAKE2sp: parallel BLAKE2s with 8 leaves.
	//
	// Structure:
	//   - 8 leaf Blake2SCore instances, each independently hashing a stripe of input.
	//   - 1 root Blake2SCore instance that hashes the concatenated 32-byte leaf digests.
	//
	// Input striping: input is divided into 64-byte (BlockSizeInBytes) chunks that are
	// fed to leaves 0..7 in round-robin order. Internally a 512-byte (8*64) buffer
	// accumulates partial stripes before flushing a full set to all leaves at once.
	//
	// Parameter block differences vs sequential BLAKE2s:
	//   All nodes:  fanout=8, depth=2, inner_length=32
	//   Leaf i:     node_depth=0, node_offset=i
	//   Root:       node_depth=1, node_offset=0
	//   Last leaf (i=7) and root both have the last-node finalization flag set.
	internal sealed class Blake2SpHasher : Hasher
	{
		private const int ParallelismDegree = 8;
		// BufSize = 8 leaves * 64 bytes/leaf = 512 bytes per full stripe set
		private const int BufSize = ParallelismDegree * Blake2SCore.BlockSizeInBytes;

		private readonly Blake2SCore[] _leaves = new Blake2SCore[ParallelismDegree];
		private readonly Blake2SCore _root = new Blake2SCore();

		// Pre-built parameter blocks (one per leaf + one for root).
		// Computed once in constructor, reused across Init() calls.
		private readonly uint[][] _leafConfigs = new uint[ParallelismDegree][];
		private readonly uint[] _rootConfig;

		// Key padded to BlockSizeInBytes, or null if no key.
		private readonly byte[] _key;
		private readonly int _outputSizeInBytes;

		// Accumulation buffer: 8 contiguous 64-byte stripes, one per leaf.
		// _buf[i*64 .. i*64+63] belongs to leaf i.
		private readonly byte[] _buf = new byte[BufSize];
		private int _buflen;

		private static readonly Blake2SConfig DefaultConfig = new Blake2SConfig();

		public Blake2SpHasher(Blake2SConfig config)
		{
			if (config == null)
				config = DefaultConfig;

			if (config.OutputSizeInBytes <= 0 || config.OutputSizeInBytes > Blake2SCore.OutputSizeInBytes)
				throw new ArgumentOutOfRangeException("config.OutputSizeInBytes");

			_outputSizeInBytes = config.OutputSizeInBytes;

			// word[0]: digest_length | (key_length<<8) | (fanout<<16) | (depth<<24)
			// All nodes share the same word[0].
			int keyLen = (config.Key != null) ? config.Key.Length : 0;
			if (keyLen > Blake2SCore.OutputSizeInBytes)
				throw new ArgumentException("Key too long");

			// BLAKE2sp does not support salt or personalization at the tree level.
			// The C reference implementation zeros these fields in all leaf and root
			// parameter blocks regardless of what the caller provides.
			if (config.Salt != null)
				throw new ArgumentException("BLAKE2sp does not support salt");
			if (config.Personalization != null)
				throw new ArgumentException("BLAKE2sp does not support personalization");

			uint word0 = (uint)_outputSizeInBytes
			           | ((uint)keyLen << 8)
			           | ((uint)ParallelismDegree << 16)
			           | (2u << 24);

			// word[3] for leaves: node_depth=0, inner_length=32
			uint word3Leaf = (uint)Blake2SCore.OutputSizeInBytes << 24;
			// word[3] for root:  node_depth=1, inner_length=32
			uint word3Root = (1u << 16) | ((uint)Blake2SCore.OutputSizeInBytes << 24);

			for (int i = 0; i < ParallelismDegree; i++)
			{
				_leafConfigs[i] = new uint[8];
				_leafConfigs[i][0] = word0;
				// word[1] = leaf_length = 0
				_leafConfigs[i][2] = (uint)i;  // node_offset = leaf index
				_leafConfigs[i][3] = word3Leaf;
				// words 4-7 = salt/personalization = 0
			}

			_rootConfig = new uint[8];
			_rootConfig[0] = word0;
			// word[1] = leaf_length = 0, word[2] = node_offset = 0
			_rootConfig[3] = word3Root;

			if (keyLen > 0)
			{
				_key = new byte[Blake2SCore.BlockSizeInBytes];
				Array.Copy(config.Key, _key, keyLen);
			}

			for (int i = 0; i < ParallelismDegree; i++)
				_leaves[i] = new Blake2SCore();

			Init();
		}

		public override void Init()
		{
			for (int i = 0; i < ParallelismDegree; i++)
			{
				_leaves[i].Initialize(_leafConfigs[i]);
				if (_key != null)
					_leaves[i].HashCore(_key, 0, _key.Length);
			}
			_root.Initialize(_rootConfig);
			_buflen = 0;
			Array.Clear(_buf, 0, _buf.Length);
		}

		public override void Update(ReadOnlySpan<byte> data)
		{
			int left = _buflen;
			int fill = BufSize - left;

			// If the buffer has a partial stripe and the new data fills it, flush.
			if (left > 0 && data.Length >= fill)
			{
				data.Slice(0, fill).CopyTo(_buf.AsSpan(left));
				for (int i = 0; i < ParallelismDegree; i++)
					_leaves[i].HashCore(_buf.AsSpan(i * Blake2SCore.BlockSizeInBytes, Blake2SCore.BlockSizeInBytes));
				data = data.Slice(fill);
				left = 0;
			}

			// Process complete 512-byte stripe sets directly from the caller's buffer.
			while (data.Length >= BufSize)
			{
				for (int i = 0; i < ParallelismDegree; i++)
					_leaves[i].HashCore(data.Slice(i * Blake2SCore.BlockSizeInBytes, Blake2SCore.BlockSizeInBytes));
				data = data.Slice(BufSize);
			}

			// Buffer any remaining bytes (< 512).
			if (data.Length > 0)
				data.CopyTo(_buf.AsSpan(left));

			_buflen = left + data.Length;
		}

		public override void Update(byte[] data, int start, int count)
		{
			if (data == null) throw new ArgumentNullException("data");
			if (start < 0) throw new ArgumentOutOfRangeException("start");
			if (count < 0) throw new ArgumentOutOfRangeException("count");
			if ((long)start + count > data.Length) throw new ArgumentOutOfRangeException("start+count");
			Update(new ReadOnlySpan<byte>(data, start, count));
		}

		public override byte[] Finish()
		{
			// Flush the partial stripe from the buffer into the appropriate leaves.
			// Leaf i receives buf[i*64 .. i*64 + min(buflen - i*64, 64) - 1],
			// but only if buflen > i*64 (otherwise leaf i got nothing extra).
			for (int i = 0; i < ParallelismDegree; i++)
			{
				if (_buflen > i * Blake2SCore.BlockSizeInBytes)
				{
					int remaining = _buflen - i * Blake2SCore.BlockSizeInBytes;
					if (remaining > Blake2SCore.BlockSizeInBytes)
						remaining = Blake2SCore.BlockSizeInBytes;
					_leaves[i].HashCore(_buf.AsSpan(i * Blake2SCore.BlockSizeInBytes, remaining));
				}

				// Leaf 7 is the last leaf — set its last-node finalization flag.
				bool isLastLeaf = (i == ParallelismDegree - 1);
				Span<byte> leafHash = stackalloc byte[Blake2SCore.OutputSizeInBytes];
				_leaves[i].HashFinal(leafHash, isLastLeaf);
				_root.HashCore(leafHash);
			}

			// Root always has its last-node flag set.
			byte[] fullResult = _root.HashFinal(isEndOfLayer: true);

			// Blake2SCore.HashFinal always returns 32 bytes. Trim here if the caller
			// requested a shorter output (1..31 bytes). Variable-length output works
			// correctly because digest_length is encoded in word[0] of the parameter
			// block for both leaves and root, so the hash value differs for each
			// distinct output length — but no additional testing is done for lengths
			// other than 32 since the KAT vectors only cover 32-byte output.
			if (_outputSizeInBytes == fullResult.Length)
				return fullResult;

			var result = new byte[_outputSizeInBytes];
			Array.Copy(fullResult, result, result.Length);
			return result;
		}
	}
}
