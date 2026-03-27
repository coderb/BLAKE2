// BLAKE2 reference source code package - C# implementation

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

using System;

namespace Blake2Sharp
{
	// Core streaming state for BLAKE2s.
	// BLAKE2s differences vs BLAKE2b:
	//   - 32-bit words (uint) instead of 64-bit (ulong)
	//   - 64-byte block size (vs 128)
	//   - 10 rounds (vs 12)
	//   - 32-byte max output
	//   - counters and finalization flags are uint (fit in the low word; high word unused)
	public sealed partial class Blake2SCore
	{
		private bool _isInitialized = false;

		private int _bufferFilled;
		private readonly byte[] _buf = new byte[BlockSizeInBytes];

		private readonly uint[] _m = new uint[16];   // message schedule, 16 words per block
		private readonly uint[] _h = new uint[8];    // hash state, 8 x 32-bit
		private uint _counter0;             // low 32 bits of byte counter
		private uint _counter1;             // high 32 bits of byte counter (usually 0)
		private bool _finalizationFlag0;    // true on the last block of the message
		private bool _finalizationFlag1;    // true when this is the last node in its layer (tree mode)

		private const int NumberOfRounds = 10;
		public const int BlockSizeInBytes = 64;
		public const int OutputSizeInBytes = 32;

		// IV = first 8 words of the fractional parts of sqrt of the first 8 primes (SHA-256 constants)
		private const uint IV0 = 0x6A09E667u;
		private const uint IV1 = 0xBB67AE85u;
		private const uint IV2 = 0x3C6EF372u;
		private const uint IV3 = 0xA54FF53Au;
		private const uint IV4 = 0x510E527Fu;
		private const uint IV5 = 0x9B05688Cu;
		private const uint IV6 = 0x1F83D9ABu;
		private const uint IV7 = 0x5BE0CD19u;

		// Sigma permutation table — same as BLAKE2b (10 rows used, rows 11-12 not needed)
		private static readonly int[] Sigma = new int[NumberOfRounds * 16]
		{
			 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
			14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3,
			11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4,
			 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8,
			 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13,
			 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9,
			12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11,
			13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10,
			 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5,
			10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0,
		};

		// Little-endian helpers (32-bit)
		internal static uint BytesToUInt32(byte[] buf, int offset)
		{
			return
				(uint)buf[offset] |
				((uint)buf[offset + 1] << 8) |
				((uint)buf[offset + 2] << 16) |
				((uint)buf[offset + 3] << 24);
		}

		private static void UInt32ToBytes(uint value, byte[] buf, int offset)
		{
			buf[offset]     = (byte)value;
			buf[offset + 1] = (byte)(value >> 8);
			buf[offset + 2] = (byte)(value >> 16);
			buf[offset + 3] = (byte)(value >> 24);
		}

		// Compress is implemented in Blake2SCore-Compress.cs
		partial void Compress(byte[] block, int start);

		// Initialize the hash state from a pre-built 8-word parameter block.
		// Per the BLAKE2 spec, the initial chaining value is IV XOR the parameter
		// block rather than the IV alone, so that different configurations (output
		// length, key, fanout, etc.) produce independent hash functions.
		public void Initialize(uint[] config)
		{
			if (config == null)
				throw new ArgumentNullException("config");
			if (config.Length != 8)
				throw new ArgumentException("config length must be 8 words");
			_isInitialized = true;

			_h[0] = IV0;
			_h[1] = IV1;
			_h[2] = IV2;
			_h[3] = IV3;
			_h[4] = IV4;
			_h[5] = IV5;
			_h[6] = IV6;
			_h[7] = IV7;

			_counter0 = 0;
			_counter1 = 0;
			_finalizationFlag0 = false;
			_finalizationFlag1 = false;

			_bufferFilled = 0;

			Array.Clear(_buf, 0, _buf.Length);

			for (int i = 0; i < 8; i++)
				_h[i] ^= config[i];
		}

		public void HashCore(byte[] array, int start, int count)
		{
			if (!_isInitialized)
				throw new InvalidOperationException("Not initialized");
			if (array == null)
				throw new ArgumentNullException("array");
			if (start < 0)
				throw new ArgumentOutOfRangeException("start");
			if (count < 0)
				throw new ArgumentOutOfRangeException("count");
			if ((long)start + (long)count > array.Length)
				throw new ArgumentOutOfRangeException("start+count");

			int offset = start;
			int bufferRemaining = BlockSizeInBytes - _bufferFilled;

			if ((_bufferFilled > 0) && (count > bufferRemaining))
			{
				Array.Copy(array, offset, _buf, _bufferFilled, bufferRemaining);
				_counter0 += (uint)BlockSizeInBytes;
				if (_counter0 == 0)
					_counter1++;
				Compress(_buf, 0);
				offset += bufferRemaining;
				count -= bufferRemaining;
				_bufferFilled = 0;
			}

			while (count > BlockSizeInBytes)
			{
				_counter0 += (uint)BlockSizeInBytes;
				if (_counter0 == 0)
					_counter1++;
				Compress(array, offset);
				offset += BlockSizeInBytes;
				count -= BlockSizeInBytes;
			}

			if (count > 0)
			{
				Array.Copy(array, offset, _buf, _bufferFilled, count);
				_bufferFilled += count;
			}
		}

		public byte[] HashFinal()
		{
			return HashFinal(false);
		}

		// isEndOfLayer corresponds to the last_node flag in the C reference (f[1]).
		// It must be true for the last leaf in a tree layer and for the root node,
		// causing _finalizationFlag1 to be expanded to 0xFFFFFFFF and XORed into
		// v15 during the final compression, distinguishing those nodes from interior
		// ones. For sequential (non-tree) hashing always pass false (or use the
		// zero-argument overload).
		public byte[] HashFinal(bool isEndOfLayer)
		{
			if (!_isInitialized)
				throw new InvalidOperationException("Not initialized");
			_isInitialized = false;

			_counter0 += (uint)_bufferFilled;
			_finalizationFlag0 = true;
			if (isEndOfLayer)
				_finalizationFlag1 = true;
			for (int i = _bufferFilled; i < _buf.Length; i++)
				_buf[i] = 0;
			Compress(_buf, 0);

			byte[] hash = new byte[32];
			for (int i = 0; i < 8; i++)
				UInt32ToBytes(_h[i], hash, i * 4);
			return hash;
		}
	}
}
