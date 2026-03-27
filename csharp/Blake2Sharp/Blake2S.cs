// BLAKE2 reference source code package - C# implementation

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

using System;

namespace Blake2Sharp
{
	// Public factory and one-shot API for BLAKE2s (sequential).
	public static class Blake2S
	{
		public static Hasher Create()
		{
			return Create(new Blake2SConfig());
		}

		public static Hasher Create(Blake2SConfig config)
		{
			return new Blake2SHasher(config);
		}

		public static byte[] ComputeHash(byte[] data)
		{
			return ComputeHash(data, 0, data.Length, null);
		}

		public static byte[] ComputeHash(ReadOnlySpan<byte> data)
		{
			return ComputeHash(data, null);
		}

		public static byte[] ComputeHash(ReadOnlySpan<byte> data, Blake2SConfig config)
		{
			var hasher = Create(config);
			hasher.Update(data);
			return hasher.Finish();
		}

		public static byte[] ComputeHash(byte[] data, Blake2SConfig config)
		{
			return ComputeHash(data, 0, data.Length, config);
		}

		public static byte[] ComputeHash(byte[] data, int start, int count)
		{
			return ComputeHash(data, start, count, null);
		}

		public static byte[] ComputeHash(byte[] data, int start, int count, Blake2SConfig config)
		{
			var hasher = Create(config);
			hasher.Update(data, start, count);
			return hasher.Finish();
		}
	}
}
