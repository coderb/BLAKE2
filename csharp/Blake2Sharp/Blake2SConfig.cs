// BLAKE2 reference source code package - C# implementation

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

using System;

namespace Blake2Sharp
{
	// BLAKE2s: 32-bit variant. Max output 32 bytes, max key 32 bytes,
	// salt 8 bytes, personalization 8 bytes.
	public sealed class Blake2SConfig : ICloneable
	{
		public byte[] Personalization { get; set; }  // exactly 8 bytes if set
		public byte[] Salt { get; set; }             // exactly 8 bytes if set
		public byte[] Key { get; set; }              // 1..32 bytes if set
		public int OutputSizeInBytes { get; set; }
		public int OutputSizeInBits
		{
			get { return OutputSizeInBytes * 8; }
			set
			{
				if (value % 8 != 0)
					throw new ArgumentException("Output size must be a multiple of 8 bits");
				OutputSizeInBytes = value / 8;
			}
		}

		public Blake2SConfig()
		{
			OutputSizeInBytes = 32;
		}

		public Blake2SConfig Clone()
		{
			var result = new Blake2SConfig();
			result.OutputSizeInBytes = OutputSizeInBytes;
			if (Key != null)
				result.Key = (byte[])Key.Clone();
			if (Personalization != null)
				result.Personalization = (byte[])Personalization.Clone();
			if (Salt != null)
				result.Salt = (byte[])Salt.Clone();
			return result;
		}

		object ICloneable.Clone()
		{
			return Clone();
		}
	}
}
