// BLAKE2 reference source code package - C# implementation

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

using System;

namespace Blake2Sharp
{
	// Sequential (non-parallel) BLAKE2s hasher.
	internal sealed class Blake2SHasher : Hasher
	{
		private readonly Blake2SCore _core = new Blake2SCore();
		private readonly uint[] _rawConfig;
		private readonly byte[] _key;          // padded to block size, or null
		private readonly int _outputSizeInBytes;

		private static readonly Blake2SConfig DefaultConfig = new Blake2SConfig();

		public Blake2SHasher(Blake2SConfig config)
		{
			if (config == null)
				config = DefaultConfig;
			_rawConfig = Blake2IvBuilder.ConfigS(config, null);
			if (config.Key != null && config.Key.Length != 0)
			{
				// Key is padded to a full block before being hashed as first message block
				_key = new byte[Blake2SCore.BlockSizeInBytes];
				Array.Copy(config.Key, _key, config.Key.Length);
			}
			_outputSizeInBytes = config.OutputSizeInBytes;
			Init();
		}

		public override void Init()
		{
			_core.Initialize(_rawConfig);
			if (_key != null)
				_core.HashCore(_key, 0, _key.Length);
		}

		public override void Update(byte[] data, int start, int count)
		{
			_core.HashCore(data, start, count);
		}

		public override byte[] Finish()
		{
			var fullResult = _core.HashFinal();
			if (_outputSizeInBytes != fullResult.Length)
			{
				var result = new byte[_outputSizeInBytes];
				Array.Copy(fullResult, result, result.Length);
				return result;
			}
			return fullResult;
		}
	}
}
