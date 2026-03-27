// BLAKE2 reference source code package - C# implementation

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

namespace Blake2Sharp
{
	// Tree configuration for BLAKE2s (shared across all nodes in the tree).
	// For sequential hashing use the static Sequential instance (fanout=1, depth=1).
	// For BLAKE2sp use CreateInterleaved(8).
	//
	// Note: node_offset and node_depth are per-node properties, not per-tree, so
	// they are not here. ConfigS() sets node_offset=0 and node_depth=0; callers
	// that need specific values patch the raw config array via ConfigSSetNode().
	// This mirrors Blake2BTreeConfig, which also has no NodeOffset field.
	public sealed class Blake2STreeConfig
	{
		public int IntermediateHashSize { get; set; }  // inner_length; must be 32 for BLAKE2sp
		public int MaxHeight { get; set; }             // depth
		public int LeafSize { get; set; }              // leaf_length (0 = unlimited)
		public int FanOut { get; set; }

		// Sequential: fanout=1, depth=1, inner_length=0
		internal static readonly Blake2STreeConfig Sequential =
			new Blake2STreeConfig { IntermediateHashSize = 0, LeafSize = 0, FanOut = 1, MaxHeight = 1 };

		// Returns a tree config for BLAKE2sp-style parallel hashing with the
		// given parallelism degree (8 for spec-compliant BLAKE2sp).
		public static Blake2STreeConfig CreateInterleaved(int parallelism)
		{
			return new Blake2STreeConfig
			{
				IntermediateHashSize = 32,
				LeafSize = 0,
				FanOut = parallelism,
				MaxHeight = 2,
			};
		}
	}
}
