// BLAKE2 reference source code package - C# implementation
// Computes a BLAKE2sp hash of the file named on the command line and prints
// the hex digest followed by the filename, matching the output format of
// the companion blake2sp-hash C binary.

using System;
using System.IO;
using Blake2Sharp;

class Program
{
	static int Main(string[] args)
	{
		if (args.Length != 1)
		{
			Console.Error.WriteLine("Usage: Blake2SpHash <filename>");
			return 1;
		}

		string path = args[0];
		if (!File.Exists(path))
		{
			Console.Error.WriteLine("Error: cannot open file '" + path + "'");
			return 1;
		}

		var hasher = Blake2Sp.Create();
		byte[] buf = new byte[65536];

		using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
		{
			int n;
			while ((n = fs.Read(buf, 0, buf.Length)) > 0)
				hasher.Update(buf, 0, n);
		}

		byte[] hash = hasher.Finish();
		Console.WriteLine(BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant() + "  " + path);
		return 0;
	}
}
