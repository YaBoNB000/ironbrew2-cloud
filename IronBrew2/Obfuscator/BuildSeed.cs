using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace IronBrew2.Obfuscator
{
	/// <summary>
	/// Owns the single CSPRNG master seed for one obfuscation build and derives
	/// purpose-separated deterministic streams with HMAC-SHA-256. The master seed
	/// is compiler-side state only: generated payloads contain the values consumed
	/// from individual streams, never this root value.
	/// </summary>
	public sealed class BuildSeed : IDisposable
	{
		private const int MasterSeedBytes = 32;
		private static readonly byte[] DerivationPrefix =
			Encoding.ASCII.GetBytes("IronBrew2.BuildSeed.v1\0");

		private readonly byte[] _masterSeed;
		private readonly Dictionary<string, BuildRandom> _streams =
			new Dictionary<string, BuildRandom>(StringComparer.Ordinal);
		private bool _disposed;

		public BuildSeed()
			: this(RandomNumberGenerator.GetBytes(MasterSeedBytes))
		{
		}

		/// <summary>
		/// Creates a reproducible build root for library callers and regression tests.
		/// CLI builds always use the parameterless CSPRNG constructor.
		/// </summary>
		public BuildSeed(ReadOnlySpan<byte> masterSeed)
		{
			if (masterSeed.Length != MasterSeedBytes)
				throw new ArgumentException($"Build master seed must contain {MasterSeedBytes} bytes.", nameof(masterSeed));
			_masterSeed = masterSeed.ToArray();
		}

		/// <summary>
		/// Returns the unique mutable stream for a purpose. Repeated requests for the
		/// same purpose continue that stream instead of restarting its sequence.
		/// </summary>
		public BuildRandom GetStream(string purpose)
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			if (string.IsNullOrWhiteSpace(purpose))
				throw new ArgumentException("A non-empty build-random purpose is required.", nameof(purpose));

			lock (_streams)
			{
				if (_streams.TryGetValue(purpose, out BuildRandom existing))
					return existing;

				byte[] purposeBytes = Encoding.UTF8.GetBytes(purpose);
				byte[] message = new byte[DerivationPrefix.Length + purposeBytes.Length];
				Buffer.BlockCopy(DerivationPrefix, 0, message, 0, DerivationPrefix.Length);
				Buffer.BlockCopy(purposeBytes, 0, message, DerivationPrefix.Length, purposeBytes.Length);
				byte[] key = HMACSHA256.HashData(_masterSeed, message);
				CryptographicOperations.ZeroMemory(message);
				var stream = new BuildRandom(key);
				CryptographicOperations.ZeroMemory(key);
				_streams.Add(purpose, stream);
				return stream;
			}
		}

		public void Dispose()
		{
			if (_disposed) return;
			lock (_streams)
			{
				foreach (BuildRandom stream in _streams.Values)
					stream.Clear();
				_streams.Clear();
				CryptographicOperations.ZeroMemory(_masterSeed);
				_disposed = true;
			}
		}
	}

	/// <summary>
	/// HMAC counter-mode random stream used by a single BuildSeed purpose. It
	/// derives unbiased bounded integers and implements Random so existing
	/// generation algorithms can migrate without reverting to process-global RNGs.
	/// </summary>
	public sealed class BuildRandom : Random
	{
		private readonly byte[] _key;
		private readonly byte[] _block = new byte[32];
		private ulong _counter;
		private int _offset = 32;
		private bool _cleared;

		internal BuildRandom(ReadOnlySpan<byte> key)
		{
			if (key.Length != 32)
				throw new ArgumentException("Build stream keys must contain 32 bytes.", nameof(key));
			_key = key.ToArray();
		}

		private void Refill()
		{
			ObjectDisposedException.ThrowIf(_cleared, this);
			Span<byte> input = stackalloc byte[8];
			BinaryPrimitives.WriteUInt64LittleEndian(input, _counter++);
			byte[] next = HMACSHA256.HashData(_key, input);
			next.CopyTo(_block, 0);
			CryptographicOperations.ZeroMemory(next);
			_offset = 0;
		}

		private void Fill(Span<byte> output)
		{
			int written = 0;
			while (written < output.Length)
			{
				if (_offset == _block.Length) Refill();
				int count = Math.Min(output.Length - written, _block.Length - _offset);
				_block.AsSpan(_offset, count).CopyTo(output.Slice(written, count));
				_offset += count;
				written += count;
			}
		}

		public uint NextUInt32()
		{
			Span<byte> bytes = stackalloc byte[4];
			Fill(bytes);
			return BinaryPrimitives.ReadUInt32LittleEndian(bytes);
		}

		public uint NextUInt32(uint minimumInclusive, uint maximumExclusive)
		{
			if (minimumInclusive >= maximumExclusive)
				throw new ArgumentOutOfRangeException(nameof(maximumExclusive));
			return minimumInclusive + NextBounded(maximumExclusive - minimumInclusive);
		}

		public byte[] GetBytes(int length)
		{
			if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
			byte[] output = new byte[length];
			NextBytes(output);
			return output;
		}

		private uint NextBounded(uint bound)
		{
			if (bound == 0) throw new ArgumentOutOfRangeException(nameof(bound));
			uint threshold = unchecked(0u - bound) % bound;
			uint value;
			do value = NextUInt32(); while (value < threshold);
			return value % bound;
		}

		private ulong NextUInt64()
		{
			Span<byte> bytes = stackalloc byte[8];
			Fill(bytes);
			return BinaryPrimitives.ReadUInt64LittleEndian(bytes);
		}

		private ulong NextBounded(ulong bound)
		{
			if (bound == 0) throw new ArgumentOutOfRangeException(nameof(bound));
			ulong threshold = unchecked(0UL - bound) % bound;
			ulong value;
			do value = NextUInt64(); while (value < threshold);
			return value % bound;
		}

		public override int Next() => (int)NextBounded(int.MaxValue);

		public override int Next(int maxValue)
		{
			if (maxValue < 0) throw new ArgumentOutOfRangeException(nameof(maxValue));
			return maxValue == 0 ? 0 : (int)NextBounded((uint)maxValue);
		}

		public override int Next(int minValue, int maxValue)
		{
			if (minValue > maxValue) throw new ArgumentOutOfRangeException(nameof(minValue));
			ulong range = (ulong)(long)maxValue - (ulong)(long)minValue;
			return range == 0 ? minValue : (int)((ulong)(long)minValue + NextBounded(range));
		}

		public override long NextInt64() => (long)NextBounded((ulong)long.MaxValue);

		public override long NextInt64(long maxValue)
		{
			if (maxValue < 0) throw new ArgumentOutOfRangeException(nameof(maxValue));
			return maxValue == 0 ? 0 : (long)NextBounded((ulong)maxValue);
		}

		public override long NextInt64(long minValue, long maxValue)
		{
			if (minValue > maxValue) throw new ArgumentOutOfRangeException(nameof(minValue));
			ulong range = unchecked((ulong)maxValue - (ulong)minValue);
			return range == 0 ? minValue : unchecked((long)((ulong)minValue + NextBounded(range)));
		}

		protected override double Sample() => NextDouble();

		public override double NextDouble() =>
			(NextUInt64() >> 11) * (1.0 / (1UL << 53));

		public override void NextBytes(byte[] buffer)
		{
			ArgumentNullException.ThrowIfNull(buffer);
			Fill(buffer);
		}

		public override void NextBytes(Span<byte> buffer) => Fill(buffer);

		internal void Clear()
		{
			if (_cleared) return;
			CryptographicOperations.ZeroMemory(_key);
			CryptographicOperations.ZeroMemory(_block);
			_cleared = true;
		}
	}
}
