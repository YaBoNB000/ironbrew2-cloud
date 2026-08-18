using System;
using System.Collections.Generic;
using System.Linq;

namespace IronBrew2.Obfuscator
{
	public enum OuterHeaderField
	{
		Head,
		Integrity,
		Flags
	}

	public enum EnvelopeHeaderField
	{
		FramedLength,
		EntropyLength,
		RecordCount,
		DataCount,
		EntropyCount,
		Nonce,
		EntropyDigest,
		Integrity
	}

	public enum EnvelopeRecordField
	{
		Kind,
		Ordinal,
		Length
	}

	/// <summary>
	/// Build-local physical payload grammar.  The generated VM receives only the
	/// selected coordinates; it does not carry a universal format switch or a
	/// self-describing layout byte that an old parser can blindly follow.
	/// </summary>
	public sealed class PayloadFormatLayout
	{
		public OuterHeaderField[] OuterHeaderOrder { get; }
		public EnvelopeHeaderField[] EnvelopeHeaderOrder { get; }
		public EnvelopeRecordField[] EnvelopeRecordOrder { get; }
		public int RecordOrdinalWidth { get; }
		public int RecordLengthWidth { get; }
		public int PageLengthWidth { get; }
		public bool PageLengthSuffix { get; }
		public int PipelineVariant { get; }
		public int ByteTransformVariant { get; }
		public int ByteTransformParameter { get; }

		public int OuterHeadOffset => FieldOffset(OuterHeaderOrder, OuterHeaderField.Head, OuterWidth);
		public int OuterIntegrityOffset => FieldOffset(OuterHeaderOrder, OuterHeaderField.Integrity, OuterWidth);
		public int OuterFlagsOffset => FieldOffset(OuterHeaderOrder, OuterHeaderField.Flags, OuterWidth);
		public int EnvelopeIntegrityOffset =>
			Array.IndexOf(EnvelopeHeaderOrder, EnvelopeHeaderField.Integrity) * 4;
		public int RecordHeaderWidth => 1 + RecordOrdinalWidth + RecordLengthWidth;

		public PayloadFormatLayout(BuildDomains domains)
		{
			if (domains == null) throw new ArgumentNullException(nameof(domains));

			OuterHeaderOrder = DerivePermutation(3, domains.PayloadFormatDomain, 0x13579BDFu)
				.Select(value => (OuterHeaderField)value).ToArray();
			EnvelopeHeaderOrder = DerivePermutation(8, domains.PayloadFormatDomain, 0x2468ACE1u)
				.Select(value => (EnvelopeHeaderField)value).ToArray();
			EnvelopeRecordOrder = DerivePermutation(3, domains.PayloadFormatDomain, 0x9E3779B9u)
				.Select(value => (EnvelopeRecordField)value).ToArray();

			RecordOrdinalWidth = ((domains.PayloadFormatDomain >> 3) & 1u) == 0 ? 2 : 4;
			RecordLengthWidth = ((domains.PayloadFormatDomain >> 7) & 1u) == 0 ? 3 : 4;
			PageLengthWidth = ((domains.PayloadFormatDomain >> 11) & 1u) == 0 ? 2 : 4;
			PageLengthSuffix = ((domains.PayloadFormatDomain >> 15) & 1u) != 0;
			PipelineVariant = (int)(domains.DecodePipelineDomain % 3u);
			ByteTransformVariant = (int)((domains.DecodePipelineDomain >> 8) % 4u);
			ByteTransformParameter = ByteTransformVariant == 3
				? (int)(((domains.DecodePipelineDomain >> 18) % 7u) + 1u)
				: (int)(((domains.DecodePipelineDomain >> 16) ^ domains.PayloadFormatDomain) & 0xFFu);
		}

		public int EnvelopeSlot(EnvelopeHeaderField field) =>
			Array.IndexOf(EnvelopeHeaderOrder, field) + 1;

		public int RecordSlot(EnvelopeRecordField field) =>
			Array.IndexOf(EnvelopeRecordOrder, field) + 1;

		private static int OuterWidth(OuterHeaderField field) =>
			field == OuterHeaderField.Flags ? 1 : 4;

		private static int FieldOffset<T>(IReadOnlyList<T> order, T target, Func<T, int> width)
		{
			int offset = 0;
			foreach (T field in order)
			{
				if (EqualityComparer<T>.Default.Equals(field, target)) return offset;
				offset += width(field);
			}
			throw new InvalidOperationException("Payload format field is missing.");
		}

		private static int[] DerivePermutation(int count, uint seed, uint domain)
		{
			int[] values = Enumerable.Range(0, count).ToArray();
			uint state = seed ^ domain;
			for (int size = count; size >= 2; size--)
			{
				state = unchecked(state * 1664525u + 1013904223u + (uint)size * domain);
				int target = (int)(state % (uint)size);
				(values[size - 1], values[target]) = (values[target], values[size - 1]);
			}
			return values;
		}
	}
}
