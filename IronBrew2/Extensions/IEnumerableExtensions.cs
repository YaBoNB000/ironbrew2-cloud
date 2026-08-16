using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace IronBrew2.Extensions
{
	public static class IEnumerableExtensions
	{
		/// <summary>Fisher-Yates shuffle backed by the operating system CSPRNG.</summary>
		public static void Shuffle<T>(this IList<T> list)
		{
			for (int i = list.Count - 1; i > 0; i--)
				list.Swap(i, RandomNumberGenerator.GetInt32(i + 1));
		}

		/// <summary>Fisher-Yates shuffle driven by a build-purpose stream.</summary>
		public static void Shuffle<T>(this IList<T> list, Random random)
		{
			if (random == null) throw new ArgumentNullException(nameof(random));
			for (int i = list.Count - 1; i > 0; i--)
				list.Swap(i, random.Next(i + 1));
		}

		public static void Swap<T>(this IList<T> list, int i, int j)
		{
			T temp = list[i];
			list[i] = list[j];
			list[j] = temp;
		}

		public static T Random<T>(this IList<T> list) =>
			list[RandomNumberGenerator.GetInt32(list.Count)];
	}
}
