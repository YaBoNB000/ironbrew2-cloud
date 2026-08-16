using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace IronBrew2.Obfuscator.Encryption
{
	public class Decryptor
	{
		public int[] Table;
		public int SLen = 0;
		
		public string Name;
		private readonly BuildRandom _random;

		private static string BuildXorFn()
		{
			return "local function xr(a,c)local d,e=1,0;while a>0 and c>0 do local f,g=a%2,c%2;if f~=g then e=e+d end;a,c,d=(a-f)/2,(c-g)/2,d*2 end;if a<c then a=c end;while a>0 do local f=a%2;if f>0 then e=e+d end;a,d=(a-f)/2,d*2 end;return e end;";
		}

		private static string LuaNum(long v)
		{
			return v.ToString();
		}

		public string Encrypt(byte[] bytes)
		{
			BuildRandom rnd = _random;
			int variant = rnd.Next(0, 3);
			List<byte> encrypted = new List<byte>();

			// 模板 A:动态 Fisher-Yates 置换表 + LCG 密钥流(表不存明文)
			if (variant == 0)
			{
				long seed = rnd.Next(1, 0x7FFFFFFF);
				int m1 = rnd.Next(1664525, 2500000) | 1;  // 奇数且 < 2^22,保证 s*m1+m2 < 2^53(Lua double 精确)
				long m2 = rnd.Next(1, 0x7FFFFFFF);

				int[] T = new int[256];
				for (int i = 0; i < 256; i++) T[i] = i;
				long s = seed;
				for (int i = 255; i >= 1; i--)
				{
					s = (s * m1 + m2) % 2147483648L;
					int j = (int)(s % (i + 1));
					int tmp = T[i]; T[i] = T[j]; T[j] = tmp;
				}
				int[] InvT = new int[256];
				for (int i = 0; i < 256; i++) InvT[T[i]] = i;

				s = seed;
				foreach (byte b in bytes)
				{
					s = (s * m1 + m2) % 2147483648L;
					int key = (int)(s % 256);
					encrypted.Add((byte)InvT[b ^ key]);
				}

				return "((function(b)IB_INLINING_START(true);" + BuildXorFn()
					+ "local T={}for i=0,255 do T[i]=i end;local s=" + LuaNum(seed)
					+ ";for i=255,1,-1 do s=(s*" + LuaNum(m1) + "+" + LuaNum(m2) + ")%2147483648;local j=s%(i+1);T[i],T[j]=T[j],T[i]end;"
					+ "local c=\"\"s=" + LuaNum(seed)
					+ ";for i=1,#b do s=(s*" + LuaNum(m1) + "+" + LuaNum(m2) + ")%2147483648;c=c..string.char(xr(T[string.byte(b,i)],s%256))end;return c end)(\""
					+ string.Join("", encrypted.Select(t => "\\" + t.ToString())) + "\"))";
			}

			// 模板 B:字节反转 + LCG 密钥流 XOR(无表)
			if (variant == 1)
			{
				long seed = rnd.Next(1, 0x7FFFFFFF);
				int m1 = rnd.Next(1664525, 2500000) | 1;  // 奇数且 < 2^22,保证 s*m1+m2 < 2^53(Lua double 精确)
				long m2 = rnd.Next(1, 0x7FFFFFFF);

				byte[] rev = new byte[bytes.Length];
				for (int i = 0; i < bytes.Length; i++)
					rev[bytes.Length - 1 - i] = bytes[i];

				long s = seed;
				foreach (byte b in rev)
				{
					s = (s * m1 + m2) % 2147483648L;
					int key = (int)(s % 256);
					encrypted.Add((byte)(b ^ key));
				}

				return "((function(b)IB_INLINING_START(true);" + BuildXorFn()
					+ "local c=\"\"local s=" + LuaNum(seed)
					+ ";for i=1,#b do s=(s*" + LuaNum(m1) + "+" + LuaNum(m2) + ")%2147483648;c=string.char(xr(string.byte(b,i),s%256))..c end;return c end)(\""
					+ string.Join("", encrypted.Select(t => "\\" + t.ToString())) + "\"))";
			}

			// 模板 C:双向 LCG(前进/后退) + 常量偏移 XOR
			{
				long seed = rnd.Next(1, 0x7FFFFFFF);
				int m1 = rnd.Next(1664525, 2500000) | 1;
				long m2 = rnd.Next(1, 0x7FFFFFFF);
				int off = rnd.Next(1, 255);

				long s = seed;
				foreach (byte b in bytes)
				{
					s = (s * m1 + m2) % 2147483648L;
					int key = (int)(s % 256);
					encrypted.Add((byte)((b + off) ^ key));
				}

				return "((function(b)IB_INLINING_START(true);" + BuildXorFn()
					+ "local c=\"\"local s=" + LuaNum(seed)
					+ ";for i=1,#b do s=(s*" + LuaNum(m1) + "+" + LuaNum(m2) + ")%2147483648;c=c..string.char((xr(string.byte(b,i),s%256)+256-" + off + ")%256)end;return c end)(\""
					+ string.Join("", encrypted.Select(t => "\\" + t.ToString())) + "\"))";
			}
		}

		public Decryptor(string name, int maxLen, BuildRandom random)
		{
			_random = random ?? throw new ArgumentNullException(nameof(random));
			Name = name;
			Table = Enumerable.Repeat(0, maxLen).Select(i => _random.Next(0, 256)).ToArray();
		}
	}
	
	public class ConstantEncryption
	{
		private string _src;
		private ObfuscationSettings _settings;
		private readonly BuildRandom _random;
		private Encoding _fuckingLua = Encoding.GetEncoding(28591);

		public Decryptor GenerateGenericDecryptor(MatchCollection matches)
		{
			int len = 0;

			for (int i = 0; i < matches.Count; i++)
			{
				int l = matches[i].Length;
				if (l > len)
					len = l;
			}

			if (len > _settings.DecryptTableLen)
				len = _settings.DecryptTableLen;
			
			return new Decryptor("IRONBREW_STR_DEC_GENERIC", len, _random);
		}

		public static byte[] UnescapeLuaString(string str)
		{
			List<byte> bytes = new List<byte>();
			
			int i = 0;
			while (i < str.Length)
			{
				char cur = str[i++];
				if (cur == '\\')
				{
					char next = str[i++];

					switch (next)
					{
						case 'a':
							bytes.Add((byte) '\a');
							break;

						case 'b':
							bytes.Add((byte) '\b');
							break;

						case 'f':
							bytes.Add((byte) '\f');
							break;

						case 'n':
							bytes.Add((byte) '\n');
							break;

						case 'r':
							bytes.Add((byte) '\r');
							break;

						case 't':
							bytes.Add((byte) '\t');
							break;

						case 'v':
							bytes.Add((byte) '\v');
							break;

						default:
						{
							if (!char.IsDigit(next))
								bytes.Add((byte) next);
							else // \001, \55h, etc
							{
								string s = next.ToString(); 
								for (int j = 0; j < 2; j++, i++)
								{
									if (i == str.Length)
										break;

									char n = str[i];
									if (char.IsDigit(n))
										s = s + n;
									else
										break;
								}

								bytes.Add((byte) int.Parse(s));
							}

							break;
						}
					}
				}
				else
					bytes.Add((byte) cur);
			}

			return bytes.ToArray();
		}

		public string EncryptStrings()
		{
			const string encRegex = @"(['""])?(?(1)((?:[^\\]|\\.)*?)\1|\[(=*)\[(.*?)\]\3\])";
			
			if (_settings.EncryptStrings)
			{
				Regex r       = new Regex(encRegex, RegexOptions.Singleline | RegexOptions.Compiled);

				int indDiff = 0;
				var   matches = r.Matches(_src);
				
				Decryptor dec     = GenerateGenericDecryptor(matches);
			
				foreach (Match m in matches)
				{
					string before = _src.Substring(0, m.Index        + indDiff);
					string after  = _src.Substring(m.Index + indDiff + m.Length);

					string captured = m.Groups[2].Value + m.Groups[4].Value;

					if (captured.StartsWith("[STR_ENCRYPT]"))
						captured = captured.Substring(13);
					
					string nStr = before + dec.Encrypt(m.Groups[2].Value != "" ? UnescapeLuaString(captured) : _fuckingLua.GetBytes(captured));
					nStr += after;
				
					indDiff += nStr.Length - _src.Length;
					_src    =  nStr;
				}
			}

			else
			{
				Regex r = new Regex(encRegex, RegexOptions.Singleline | RegexOptions.Compiled);
				var matches = r.Matches(_src);

				int indDiff = 0;
				int n       = 0;

				foreach (Match m in matches)
				{
					string captured = m.Groups[2].Value + m.Groups[4].Value;
					
					if (!captured.StartsWith("[STR_ENCRYPT]"))
						continue;

					captured = captured.Substring(13);
					Decryptor dec = new Decryptor("IRONBREW_STR_ENCRYPT" + n++, m.Length, _random);

					string before = _src.Substring(0, m.Index + indDiff);
					string after = _src.Substring(m.Index + indDiff + m.Length);

					string nStr = before + dec.Encrypt(m.Groups[2].Value != ""
						              ? UnescapeLuaString(captured)
						              : _fuckingLua.GetBytes(captured));
					nStr += after;

					indDiff += nStr.Length - _src.Length;
					_src = nStr;
				}
			}
			
			if (_settings.EncryptImportantStrings)
			{
				Regex r = new Regex(encRegex, RegexOptions.Singleline | RegexOptions.Compiled);
				var matches = r.Matches(_src);

				int indDiff = 0;
				int n = 0;

				List<string> sTerms = new List<string>() {"http", "function", "metatable", "local"};

				foreach (Match m in matches)
				{
					string captured = m.Groups[2].Value + m.Groups[4].Value;
					if (captured.StartsWith("[STR_ENCRYPT]"))
						captured = captured.Substring(13);

					bool cont = false;

					foreach (string search in sTerms)
					{
						if (captured.ToLower().Contains(search.ToLower()))
							cont = true;
					}

					if (!cont)
						continue;

					Decryptor dec = new Decryptor("IRONBREW_STR_ENCRYPT_IMPORTANT" + n++, m.Length, _random);

					string before = _src.Substring(0, m.Index + indDiff);
					string after = _src.Substring(m.Index + indDiff + m.Length);

					string nStr = before + dec.Encrypt(m.Groups[2].Value != ""
						              ? UnescapeLuaString(captured)
						              : _fuckingLua.GetBytes(captured));

					nStr += after;

					indDiff += nStr.Length - _src.Length;
					_src = nStr;
				}
			}

			return _src;
		}

		public ConstantEncryption(ObfuscationSettings settings, string source, BuildRandom random)
		{
			_settings = settings;
			_src = source;
			_random = random ?? throw new ArgumentNullException(nameof(random));
		}
	}
}