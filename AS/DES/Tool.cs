using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DES
{
    class Tool
    {
		public static String StrToBin(String str,bool isasc = false)
		{
			//字符串内字符转二进制
			byte[] data;
            if (!isasc)
                data = Encoding.Unicode.GetBytes(str);
            else
                data = Encoding.ASCII.GetBytes(str);
			StringBuilder sb = new StringBuilder(data.Length * 8);
			foreach (byte item in data)
		    {
			    sb.Append(Convert.ToString(item, 2).PadLeft(8, '0'));
				//Console.WriteLine(Convert.ToString(item, 2).PadLeft(8, '0'));
		    }
			
			return sb.ToString();
		}

		public static String BinToStr(String binstr)
        {
			System.Text.RegularExpressions.CaptureCollection cs = System.Text.RegularExpressions.Regex.Match(binstr, @"([01]{8})+").Groups[1].Captures;
			//Group[0]无输出
			byte[] data = new byte[cs.Count];
			for (int i = 0; i < cs.Count; i++)
			{
				//Console.WriteLine(cs[i]);
				data[i] = Convert.ToByte(cs[i].Value, 2);
			}
	            return Encoding.Unicode.GetString(data, 0, data.Length);
		}

		public static bool Trans(int[] data, int[] Table)
		{
			//根据给定转换表转置数据
			int len = data.Length;
			if (len != Table.Length)
				return false;

			int[] Temp = new int[len];
			int Loc;
			data.CopyTo(Temp, 0);

			for (int i = 0; i < len; i++)
			{//根据置换表赋值
				Loc = Table[i] - 1;
				data[i] = Temp[Loc];
			}


			return true;
		}

		public static int[] BStrToInt(String bstr, int len)
		{//二进制字符串转int形式
			int[] bint = new int[len];
			int slen = bstr.Length;
			//Console.WriteLine("Bstr = " + bstr);
			//Console.WriteLine("slen = " + slen);
			for (int i = 0; i < slen; i++)
			{
				bint[i] = bstr[i] - '0';
				//Console.Write(bint[i] + ",");
			}
			//Console.WriteLine();
			return bint;
		}

		public static string BIntToStr(int[] arr)
        {//int二进制数组转二进制形式
			int len = arr.Length;
			StringBuilder sb = new StringBuilder();
			foreach(int i in arr)
            {
				sb.Append((char)('0' + i));
            }
			return sb.ToString();
        }

		public static void intArrEor(int[] A, int[] B)
		{//int数组A与B异或，结果保存于A中
			int len = A.Length;
			if (B.Length < len)
			{
				Console.WriteLine("Eor Length Error！");
				return;
			}

			for (int i = 0; i < len; i++)
			{
				A[i] = A[i] ^ B[i];
			}
		}

		public static int BinArrtoint(int[] arr)
		{//int二进制数组转正数int
			int len = arr.Length, result = 0;
			for (int i = 0; i < len; i++)
			{
				if (arr[i] == 1)
				{
					result += (int)Math.Pow(2, len - i - 1);
				}
			}
			return result;
		}

		public static void inttoBinArr(int i, int[] arr)
		{//int转二进制数组
			String bin = Convert.ToString(i, 2);
			//System.out.println(bin);
			char c = '0';

			int slen = bin.Length, ilen = arr.Length, gap = ilen - slen;
			if (slen > ilen)
			{
				Console.WriteLine("Arr Length Error！");
				return;
			}

			for (int j = 0; j < ilen; j++)
			{
				if (j < gap)
				{
					arr[j] = 0;
				}
				else
				{
					arr[j] = bin[j - gap] - c;
				}
			}
		}

		public static String StrtoHex(String s)
		{//字符串转十六进制字符
			String bin = StrToBin(s), result = "";
			int len = bin.Length, i, con = 0, val, rlen;
			int[] tmp = { 0, 0, 0, 0 };
			rlen = len / 4;
			char c;

			for (i = 0; i < len; i++)
			{
				if (bin[i] == '0')
				{
					tmp[con] = 0;
				}
				else
				{
					tmp[con] = 1;
				}
				con++;
				if (con == 4)
				{
					val = BinArrtoint(tmp);
					if (val < 10)
					{
						result += (char)(val + '0');
					}
					else
					{
						result += (char)(val + 'A' - 10);
					}
					con = 0;
				}
			}
			return result;
		}

		public static String HextoStr(String Hex)
		{//十六进制字符串转字符串
			int len = Hex.Length, con, val, ctmp = 0, cur = 0, clen = len / 2;
			int[] Arr4 = { 0, 0, 0, 0 };
			String result;
			char c, tmp = (char)0;
			char[] CArr = new char[clen];
			for (int i = 0; i < len; i++)
			{
				c = Hex[i];
				if (c <= '9' && c >= '0')
				{
					val = c - '0';

				}
				else
				{
					val = c - 'A' + 10;
				}
				inttoBinArr(val, Arr4);
				if (i % 2 == 0)
				{
					ctmp += (int)(val * Math.Pow(2, 4));
				}
				else
				{
					ctmp += val;
					CArr[cur] = (char)ctmp;
					cur++;
					ctmp = 0;
				}

			}
			

			result = CArr.ToString();

			return result;
		}

		public static string binStrToHex(string binstr)
        {
			StringBuilder sb = new StringBuilder();
			//Console.WriteLine("被转化时字符串" + binstr);
			System.Text.RegularExpressions.CaptureCollection cs = System.Text.RegularExpressions.Regex.Match(binstr, @"([01]{4})+").Groups[1].Captures;
			for (int i = 0; i < cs.Count; i++)
			{
				//Console.WriteLine(cs[i].Value + "值为" + Convert.ToInt32(cs[i].Value, 2));
				sb.Append(Convert.ToInt32(cs[i].Value, 2).ToString("X1"));
			}
			//Console.WriteLine(sb.ToString());
			return sb.ToString();
		}

		public static string hexStrToBin(string hex)
        {
			StringBuilder sb = new StringBuilder();
			char[] temp = hex.ToCharArray();
			int i;
			foreach(char c in temp)
            {
				if (c >= '0' && c <= '9')
					i = c - '0';
				else
					i = c - 'A' + 10;
				sb.Append(Convert.ToString(i,2).PadLeft(4,'0'));
            }
			return sb.ToString();
		}

		public static string[] splitStrn(String s, int n)
		{//每n位分割一个String
			char[] splitch, chTmp = new char[n];

			int i, j, len = s.Length, times = len / n, surplus = len % n;
			String[] result;
			splitch = s.ToCharArray();

			if (surplus == 0)
				result = new String[times];
			else
				result = new string[times + 1];

			for (i = 0; i < times; i++)
			{
				for (j = 0; j < n; j++)
				{
					chTmp[j] = splitch[i * n + j];
				}
				result[i] = new String(chTmp);
				//Console.WriteLine(result[i]);
			}

			chTmp = new char[surplus];
			if (surplus > 0)
			{
				for (j = 0; j < surplus; j++)
				{
					chTmp[j] = splitch[i * n + j];
				}
				result[i] = new String(chTmp);
				//Console.WriteLine(result[i]);
			}

			return result;
		}

		public static String txtDES(String txt, bool isPlain, String key)//DES加密、解密
		{

			String destxt, DESResult, detxt;
			String[] txts;

			DES DEScode;

			destxt = "";
			detxt = "";
			if (isPlain)
				txts = splitStrn(txt, 4);
			else
				txts = splitStrn(txt, 16);


			DEScode = new DES(txts, isPlain, key);
			DESResult = DEScode.getProcTxt();

			if (isPlain)
				destxt = Tool.binStrToHex(DESResult);
			else
				destxt = Tool.BinToStr(DESResult);
			return destxt;
		}
	}
}
