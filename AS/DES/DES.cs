using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DES
{
    class DES
    {
		private String[] OriginTxt;//输入的字符串
		private String[] ProcTxt;//输出的加密/解密二进制字符串

		private Box box;
		private IP ip;
		private KEY key;
		private TxtPDES[] destxt;

		public DES(String[] txtSet, bool IsPlain, String k)
		{
			string keystr, vector,temp;
			OriginTxt = txtSet;
			int Count = OriginTxt.Length;
			ProcTxt = new String[Count];
			temp = k.PadRight(16, '0');
			keystr = temp.Substring(0, 8);
			vector = temp.Substring(8, 8);
			key = new KEY(keystr, IsPlain);
			ip = new IP();
			box = new Box();
			destxt = new TxtPDES[Count];

			for (int i = 0; i < Count; i++)
			{
				//Console.WriteLine(OriginTxt[i]);
				destxt[i] = new TxtPDES(OriginTxt[i], box, key, ip, vector, IsPlain);
				ProcTxt[i] = destxt[i].getDESString();
			}
		}

		public String getProcTxt()
		{//获取DES的结果
			int len = ProcTxt.Length;
			StringBuilder sb = new StringBuilder();

			for (int i = 0; i < len; i++)
			{
				//Console.WriteLine("二进制：" + ProcTxt[i]);
				sb.Append(ProcTxt[i]);
			}

			return sb.ToString();
		}
	}
}
