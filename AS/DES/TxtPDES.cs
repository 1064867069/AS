using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DES
{
    class TxtPDES
    {
		private String TxtP;//64位明文或密文
		private int[] BinTxtOr;//64位明文、密文二进制
		private int[] EData;//根据E扩展置换表得出的二进制数组

		private int[] LPre;//Li-1
		private int[] RPre;//Ri-1
		private int[] LNext;//L
		private int[] RNext;//R
		private int[] DEStxt;//加密、解密后得到的文本
							 //private int[] RTemp;//Ri-1与秘钥异或运算的结果
		private int[] ETable = {
			32, 1, 2, 3, 4, 5,
			4, 5, 6, 7, 8, 9,
			8, 9, 10, 11, 12, 13,
			12, 13, 14, 15, 16, 17,
			16, 17, 18, 19, 20, 21,
			20, 21, 22, 23, 24, 25,
			24, 25, 26, 27, 28, 29,
			28, 29, 30, 31, 32, 1
	};//E扩展置换表

		public TxtPDES(string txt, Box b, KEY k, IP ip,string vector, bool isPlain)
		{
			//Console.WriteLine("操作" + txt + "时");
			TxtP = txt;

			EData = new int[48];
			LPre = new int[32];
			RPre = new int[32];
			LNext = new int[32];
			RNext = new int[32];
			DEStxt = new int[64];
			String TBstr,vbinstr = Tool.StrToBin(vector,true);
			int[] viarr = Tool.BStrToInt(vbinstr,64);
			//Console.WriteLine(txt);
			if (isPlain)
				TBstr = Tool.StrToBin(TxtP);
			else
				TBstr = Tool.hexStrToBin(TxtP);

			if (TBstr.Length > 64)
			{
				Console.WriteLine("TBstr的长度大于64！");
			}
			BinTxtOr = Tool.BStrToInt(TBstr, 64);
			//if(isPlain)
			//	Tool.intArrEor
			//Console.WriteLine("原字符串：" + TxtP);
			//Console.WriteLine(TBstr);
			BstrDefault(TBstr);
			//foreach (int i in BinTxtOr)
			//{
			//	Console.Write(i + ",");
			//}
			//Console.WriteLine();
			if (isPlain)
				Tool.intArrEor(BinTxtOr, viarr);
			Tool.Trans(BinTxtOr, ip.getIP());

			//foreach(int i in BinTxtOr)
   //         {
			//	Console.Write(i + " ");
   //         }
			//Console.WriteLine();

			Array.Copy(BinTxtOr, LPre, 32);
			Array.Copy(BinTxtOr, 32, RPre, 0, 32);

			PDES(b, k);

			Array.Copy(LPre, DEStxt, 32);
			Array.Copy(RPre, 0, DEStxt, 32, 32);

			//Console.WriteLine("逆置换前：");
			//foreach(int i in DEStxt)
   //         {
			//	Console.Write(i + ",");
   //         }
			//Console.WriteLine();
			Tool.Trans(DEStxt, ip.getIP_1());
			if (!isPlain)
				Tool.intArrEor(DEStxt, viarr);
		}



		private void BstrDefault(String Bstr)
		{
			//检查文本是否有64位,若无则补全
			int len = Bstr.Length;
			bool high = true;//在高位，则置为空格符
			if (len < 64)
			{
				for (int i = len; i < 64; i++)
				{
					//if (i % 8 == 2)
					//{
					//	BinTxtOr[i] = 0;
					//}
					//else
						BinTxtOr[i] = 0;
				}
			}
		}

		private void Eexpand()
		{//E扩展
			int i, Loc;
			for (i = 0; i < 48; i++)
			{
				Loc = ETable[i] - 1;
				EData[i] = RPre[Loc];
			}

			//System.out.println(Arrays.toString(EData));
			//Console.WriteLine(string.Join("", EData));
		}

		private void KeyExls(int time, KEY k)
		{//扩展并与秘钥异或
			int[] Kn = k.getKn(time);
			Eexpand();
			Tool.intArrEor(EData, Kn);
			//Console.WriteLine(string.Join("",EData));
			//Console.WriteLine("得到秘钥"+string.Join("", Kn));
			//System.out.println(Arrays.toString(EData));
		}

		private void SboxChk(Box b)
		{//S盒子映射
			int[] Arr6 = { 0, 0, 0, 0, 0, 0 },
				SCArr = { 0, 0, 0, 0, 0, 0, 0, 0 },
				Arr4 = { 0, 0, 0, 0 };
			int i, j;
			for (i = 0; i < 8; i++)
			{
				for (j = 0; j < 6; j++)
				{
					Arr6[j] = EData[i * 6 + j];
				}

				SCArr[i] = b.Scheck(Arr6, i);
				Tool.inttoBinArr(SCArr[i], Arr4);
				for (j = 0; j < 4; j++)
				{
					RNext[i * 4 + j] = Arr4[j];
				}
			}
			//System.out.println(Arrays.toString(RNext));
		}

		private void PEor(Box b)
		{//P盒子置换
			Tool.Trans(RNext, b.getPbox());
			//System.out.println(Arrays.toString(RNext));
			Tool.intArrEor(RNext, LPre);
			//System.out.println(Arrays.toString(RNext));
		}


		private void PDES(Box b, KEY k)
		{//16次迭代
			int[] L = LPre, R = RPre;

			for (int i = 0; i < 16; i++)
			{
				Array.Copy(RPre, LNext, 32);
				//Console.WriteLine("第" + (i + 1) + "次扩展\n");
				//Eexpand();
				//Console.WriteLine("\n第" + (i + 1) + "次秘钥加工\n");
				KeyExls(i, k);
				SboxChk(b);
				PEor(b);
				//为下一轮迭代做准备
				if (i < 15)
				{
					Array.Copy(LNext, LPre, 32);
					Array.Copy(RNext, RPre, 32);
				}

				else
				{
					Array.Copy(LNext, RPre, 32);
					Array.Copy(RNext, LPre, 32);
				}
                //Console.WriteLine("\n第" + (i + 1) + "次迭代\n");
                //Console.WriteLine("左：" + string.Join("", LPre));
                //Console.WriteLine("右：" + string.Join("", RPre));
            }
			//System.out.println("右半部分：" + Arrays.toString(RPre));
			//System.out.println("左半部分：" + Arrays.toString(LPre));
		}

		public String getDESString()
		{//获取加密、解密后的二进制字符串
		 //foreach (int i in DEStxt)
		 //	Console.Write(i);
		 //Console.WriteLine();
			//int len = Tool.BIntToStr(DEStxt).Length;
			//Console.WriteLine("解密部分字符串长度=" + len);
			//Console.WriteLine(Tool.BIntToStr(DEStxt));
			return Tool.BIntToStr(DEStxt);
		}
	}
}
