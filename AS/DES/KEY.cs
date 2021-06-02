using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DES
{
    class KEY
    {
		private int[] Key;//秘钥二进制
		private int[,] Kn;//子密钥Kn
		private int[] Cn;
		private int[] Dn;
		private int[] CDTemp;//存放Cn与Dn合并时的临时数组
		private int[] MovTable = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };//左移步数参照表
		private int[] KnTemp;//子密钥模板
		bool isPlain;

		private int[] PC2Tble ={
			14,17,11,24,1,5,
			3,28,15,6,21,10,
			23,19,12,4,26,8,
			16,7,27,20,13,2,
			41,52,31,37,47,55,
			30,40,51,45,33,48,
			44,49,39,56,34,53,
			46,42,50,36,29,32

	};

		public KEY(String K, bool i)
		{
			//K为输入的字符型秘钥
			Kn = new int[16,48];
			Cn = new int[28];
			Dn = new int[28];
			CDTemp = new int[56];
			KnTemp = new int[48];
			isPlain = i;

			string KBstr = Tool.StrToBin(K, true);

			if (!isPlain)
			{
				resMovTble();
			}
			Key = Tool.BStrToInt(KBstr, 64);
			//Console.WriteLine(string.Join("",Key));
			PC1();
			KnLop();
		}

		private void resMovTble()
		{//解密时重置移动表
		 //MovTable[0] = 0;
		}

		private void PC1()
		{
			//PC1置换
			int CLoc, DLoc;
			int[] PCC = {//C0转置表
				57,49,41,33,25,17,9,
				1,58,50,42,34,26,18,
				10,2,59,51,43,35,27,
				19,11,3,60,52,44,36
		};

			int[] PCD = {//D0转置表
				63,55,47,39,31,23,15,
				7,62,54,46,38,30,22,
				14,6,61,53,45,37,29,
				21,13,5,28,20,12,4
		};

			for (int i = 0; i < 28; i++)
			{//根据转置表进行转置
				CLoc = PCC[i] - 1;
				DLoc = PCD[i] - 1;

				Cn[i] = Key[CLoc];
				Dn[i] = Key[DLoc];
			}
			//Console.WriteLine(string.Join("", Cn));
			//Console.WriteLine(string.Join("", Dn));
		}

		private void CDLMove(int step)
		{//Cn,Dn循环左移
			int[] CTmp = new int[step], DTmp = new int[step];
			int i;
			for (i = 0; i < step; i++)
			{//由于从数组开头开始进行左移，先备份
				CTmp[i] = Cn[i];
				DTmp[i] = Dn[i];
			}

			for (i = 0; i < 28 - step; i++)
			{//左移开始
				Cn[i] = Cn[i + step];
				Dn[i] = Dn[i + step];
			}

			for (int j = 0; j < step; j++)
			{//将备份赋给末尾
				Cn[j + i] = CTmp[j];
				Dn[j + i] = DTmp[j];
			}

		}

		private void CDRMove(int step)
		{//Cn,Dn循环右移
			int[] CTmp = new int[step], DTmp = new int[step];
			int i, j = 0;
			for (i = 28 - step; i < 28; i++)
			{
				CTmp[j] = Cn[i];
				DTmp[j] = Dn[i];
				j++;
			}

			for (i = 27; i > step - 1; i--)
			{
				Cn[i] = Cn[i - step];
				Dn[i] = Dn[i - step];
			}

			for (i = 0; i < step; i++)
			{
				Cn[i] = CTmp[i];
				Dn[i] = DTmp[i];
			}
		}

		private void makeKn(int Knum)
		{//计算当前Cn、Dn可合并得出的秘钥


			Cn.CopyTo(CDTemp, 0);
			Array.Copy(Dn, 0, CDTemp, 28, 28);

			int Loc;

			//Console.WriteLine("合成的秘钥：");
			for (int i = 0; i < 48; i++)
			{
				Loc = PC2Tble[i] - 1;
				Kn[Knum, i] = CDTemp[Loc];
				//Console.Write(Kn[Knum, i]);
			}
			//Console.WriteLine("\n");
		}

		private void KnLop()
		{//16次秘钥迭代

			for (int i = 0; i < 16; i++)
			{
				/*if(isPlain){
					CDLMove(MovTable[i]);
				}
				else{
					CDRMove(MovTable[i]);
				}*/
				CDLMove(MovTable[i]);
                //Console.WriteLine("\n第" + (i + 1) + "次循环移动\n");
                //Console.WriteLine(string.Join("", Cn));
                //Console.WriteLine(string.Join("", Dn));
                makeKn(i);
			}
		}

		public int[] getKn(int i)
		{
			int index;
			if (isPlain)
			{
				index = i;
			}

			else
			{
				index = 15 - i;
			}
			for(int j = 0; j < 48;j++)
            {
				KnTemp[j] = Kn[index, j];
            }
			return KnTemp;
		}
	}
}
