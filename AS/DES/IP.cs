using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DES
{
    class IP
    {
		private int[] PosIPTble = {
				58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7
					};//正向IP置换表
		private int[] InvIPTble;//反向IP置换表
		public int[] TempTable;//用于传递IP表，防止IP表被修改

		public IP()
		{//构造两个表
			
			InvIPTble = new int[64];
			TempTable = new int[64];

			int i, row, col;
			//int[] PosTemp = { 58, 60, 62, 64, 57, 59, 61, 63 };//IP置换表中每行第一个元素
			int[] InvTemp = { 40, 8, 48, 16, 56, 24, 64, 32 };//IP-1置换表中第一行的8个元素
			for (i = 0; i < 8; i++)
			{
				//PosIPTble[i] = PosTemp[0] - i * 8;
				InvIPTble[i] = InvTemp[i];

			}
			//System.out.println("");
			do
			{
				row = i / 8;
				col = i % 8;
				//PosIPTble[i] = PosTemp[row] - col * 8;
				InvIPTble[i] = InvIPTble[i - 8] - 1;
				i++;

			} while (i < 64);

		}

		public int[] getIP()
		{
			//返回IP表
			PosIPTble.CopyTo(TempTable, 0);
			//System.out.println(Arrays.toString(PosIPTble));
			return TempTable;
		}

		public int[] getIP_1()
		{
			//返回IP-1表
			InvIPTble.CopyTo(TempTable, 0);
			return TempTable;
		}
		
	}
}
