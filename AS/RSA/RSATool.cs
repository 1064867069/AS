using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RSA
{
    class RSATool
    {
        public static string StrtoBin(string str)//将str转为二进制字符串
        {
            //使用的不只有ASCII字符时不能用此算法
            char[] carr = str.ToArray();
            StringBuilder result = new StringBuilder(carr.Length * 8);
            foreach (char c in carr)
            {
                result.Append(Convert.ToString(c, 2).PadLeft(8, '0'));
            }
            return result.ToString();
        }



        public static Stack<int> Split(string str, int n)//根据给定字符串进行分割并得出相应的值
        {
            //从后往前分割，将分割得出的值压入栈中
            string bin = StrtoBin(str);
            char[] binarr = bin.ToCharArray();
            //Console.WriteLine(bin);
            //Console.WriteLine("原字符串长度" + bin.Length);
            int len = binarr.Length, value = 0, circle = 0,
                mlen = Convert.ToString(n, 2).Length - 1, i;
            //Console.WriteLine("mlen = " + mlen);
            Stack<int> stk = new Stack<int>();

            for (i = len - 1; i >= 0; i--)
            {
                value += (binarr[i] - '0') * (int)Math.Pow(2, circle);

                circle++;
                if (circle == mlen)
                {
                    while (binarr[i] == '0')
                        i++;
                    stk.Push(value);
                    //Console.WriteLine("明文：" + value);
                    circle = 0;
                    value = 0;
                }
            }
            if (circle > 0)
            {
                stk.Push(value);
                //Console.WriteLine("明文：" + value);
            }

            return stk;
        }

        public static Stack<int> HexStr_Int(string hstr, int n)//将十六进制加密字符串转换为十进制数字
        {
            string nHex = Convert.ToString(n, 16);
            int nlen = nHex.Length, hlen = hstr.Length, cur, i;
            char[] hexarr = hstr.ToCharArray();
            StringBuilder temp = new StringBuilder();
            cur = hlen;
            Stack<int> results = new Stack<int>();
            Stack<char> tempstk = new Stack<char>();

            while (cur > 0)
            {
                for (i = 0; i < nlen; i++)
                {
                    cur--;
                    tempstk.Push(hexarr[cur]);
                    //temp.Insert(0, hexarr[cur]);
                }
                while (tempstk.Count > 0)
                    temp.Append(tempstk.Pop());
                results.Push(Convert.ToInt32(temp.ToString(), 16));
                //Console.WriteLine(Convert.ToInt32(temp.ToString(), 16));
                temp.Clear();
            }
            return results;
        }
    }


}
