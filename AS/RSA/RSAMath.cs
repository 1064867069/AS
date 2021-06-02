using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace RSA
{
    struct Baseint //进制结构体，用于存储bs进制数并进行操作
    {
        public int[] num;//每一位
        public int bs;//进制

        public Baseint(int len, int b = 1024)
        {
            num = new int[len];
            bs = b;
            for (int i = 0; i < len; i++)
                num[i] = 0;
        }

        public Baseint(string binnum, int b = 1024)//为方便使用超大数，用二进制string表示数字
        {
            char[] binarr = binnum.ToCharArray();
            int plen = Convert.ToString(b, 2).Length - 1, i, j = 0, tempint, len;
            Stack<int> numstore = new Stack<int>();//存储数组
            Stack<char> tempsk = new Stack<char>();
            StringBuilder tempsb = new StringBuilder();

            for (i = binnum.Length - 1; i >= 0; i--)
            {
                tempsk.Push(binarr[i]);
                j++;
                if (j == plen)
                {
                    while (tempsk.Count > 0)
                    {
                        tempsb.Append(tempsk.Pop());
                    }
                    tempint = Convert.ToInt32(tempsb.ToString(), 2);
                    //Console.WriteLine("插入" + tempint);
                    if (tempint < b)
                    {
                        numstore.Push(tempint);
                    }
                    else
                    {
                        num = new int[0];
                        bs = 0;
                        return;
                    }
                    j = 0;
                    tempsb.Clear();
                }
            }

            if (j > 0)
            {
                while (tempsk.Count > 0)
                {
                    tempsb.Append(tempsk.Pop());
                }
                numstore.Push(Convert.ToInt32(tempsb.ToString(), 2));
            }
            len = numstore.Count;
            num = new int[len];
            bs = b;

            for (i = 0; i < len; i++)
            {
                num[i] = numstore.Pop();
                //Console.WriteLine(num[i]);
            }
        }
        public string pow(int p)//计算表示的值的n次方，返回它的二进制字符串
        {
            //Stopwatch stpw = new Stopwatch();
            //stpw.Start();
            if (p == 0) return "1";
            //else if (p == 1) return ToBinString();

            char[] parr = Convert.ToString(p, 2).ToCharArray();
            int plen = parr.Length, nlen = num.Length, len = nlen * p, i, j, k, blen = Convert.ToString(bs, 2).Length - 1,
                curtpend = len - 1, currsstart = len - nlen, curtmp, curres, carry, carindx = curtpend;
            int[] result = new int[len], temp = new int[len];//计算结果于计算中结果模板
            StringBuilder sb = new StringBuilder();
            num.CopyTo(result, currsstart);

            for (i = 1; i < p; i++)
            {
                curtpend = len - 1;
                for (curtmp = curtpend; curtmp >= 0; curtmp--)
                    temp[curtmp] = 0;
                for (k = nlen - 1; k >= 0; k--)
                {
                    if (num[k] != 0)
                    {
                        for (curtmp = curtpend, curres = len - 1; curres >= currsstart; curtmp--, curres--)
                        {
                            temp[curtmp] += num[k] * result[curres];
                            carindx = curtmp;
                            while ((temp[carindx]) >= bs)//若不出意外，当carindx=0时不可能出现该情况
                            {
                                temp[carindx - 1] += temp[carindx] / bs;
                                temp[carindx--] %= bs;
                            }
                        }
                    }
                    curtpend--;
                }
                currsstart = carindx;
                temp.CopyTo(result, 0);
            }
            sb.Append(Convert.ToString(result[currsstart], 2));
            for (i = currsstart + 1; i < len; i++)
            {
                sb.Append(Convert.ToString(result[i], 2).PadLeft(blen, '0'));
            }
            //stpw.Stop();
            //Console.WriteLine("计算立方用了" + stpw.ElapsedMilliseconds +"毫秒");
            return sb.ToString();
        }
    }
    class RSAMath
    {
        public static bool IsPrime(int num)//判断是否质数
        {
            if (num < 2) return false;
            int i;
            for (i = 2; i < num; i++)
            {
                if (num % i == 0)
                {
                    //Console.WriteLine("{0:D}可以整除{1:D}", i, num);
                    return false;//有其他数可以整除num，不为质数
                }
            }
            return true;//没有其他数可整除，是质数
        }

        public static bool IscoPrime(long a, long b)//检查a,b是否互质
        {
            if (a == 1 || b == 1)//若其中一个为1，必定互质
                return true;
            else if (a == b || a < 1 || b < 1)//a,b相等不为1或者有一个小于1，则必不互质
                return false;

            long min;
            min = a < b ? a : b;

            for (int i = 2; i < min + 1; i++)
            {
                if (a % i == 0 && b % i == 0)
                    return false;//有不为1的公约数
            }
            return true;//只有公约数1
        }

        public static int FindPrime(int num, bool isint)//寻找与num差值最小的质数
        {
            if (num < 3) return 2;

            int low = num, high = num, maxV;
            if (isint)
                maxV = int.MaxValue;
            else
                maxV = short.MaxValue;

            while (low > 2 || high < maxV)
            {
                if (low % 2 == 0)
                {
                    low--;
                    high++;
                    continue;
                }
                if (RSAMath.IsPrime(low)) return low;
                if (RSAMath.IsPrime(high)) return high;
                low--;
                high++;
            }
            return 2;
        }

        public static bool IsMod(long a, long b, long modn)//a≡b(modn)
        {
            if (a < 0 || b < 0 || modn < 0)
                return false;

            long DV = a - b;
            if (DV < 0)
                DV = 0 - DV;
            if (DV % modn == 0)
                return true;
            return false;
        }

        public static string Bindiv(string abin, string bbin)//计算a%b结果二进制数
        {
            Stopwatch stopw = new Stopwatch();
            if (bbin.IndexOf('1') == -1)//除数为0
                return null;
            int alen = abin.Length, blen = bbin.Length, i, j, k, highest = 0;
            if (alen < blen)
                return abin;

            int curstart = 0, cur, borwindx;//被除数减法首位索引，当前计算位，借位索引
            char[] atemp = abin.ToArray(), btemp = bbin.ToArray(), restemp;
            bool isOne = true, borrow = false;
            string result;

            stopw.Start();
            while (true)
            {
                //Console.WriteLine("当" + (curstart + 1) + "次计算时");
                if (highest < curstart)
                    isOne = true;
                else
                {
                    for (i = 0; i < blen; i++)
                    {
                        cur = i + curstart;
                        if (atemp[cur] > btemp[i])
                        {
                            isOne = true;
                            break;
                        }
                        else if (atemp[cur] < btemp[i])
                        {
                            isOne = false;
                            break;
                        }
                        //Console.WriteLine("cur = " + cur);
                        //Console.WriteLine("atemp[cur] = " + atemp[cur]);
                    }
                    if (i == blen)
                        isOne = true;
                }

                if (isOne)
                {
                    //Console.WriteLine("除数该位为1");
                    for (i = blen - 1; i >= 0; i--)
                    {
                        cur = i + curstart;
                        if (atemp[cur] == btemp[i])
                        {
                            atemp[cur] = '0';
                            if (cur == highest)
                            {
                                while (highest < alen && atemp[highest] != '1')
                                    highest++;
                            }
                        }
                        else if (atemp[cur] < btemp[i])
                        {
                            borwindx = cur;
                            borrow = true;
                            do
                            {
                                atemp[borwindx]++;
                                borwindx--;
                                if (atemp[borwindx] == '1')
                                {
                                    atemp[borwindx]--;
                                    borrow = false;
                                }

                                if (borwindx == highest)
                                {
                                    while (atemp[highest] != '1')
                                        highest++;
                                }
                                //Console.WriteLine("借位！");
                            } while (borrow);
                        }
                    }
                }
                curstart++;
                if (curstart + blen > alen)
                    break;
            }

            for (i = 0; i < alen; i++)
            {
                if (atemp[i] == '1')
                    break;
            }

            if (i == alen)
                return "0";
            k = alen - i;
            restemp = new char[k];
            for (j = alen - 1; j >= i; j--)
            {
                k--;
                restemp[k] = atemp[j];
            }
            stopw.Stop();
            //Console.WriteLine("相除用了" + stopw.ElapsedMilliseconds + "毫秒！\n");
            result = string.Join("", restemp);
            return result;
        }
        public static int En_FindC(int m, int e, int n)//以二进制字符串计算c≡ m^e mod n中的c
        {
            //Console.WriteLine("m = " + m + "\ne = " + e);
            if (m < 0 || e < 0 || n < 0)
                return -1;
            int c;
            string nBin = Convert.ToString(n, 2);
            Baseint bsi = new Baseint(Convert.ToString(m, 2), 4096); ;
            c = Convert.ToInt32(Bindiv(bsi.pow(e), nBin), 2);
            return c;
        }

        public static int De_FindD(int c, int d, int n)
        {
            //Console.WriteLine("c = " + c + "\nd = " + d);
            if (c < 0 || d < 0 || n < 0)
                return -1;
            string nBin = Convert.ToString(n, 2);//n的二进制形式，余数二进制形式
            //Console.WriteLine(Bindiv(Binpow(c, d),nBin));
            Baseint bsi = new Baseint(Convert.ToString(c, 2), 4096);
            int m = Convert.ToInt32(Bindiv(bsi.pow(d), nBin), 2);
            return m;
        }

    }
}
