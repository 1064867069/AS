using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace RSA
{
    class RSA_KeyMake
    {
        private short p, q;
        private int n, L, e, d;

        public RSA_KeyMake(short p0, short q0)
        {
            if((p = (short)RSAMath.FindPrime(p0, false)) < 17)
                p = 17;
            if((q = (short)RSAMath.FindPrime(q0, false)) < 19)
                q = 19;
            if (p == q)
                p = (short)RSAMath.FindPrime(p + q, false);
            //Console.WriteLine("p = " + p);
            //Console.WriteLine("q = " + q);
            n = p * q;
            L = (p - 1) * (q - 1);
            CalE();
            CalD();

            if (n < 128)
                RSA_Default();
        }

        void RSA_Default()//如若生成出错，则置为默认值
        {
            p = 47;
            q = 71;
            n = 3337;
            e = 79;
            d = 1019;
        }

        void CalE()//寻找e的值
        {
            if (L < 3) return;
            int DV = 0; ;
            Thread.Sleep(15);
            Random r = new Random();
            e = r.Next() % (L - 2) + 2;

            do
            {
                if (e - DV > 1 && RSAMath.IscoPrime(e - DV, L))
                {
                    e -= DV;
                    break;
                }

                if (e + DV < L && RSAMath.IscoPrime(e + DV, L))
                {
                    e += DV;
                    break;
                }
                DV++;
            } while (true);
        }

        void CalD()//寻找d的值
        {
            long de;

            Random r = new Random();
            int d0, rd = r.Next() % (n);
            for (d0 = rd; d0 < int.MaxValue; d0++)
            {
                de = d0 * e;
                if (RSAMath.IsMod(de, 1, L))
                {
                    d = d0;
                    break;
                }
            }
        }

        public Tuple<int, int> GetPublicKey()//获取公钥
        {
            Tuple<int, int> pubkey = new Tuple<int, int>(n, e);
            return pubkey;
        }

        public Tuple<int, int> GetPrivateKey()//获取私钥
        {
            var prvkey = new Tuple<int, int>(n, d);
            return prvkey;
        }
    }
}
