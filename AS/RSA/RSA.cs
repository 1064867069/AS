using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RSA
{
    class RSA
    {
        RSA_KeyMake rsa_key;
        Tuple<int, int> pubkey;//公钥
        Tuple<int, int> prvkey;//私钥

        public RSA(short p, short q)
        {
            rsa_key = new RSA_KeyMake(p, q);
            pubkey = rsa_key.GetPublicKey();
            prvkey = rsa_key.GetPrivateKey();
        }

        public RSA(int n, int de)
        {
            rsa_key = null;
            pubkey = new Tuple<int, int>(n, de);
            prvkey = new Tuple<int, int>(n, de);
        }

        public string RSAEn(string ptxt)//RSA加密，返回一个十六进制的加密字符串
        {
            int n = pubkey.Item1, e = pubkey.Item2, nlen, pnum, ennum;
            string nHex = Convert.ToString(n, 16);
            nlen = nHex.Length;
            StringBuilder result = new StringBuilder();

            Stack<int> pstack = RSATool.Split(ptxt, n);
            while (pstack.Count != 0)
            {
                pnum = pstack.Pop();
                ennum = RSAMath.En_FindC(pnum, e, n);
                result.Append(Convert.ToString(ennum, 16).PadLeft(nlen, '0'));
                //Console.Write(Convert.ToString(ennum, 16).PadLeft(nlen, '0'));
            }
            Console.WriteLine("");
            return result.ToString();
        }

        public string RSADe(string ctxt)//RSA解密，返回原字符串
        {
            int n = prvkey.Item1, d = prvkey.Item2, nlen, clen, cnum, denum, blen, bsup, i, po, cint;
            string nHex = Convert.ToString(n, 16), bintemp;
            nlen = nHex.Length;
            clen = ctxt.Length;
            char[] recarr;

            Stack<int> cstk = RSATool.HexStr_Int(ctxt, n);
            StringBuilder result = new StringBuilder(), binres = new StringBuilder();

            while (cstk.Count != 0)
            {
                cnum = cstk.Pop();
                denum = RSAMath.De_FindD(cnum, d, n);
                //Console.WriteLine("解密后：" + denum);
                binres.Append(Convert.ToString(denum, 2));
            }

            blen = binres.Length;
            bsup = 8 - blen % 8;
            if (bsup < 8)
            {
                for (i = 0; i < bsup; i++)
                {
                    binres.Insert(0, '0');
                }
            }
            else
            {
                bsup = 0;
            }

            recarr = binres.ToString().ToCharArray();
            //Console.WriteLine(binres.ToString());
            //Console.WriteLine("现在字符串长度"+binres.Length);
            po = 8;
            cint = 0;
            for (i = 0; i < binres.Length; i++)
            {
                po--;
                cint += (int)Math.Pow(2, po) * (recarr[i] - '0');
                if (po < 0)
                {
                    po = 7;
                    result.Append((char)cint);
                    cint = 0;
                }
            }
            result.Append((char)cint);
            //Console.WriteLine("");
            return result.ToString();
        }
    }
}
