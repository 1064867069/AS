using System;
using System.Collections.Generic;
using System.Text;


namespace AS
{
    class Ticket_Make
    {
        private static string enkey = "20181002238";
        public static string MakeTicket(Tuple<int ,int>key, string uname,string uip,string idtgs)//票据生成
        {
            string pt;
            StringBuilder sb = new StringBuilder();

            sb.Append(key.Item1);
            sb.Append(",");
            sb.Append(key.Item2);
            sb.Append("%");
            sb.Append(uname);
            sb.Append("%");
            sb.Append(uip);
            sb.Append("%");
            sb.Append(idtgs);
            sb.Append("%");
            sb.Append(DateTime.Now.ToString());
            sb.Append("%");
            sb.Append(Program.Lifetime);

            pt = sb.ToString();
            //string ctxt = DES.Tool.txtDES(pt, true, enkey),detxt;
            //Console.WriteLine("票据内容：");
            //Console.WriteLine(pt);
            //Console.WriteLine("AS生成的票据：");
            //Console.WriteLine(DES.Tool.txtDES(pt, true, enkey));
            //Console.WriteLine("票据长度" + ctxt.Length);
            //Console.WriteLine("AS自己解密票据结果\n\n\n\n\n");
            //detxt = DES.Tool.txtDES(ctxt, false, enkey);
            //Console.WriteLine("自解密票据完成！\n\n\n\n\n");
            //Console.WriteLine(detxt);
            return DES.Tool.txtDES(pt, true, enkey);
            
        }
    }
}
