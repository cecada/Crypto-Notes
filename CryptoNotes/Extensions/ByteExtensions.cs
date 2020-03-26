using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CustomExtensions
{
    public static class ByteExtensions
    {
        public static string ByteArrayToString(this byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
        public static byte[] ReadFully(this Stream stream)
        {
            if (!stream.CanRead) throw new ArgumentException("This is not a readable stream.");
            var buffer = new byte[32768];
            using (var ms = new MemoryStream())
            {
                while (true)
                {
                    var read = stream.Read(buffer, 0, buffer.Length);
                    if (read <= 0)
                        return ms.ToArray();
                    ms.Write(buffer, 0, read);
                }
            }
        }
    }
}
