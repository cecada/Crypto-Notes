using System;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace CryptoNotes.Classes
{
    static class Compress
    {
        private static void CopyTo(int size, Stream src, Stream dest)
        {
            byte[] bytes = new byte[size];

            int cnt;

            while ((cnt = src.Read(bytes, 0, bytes.Length)) != 0)
            {
                dest.Write(bytes, 0, cnt);
            }
        }

        public static string Zip(string str)
        {
            try
            {
                var bytes = Encoding.UTF8.GetBytes(str);

                using var msi = new MemoryStream(bytes);
                using var mso = new MemoryStream();
                using (var gs = new GZipStream(mso, CompressionMode.Compress))
                {
                    CopyTo(bytes.Length, msi, gs);
                }

                return Convert.ToBase64String(mso.ToArray());
            }
            catch (Exception e)
            {
                Console.WriteLine(e.GetType());
                return null;
            }
        }

        public static string Unzip(string str)
        {
            try
            {
                byte[] bytes = Convert.FromBase64String(str);
                using var msi = new MemoryStream(bytes);
                using var mso = new MemoryStream();
                using (var gs = new GZipStream(msi, CompressionMode.Decompress))
                {
                    CopyTo(bytes.Length, gs, mso);
                }

                return Encoding.UTF8.GetString(mso.ToArray());
            }catch(Exception e)
            {
                Console.WriteLine(e.GetType());
                return null;
            }
        }
    }
}