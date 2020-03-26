using System;
using System.IO;
using System.Text;

namespace CustomExtensions
{
    //Extension methods must be defined in a static class
    public static class StringExtension
    {
        // This is the extension method.
        // The first parameter takes the "this" modifier
        // and specifies the type for which the method is defined.
        public static string ToBase64(this byte[] strbytes)
        {
            return Convert.ToBase64String(strbytes);
        }
        public static byte[] FromBase64(this string str)
        {
            return Convert.FromBase64String(str);
        }
        public static byte[] ToByteArray(this string str)
        {
            return Encoding.UTF8.GetBytes(str);
        }
        public static string FromByteArray(this byte[] strbytes)
        {
            return Encoding.UTF8.GetString(strbytes);
        }
        public static Stream Streamify(this string theString, Encoding encoding = null)
        {
            encoding = encoding ?? Encoding.UTF8;
            var stream = new MemoryStream(theString.ToByteArray());
            return stream;
        }
        public static Stream Base64Streamify(this string theString, Encoding encoding = null)
        {
            encoding = encoding ?? Encoding.UTF8;
            var stream = new MemoryStream(theString.FromBase64());
            return stream;
        }
    }

}
