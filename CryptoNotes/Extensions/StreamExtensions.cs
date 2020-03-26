using System.IO;
using System.Text;

namespace CustomExtensions
{
    public static class StreamExtensions
    {
        public static string Stringify(this Stream theStream, Encoding encoding = null)
        {
            encoding = encoding ?? Encoding.UTF8;
            using (var reader = new StreamReader(theStream, encoding))
            {
                return reader.ReadToEnd();
            }
        }
    }
}
