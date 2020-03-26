using System.Globalization;
using System.IO;
using System.Resources;
using CryptoNotes.Resources;

namespace CryptoNotes.Classes
{
    static class FileHelper
    {
        static public readonly string AppPath = System.Environment.GetFolderPath(System.Environment.SpecialFolder.ApplicationData);
        static public readonly string SaltFilePath = Path.Combine(AppPath, StringResource.SaltFileName);
        static public readonly string RandomSeedPath = Path.Combine(AppPath, StringResource.RandomSeedFileName);
        static public readonly string RSAKeyPath = Path.Combine(AppPath, StringResource.RSAKeyFileName);
        static public readonly string ErrorPath = Path.Combine(AppPath, StringResource.ErrorFileName);

        public static void WriteFile(string data, string path, bool append = false)
        {
            using var writer = new StreamWriter(path, append);
            writer.WriteLine(data);
        }

        public static string ReadFile(string path)
        {
            string content;
            using (var reader = new StreamReader(path))
            {
                content = reader.ReadToEnd();
            }
            return content;
        }
        public static void DeleteFile(string path)
        {
            File.Delete(path);
        }
        public static bool FileExist(string path)
        {
            if (File.Exists(path))
                return true;
            return false;
        }
    }
}
