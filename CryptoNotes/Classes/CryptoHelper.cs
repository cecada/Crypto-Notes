using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using CryptoNotes.Enum;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Xamarin.Essentials;
using CustomExtensions;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Digests;
using CryptoNotes.Models;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using Xamarin.Forms;
using System.Collections;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoNotes.Classes
{
    static public class CryptoHelper
    {
        static public AsymmetricCipherKeyPair GetRSAKeyPair(string password,int iterations)
        {
            AppData appData = App.AppDatabase.GetDataAsync(1).Result;
            if (appData == null) return null;

            var rsaKey = DecodeKey(appData.RSAPrivateKey, password, iterations);
            return rsaKey;
        }
        static public bool LoadRSAKey(string password, int iterations)
        {
            try
            {
                AppData appData = App.AppDatabase.GetDataAsync(1).Result;
                if (appData == null) return false;

                var rsaKey = DecodeKey(appData.RSAPrivateKey, password, iterations);
                var privateKey = StringBuilder(rsaKey, KeyType.PrivateKey);
                SecureStorage.SetAsync(KeyType.PrivateKey.ToString(), privateKey).Wait();

                return true;
            }
            catch (Exception e)
            {
                FileHelper.WriteFile(ErrorHelper.FormatError(e), FileHelper.ErrorPath, true);
                return false;
            }
        }
        public static bool DoesRSAKeyExists(bool fromFile = false)
        {
            try
            {
                if (fromFile)
                {
                    if (FileHelper.FileExist(FileHelper.RSAKeyPath))
                        return true;
                }
                else
                {
                    var appData = App.AppDatabase.GetDataAsync(1).Result;
                    if (appData == null) return false;
                    if (appData.RSAPrivateKey != null || appData.RSAPrivateKey.Length > 0)
                        return true;
                }
            }
            catch (Exception e)
            {
                FileHelper.WriteFile(ErrorHelper.FormatError(e), FileHelper.ErrorPath, true);
                return false;
            }
            return false;
        }
        public static void DeleteRSAKey()
        {
            FileHelper.DeleteFile(FileHelper.RSAKeyPath);
            AppData appData = App.AppDatabase.GetDataAsync(1).Result;
            App.AppDatabase.DeleteDataAsync(appData);
        }
        static private void UpdateStatus(string message, string toast, Label label, IDispatcher dispatcher)
        {
            dispatcher.BeginInvokeOnMainThread(() =>
            {
                label.Text = message;
            });
        }
        static public AppData GenerateRSAPrivateKey(RSAKeySize strength, string password, int iteration, Label label, IDispatcher dispatcher)
        {
            try
            {
                IDictionary attrs = new Hashtable
                {
                    { X509Name.CN, "commonname" },
                    { X509Name.O, "organization" },
                    { X509Name.OU, "organizationalUnit" },
                    { X509Name.L, "locality" },
                    { X509Name.ST, "state" },
                    { X509Name.C, "countryIso2Characters" },
                    { X509Name.EmailAddress, "emailAddress" }
                };

                UpdateStatus("1 of 16 Completed!\nCreating X509", "", label, dispatcher);
                X509Name subject = new X509Name(new ArrayList(attrs.Keys), attrs);

                UpdateStatus("2 of 16 Completed!\n1 of 3 RSA Key Pair\nInitializing", "X509 Generated", label, dispatcher);
                RsaKeyPairGenerator rsa = new RsaKeyPairGenerator();

                UpdateStatus("3 of 16 Completed!\n2 of 3 RSA Key Pair\nRandomizing", "", label, dispatcher);
                rsa.Init(new KeyGenerationParameters(GetSecureRandom(), (int)strength));

                UpdateStatus("4 of 16 Completed!\n3 of 3 RSA Key Pair\nGenerating", "Randomizing Done", label, dispatcher);
                AsymmetricCipherKeyPair asym = rsa.GenerateKeyPair();

                UpdateStatus("5 of 16 Completed!\n1 of 4 Encrypting RSA Key Pair: Initalizing", "RSA Keys Created", label, dispatcher);
                var generator = new Pkcs8Generator(asym.Private, Pkcs8Generator.PbeSha1_RC4_128);
                generator.IterationCount = iteration;

                UpdateStatus("6 of 16 Completed!\n2 of 4 Encrypting RSA Key Pair: Randomize", "", label, dispatcher);
                generator.SecureRandom = GetSecureRandom();

                UpdateStatus("7 of 16 Completed!\n3 of 4 Encrypting RSA Key Pair: Hashing", "Randomize Done", label, dispatcher);
                generator.Password = Hash512Iterate(password.ToByteArray(), iteration).ToBase64().ToCharArray();

                UpdateStatus("8 of 16 Completed!\n4 of 4 Encrypting RSA Key Pair: Finalizing", "Hashing Done", label, dispatcher);
                var pem = generator.Generate();

                string SecurePrivateKey = ConvertRSAPemToString(pem);

                UpdateStatus("9 of 16 Completed!\nStoring Encrypted RSA Key Pair", "RSA Key Pair Encrypted", label, dispatcher);
                AppData appData = new AppData
                {
                    RSAPrivateKey = SecurePrivateKey,               
                    RSAPublicKey = StringBuilder(asym, KeyType.PublicKey),
                };
                
                int id = App.AppDatabase.SaveDataAsync(appData).Result;
                if (id != 1) throw new Exception("GenerateRSAKey: RSA Save Key filed. id != 1");

                appData.ID = 1;

                UpdateStatus("10 of 16 Completed!\nLoading RSA Key Pair", "RSA Key Pair Stored", label, dispatcher);

                if (!LoadRSAKey(password, iteration)) throw new Exception("Generate KeyPair: Could not load RSA Keys");

                UpdateStatus("11 of 16 Completed!\nCreating PKCS#10 CSR", "RSA Keys Loaded", label, dispatcher);

                Asn1SignatureFactory signatureFactory = new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha512WithRsaEncryption.Id, asym.Private);
                Pkcs10CertificationRequest csr = new Pkcs10CertificationRequest(signatureFactory, subject, asym.Public, null);
                appData.CSR = StringBuilder(csr);
                
                UpdateStatus("12 of 16 Completed!\n1 of 4 AES Tasks: Creating Seed", "PKCS#10 CSR Created", label, dispatcher);
                appData.Seed = GenerateSeed(false).seed;

                UpdateStatus("13 of 16 Completed!\n2 of 4 AES Tasks: Creating Salt", "AES Seed Created", label, dispatcher);
                appData.Salt = GenerateSalt(false).salt;

                UpdateStatus("14 of 16 Completed!\n3 of 4 AES Tasks: Encrypting Iterations", "AES Salt Created", label, dispatcher);
                appData.Iterations = RSAEncrypt(iteration.ToString());

                UpdateStatus("15 of 16 Completed!\n4 of 4 AES Tasks: Encrypting Certs", "Iterations Encrypted", label, dispatcher);
                appData = AESEncrypt(appData) as AppData;
                if (appData == null) throw new Exception("AES Encryption Failed during Key Generation");

                UpdateStatus("16 of 16 Completed!\nFinishing up", "", label, dispatcher);
                App.AppDatabase.SaveDataAsync(appData).Wait();

                return appData;

            }
            catch (Exception e)
            {
                FileHelper.WriteFile(ErrorHelper.FormatError(e), FileHelper.ErrorPath, true);
                return null;
            }
        }
        public static SecureRandom GetSecureRandom()
        {
            SecureRandom random = new SecureRandom();
            int rnd = CryptoHelper.PseudoRandomNumber();
            random.SetSeed(random.GenerateSeed(rnd));
            return random;
        }
        public static AsymmetricCipherKeyPair DecodeKey(string key, string password, int iterations)
        {
            try
            {
                password = Hash512Iterate(password.ToByteArray(), iterations).ToBase64();
                TextReader textReader = new StringReader(key);
                PemReader pemReader = new PemReader(textReader, new PasswordFinder(password));
                object privateKeyObject = pemReader.ReadObject();
                RsaPrivateCrtKeyParameters rsaPrivatekey = (RsaPrivateCrtKeyParameters)privateKeyObject;
                RsaKeyParameters rsaPublicKey = new RsaKeyParameters(false, rsaPrivatekey.Modulus, rsaPrivatekey.PublicExponent);
                AsymmetricCipherKeyPair kp = new AsymmetricCipherKeyPair(rsaPublicKey, rsaPrivatekey);
                return kp;
            }
            catch (Exception e)
            {
                FileHelper.WriteFile(ErrorHelper.FormatError(e), FileHelper.ErrorPath, true);
                return null;
            }
        }
        public static AsymmetricKeyParameter TransformKey(KeyType keyname)
        {
            if (SecureStorage.GetAsync(KeyType.PrivateKey.ToString()).Result != null)
            {
                AsymmetricCipherKeyPair key;
                using (var reader = new StringReader(SecureStorage.GetAsync(KeyType.PrivateKey.ToString()).Result))
                    key = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();
                if (keyname == KeyType.PrivateKey)
                    return key.Private;
                else
                    return key.Public;
            }
            return null;
        }
        public static string StringBuilder(Pkcs10CertificationRequest csr)
        {
            StringBuilder csrStrBuilder = new StringBuilder();
            PemWriter csrPemWriter = new PemWriter(new StringWriter(csrStrBuilder));
            csrPemWriter.WriteObject(csr);
            csrPemWriter.Writer.Flush();

            return csrStrBuilder.ToString();
        }
        public static string StringBuilder(AsymmetricCipherKeyPair key, KeyType keyType)
        {
            if (key == null) throw new Exception("String Builder: key is null");
            try
            {
                TextWriter textWriter = new StringWriter();
                PemWriter pemWriter = new PemWriter(textWriter);
                if (keyType == KeyType.PrivateKey)
                    pemWriter.WriteObject(key.Private);
                else
                    pemWriter.WriteObject(key.Public);
                pemWriter.Writer.Flush();

                return textWriter.ToString();
            }
            catch (Exception e)
            {
                FileHelper.WriteFile(ErrorHelper.FormatError(e), FileHelper.ErrorPath, true);
                return null;
            }
        }
        private static void SaveRSAPrivateKeyToFile(Org.BouncyCastle.Utilities.IO.Pem.PemObject key)
        {
            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(key);
            pemWriter.Writer.Flush();

            string privateKey = textWriter.ToString();
            FileHelper.WriteFile(privateKey, FileHelper.RSAKeyPath);
        }
        private static string ConvertRSAPemToString(Org.BouncyCastle.Utilities.IO.Pem.PemObject key)
        {
            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(key);
            pemWriter.Writer.Flush();

            string privateKey = textWriter.ToString();
            return privateKey;
        }
        public static string RSAEncrypt(byte[] bytesToEncrypt)
        {
            try
            {
                var publicKey = TransformKey(KeyType.PublicKey);
                var encryptEngine = new Pkcs1Encoding(new RsaEngine());
                encryptEngine.Init(true, publicKey);

                var encrypted = encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length).ToBase64();
                return encrypted;
            }
            catch (Exception e)
            {
                FileHelper.WriteFile(ErrorHelper.FormatError(e), FileHelper.ErrorPath, true);
                return null;
            }
        }
        public static string RSAEncrypt(string clearText)
        {
            var bytesToEncrypt = clearText.ToByteArray();
            return RSAEncrypt(bytesToEncrypt);
        }
        public static string RSADecrypt(string base64Input, bool base64result = false)
        {
            try
            {
                var privateKey = TransformKey(KeyType.PrivateKey);
                var bytesToDecrypt = base64Input.FromBase64();
                var decryptEngine = new Pkcs1Encoding(new RsaEngine());
                decryptEngine.Init(false, privateKey);
                string decrypted;
                if (!base64result)
                    decrypted = decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length).FromByteArray();
                else
                    decrypted = decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length).ToBase64();

                return decrypted;

            }
            catch (Exception e)
            {
                Console.WriteLine(e.GetType());
                return null;
            }
        }
        public static string GetSignature(string message)
        {
            byte[] messageBytes = message.ToByteArray();

            RsaDigestSigner signer = new RsaDigestSigner(new Sha256Digest());
            signer.Init(true, TransformKey(KeyType.PrivateKey));
            signer.BlockUpdate(messageBytes, 0, messageBytes.Length);

            try
            {
                byte[] signature = signer.GenerateSignature();
                return signature.ToBase64();
            }
            catch (Exception e)
            {
                FileHelper.WriteFile(ErrorHelper.FormatError(e), FileHelper.ErrorPath, true);
                return null;
            }
        }
        public static bool VerifySignature(string message, string signature)
        {
            try
            {
                byte[] messageBytes = message.ToByteArray();
                byte[] signatureBytes = signature.FromBase64();

                RsaDigestSigner signer = new RsaDigestSigner(new Sha256Digest());
                signer.Init(false, TransformKey(KeyType.PublicKey));
                signer.BlockUpdate(messageBytes, 0, messageBytes.Length);

                bool isValidSignature = signer.VerifySignature(signatureBytes);

                return isValidSignature;
            }
            catch (Exception ex)
            {
                FileHelper.WriteFile(ErrorHelper.FormatError(ex), FileHelper.ErrorPath, true);
                return false;
            }
        }
        static public int GetAPPSeed(bool fromFile = true, string encryptedSeed = null)
        {
            if (encryptedSeed == null)
            {
                AppData appData = App.AppDatabase.GetDataAsync(1).Result;
                encryptedSeed = appData.Seed;
            }
            return GetSeed(false, encryptedSeed);
        }
        static public (string seed, bool success) GenerateSeed(bool saveToFile = true, int lower = 1000, int upper = 9999)
        {
            try
            {
                string seed = RSAEncrypt(PseudoRandomNumber(lower, upper).ToString());
                if (saveToFile)
                    FileHelper.WriteFile(seed, FileHelper.RandomSeedPath);
                return (seed, success: true);

            }
            catch (Exception e)
            {
                FileHelper.WriteFile(ErrorHelper.FormatError(e), FileHelper.ErrorPath, true);
                return (null, false);
            }
        }
        static public int GetSeed(bool fromFile = true, string encryptedSeed = null)
        {
            try
            {
                string encodedSeed;
                if (fromFile)
                {
                    if (!FileHelper.FileExist(FileHelper.RandomSeedPath))
                    {
                        var result = GenerateSeed();
                        encodedSeed = result.seed;
                        if (!result.success) throw new Exception("Seed file could not be created");
                    }
                    else
                        encodedSeed = FileHelper.ReadFile(FileHelper.RandomSeedPath);
                }
                else
                {
                    if (encryptedSeed == null)
                        encodedSeed = GenerateSeed(false).seed;
                    else
                        encodedSeed = encryptedSeed;
                }

                string seedString = RSADecrypt(encodedSeed);
                if (int.TryParse(seedString, out int seed))
                {
                    seed = Math.Abs(seed);
                    return seed;
                }
                return -1;
            }
            catch (Exception e)
            {
                FileHelper.WriteFile(ErrorHelper.FormatError(e), FileHelper.ErrorPath, true);
                return -1;
            }
        }
        static public (string salt, bool success) GenerateSalt(bool saveToFile = true, int size = 32)
        {
            try
            {
                string salt = RSAEncrypt(HASH512(GenerateRandomBytes(size)).ToBase64());
                if (saveToFile)
                    FileHelper.WriteFile(salt, FileHelper.SaltFilePath);
                return (salt, true);
            }
            catch (Exception e)
            {
                FileHelper.WriteFile(ErrorHelper.FormatError(e), FileHelper.ErrorPath, true);
                return (null, false);
            }
        }
        static public string GetAPPSalt(bool fromFile = true, string encryptedSalt = null)
        {
            if (encryptedSalt == null)
            {
                AppData appData = App.AppDatabase.GetDataAsync(1).Result;
                encryptedSalt = appData.Salt;
            }
            return GetSalt(false, encryptedSalt);
        }
        static public string GetSalt(bool fromFile = true, string encryptedSalt = null)
        {
            try
            {
                string encodedSalt;
                if (fromFile)
                    if (!FileHelper.FileExist(FileHelper.SaltFilePath))
                    {
                        var result = GenerateSalt();
                        encodedSalt = result.salt;
                        if (!result.success) throw new Exception("Salt file could not be created");
                    }
                    else
                    {
                        encodedSalt = FileHelper.ReadFile(FileHelper.SaltFilePath);
                    }
                else
                {
                    if (encryptedSalt == null)
                        encodedSalt = GenerateSalt(false).salt;
                    else
                        encodedSalt = encryptedSalt;
                }
                return RSADecrypt(encodedSalt);
            }
            catch (Exception e)
            {
                FileHelper.WriteFile(ErrorHelper.FormatError(e), FileHelper.ErrorPath, true);
                return null;
            }
        }
        static public int GetIterations()
        {
            string result = RSADecrypt(SecureStorage.GetAsync("PIN").Result);
            if (int.TryParse(result, out int number))
                number = int.Parse(result);
            return number;
        }

        static public string AESEncryptString(string salt, int iterations, int seed, string plainText, string password = null, bool embedPassword = true)
        {
            byte[] encryptedBytes = null;
            byte[] bytesToBeEncrypted = plainText.ToByteArray();
            byte[] saltBytes = salt.ToByteArray();
            byte[] passwordBytes = password.FromBase64();
            string encryptedAESPassword;
            if (embedPassword)
                encryptedAESPassword = CryptoHelper.RSAEncrypt(passwordBytes);
            else
                encryptedAESPassword = "XXX";

            string signature = CryptoHelper.GetSignature(plainText);

            passwordBytes = Hash512Iterate(passwordBytes, iterations);
            saltBytes = Hash512Iterate(saltBytes, iterations);

            using (MemoryStream ms = new MemoryStream())
            {
                using RijndaelManaged AES = new RijndaelManaged
                {
                    KeySize = 256,
                    BlockSize = 128,
                    Mode = CipherMode.CBC,
                    Padding = PaddingMode.PKCS7
                };
                using var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, seed, HashAlgorithmName.SHA512);
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                    cs.Close();
                }
                encryptedBytes = ms.ToArray();
            }

            string encrypted = "$CryptoApp$" + Compress.Zip(encryptedBytes.ToBase64() + "#" + encryptedAESPassword + "#" + signature);

            return encrypted;
        }

        static public BaseModel AESEncrypt(BaseModel data, string password = null, bool embedPassword = true)
        {
            try
            {
                if (data.Salt == null || data.Salt.Length == 0)
                    data.Salt = GenerateSalt(false).salt;
                if (data.Seed == null || data.Seed.Length == 0)
                    data.Seed = GenerateSeed(false).seed;
                if (data.Iterations == null || data.Iterations.Length == 0)
                    if (GetIterations() > -1) data.Iterations = RSAEncrypt(GetIterations().ToString());

                string salt = GetSalt(false, data.Salt);

                int seed = GetSeed(false, data.Seed);
                int iterations = GetSeed(false, data.Iterations);

                if (salt == null)
                    throw new Exception("Salt is null");

                if (seed == -1)
                    throw new Exception("App Seed = -1");

                if (iterations == -1)
                    throw new Exception("Iteration = -1");

                if (password == null)
                    password = GetSecureRandom().GenerateSeed(32).ToBase64();

                if (password == null)
                    throw new Exception("AES Password is null");

                if (data as AppData != null )
                {
                    ((AppData)data).RSAPublicKey = AESEncryptString(salt, iterations,seed, ((AppData)data).RSAPublicKey, password);
                    ((AppData)data).CSR = AESEncryptString(salt, iterations, seed, ((AppData)data).RSAPublicKey, password);
                    return data as AppData;
                }
                else if (data as SecureData != null)
                {
                    ((SecureData)data).Data = AESEncryptString(salt, iterations, seed, ((SecureData)data).Data, password);
                    ((SecureData)data).NoteTitle = AESEncryptString(salt, iterations, seed, ((SecureData)data).NoteTitle, password);
                    return data as SecureData;
                } else
                {
                    data.Data = AESEncryptString(salt, iterations, seed, data.Data, password);
                    return data;
                }
            }
            catch (Exception e)
            {
                FileHelper.WriteFile(ErrorHelper.FormatError(e), FileHelper.ErrorPath, true);
                return null;
            }
        }
        static public string AESDecryptString(string salt, int iterations, int seed, string encryptedText,string password = null)
        {
            if (!encryptedText.Contains("$CryptoApp$")) return encryptedText;
            string[] encryptedArray = encryptedText.Split("$CryptoApp$");
            string encryptedBlob = Compress.Unzip(encryptedArray[1]);
            encryptedArray = encryptedBlob.Split("#");

            if (encryptedArray.Length < 3) return null;

            string encryptedData = encryptedArray[0];
            if (password == null)
                password = CryptoHelper.RSADecrypt(encryptedArray[1], true);
            string signature = encryptedArray[2];

            byte[] bytesToBeDecrypted = encryptedData.FromBase64();
            byte[] passwordBytes = password.FromBase64();
            byte[] saltBytes = salt.ToByteArray();

            if (password == "XXX") throw new Exception("Password not supplied");
            if (signature == null) throw new Exception("Signature is empty");
            if (password == null) throw new Exception("AES Password is null");

            passwordBytes = Hash512Iterate(passwordBytes, iterations);
            saltBytes = Hash512Iterate(saltBytes, iterations);
            string decrypted;
            using (MemoryStream ms = new MemoryStream(bytesToBeDecrypted))
            {
                using RijndaelManaged AES = new RijndaelManaged
                {
                    KeySize = 256,
                    BlockSize = 128,
                    Mode = CipherMode.CBC,
                    Padding = PaddingMode.PKCS7
                };

                using var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, seed, HashAlgorithmName.SHA512);
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                using CryptoStream cryptoStream = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Read);
                using StreamReader srDecrypt = new StreamReader(cryptoStream);
                decrypted = srDecrypt.ReadToEnd();
            }

            bool isgood = CryptoHelper.VerifySignature(decrypted, signature);
            if (!isgood) throw new Exception("Signature is bad");

            return decrypted;
        }
        static public BaseModel AESDecrypt(BaseModel data, string password = null)
        {
            try
            {
                string salt = CryptoHelper.GetSalt(false, data.Salt);
                int seed = CryptoHelper.GetSeed(false, data.Seed);
                int iterations = CryptoHelper.GetSeed(false, data.Iterations);

                if (salt == null) throw new Exception("Salt is null");
                if (seed == -1) throw new Exception("App Seed = -1");
                if (iterations == -1) throw new Exception("Iteration = -1");

                if (data as AppData != null)
                {
                    ((AppData)data).RSAPublicKey = AESDecryptString(salt, iterations, seed, ((AppData)data).RSAPublicKey, password);
                    ((AppData)data).CSR = AESDecryptString(salt, iterations, seed, ((AppData)data).RSAPublicKey, password);
                    return data as AppData;
                }
                else if (data as SecureData != null)
                {
                    ((SecureData)data).Data = AESDecryptString(salt, iterations, seed, ((SecureData)data).Data, password);
                    ((SecureData)data).NoteTitle = AESDecryptString(salt, iterations, seed, ((SecureData)data).NoteTitle, password);
                    return data as SecureData;
                }
                else
                {
                    data.Data = AESDecryptString(salt, iterations, seed, data.Data, password);
                    return data;
                }
            }
            catch (Exception e)
            {
                FileHelper.WriteFile(ErrorHelper.FormatError(e), FileHelper.ErrorPath, true);
                return null;
            }
        }
        public static byte[] HASH512(byte[] dataToHash)
        {
            using SHA512 shaM = new SHA512Managed();
            return shaM.ComputeHash(dataToHash);
        }
        public static byte[] Hash512Iterate(byte[] data, int iterations)
        {
            for (int i = 0; i < iterations; i++)
                data = HASH512(data);

            return data;
        }
        public static byte[] GenerateRandomBytes(int size = 32)
        {
            using var provider = new RNGCryptoServiceProvider();
            var bytes = new byte[size];
            provider.GetBytes(bytes);
            return bytes;
        }
        public static int PseudoRandomNumber(int lower = 1000, int upper = 9999)
        {
            SecureRandom random = new SecureRandom();
            random.SetSeed(GenerateRandomBytes());
            int number = random.Next(lower, upper);
            for (int i = 0; i < random.Next(lower, upper); i++)
            {
                if (i % 100 == 0)
                    random.SetSeed(GenerateRandomBytes());
                number = random.Next(lower, upper);
            }
            return number;
        }
    }
}