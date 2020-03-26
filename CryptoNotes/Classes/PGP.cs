using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Bcpg.Sig;
using System.Text;
using System.IO;
using CustomExtensions;
using CryptoNotes.Enum;
using Org.BouncyCastle.Utilities.IO;
using System.Collections.Generic;
using System.Linq;

namespace CryptoNotes.Classes
{
    public static class PGP
    { 
        public static PgpKeyRingGenerator GenerateKeyRing(String id, byte[] pass, RSAKeySize keysize)
        {
            RsaKeyPairGenerator kpg = new RsaKeyPairGenerator();

            kpg.Init(new KeyGenerationParameters(new SecureRandom(), 4096));
            
            AsymmetricCipherKeyPair rsakeys = kpg.GenerateKeyPair();

            PgpKeyPair rsakp_sign = new PgpKeyPair(PublicKeyAlgorithmTag.RsaSign, rsakeys, DateTime.UtcNow);
            PgpKeyPair rsakp_enc = new PgpKeyPair(PublicKeyAlgorithmTag.RsaEncrypt, rsakeys, DateTime.UtcNow);

            PgpSignatureSubpacketGenerator signhashgen = new PgpSignatureSubpacketGenerator();

            signhashgen.SetKeyFlags(false, KeyFlags.SignData | KeyFlags.CertifyOther);   
            signhashgen.SetPreferredSymmetricAlgorithms
                (false, new int[] {
                (int)SymmetricKeyAlgorithmTag.Aes256,
                (int)SymmetricKeyAlgorithmTag.Camellia256
                });
            
            signhashgen.SetPreferredHashAlgorithms
                (false, new int[] {
                (int) HashAlgorithmTag.Sha256,
                (int) HashAlgorithmTag.Sha384,
                (int) HashAlgorithmTag.Sha512
                });

            signhashgen.SetFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

            // Create a signature on the encryption subkey.
            PgpSignatureSubpacketGenerator enchashgen = new PgpSignatureSubpacketGenerator();
            enchashgen.SetKeyFlags(false, KeyFlags.EncryptComms | KeyFlags.EncryptStorage | KeyFlags.Authentication);

            PgpKeyRingGenerator pgpKeyRing = new PgpKeyRingGenerator(
                PgpSignature.DefaultCertification,
                rsakp_sign,
                id,
                SymmetricKeyAlgorithmTag.Aes256,
                pass,
                false,
                signhashgen.Generate(),
                null,
                new SecureRandom()
            );

            pgpKeyRing.AddSubKey(rsakp_enc, enchashgen.Generate(), null, HashAlgorithmTag.Sha512);

            return pgpKeyRing;
        }
        public static PgpSecretKey GetEncryptionKey(PgpSecretKeyRing keys)
        {
            foreach(PgpSecretKey key in keys.GetSecretKeys())
            {
                var test = key.PublicKey.IsEncryptionKey;
                if (key.PublicKey.IsEncryptionKey) return key;
            }
            return null;
        }
        private static string GetArmorString(Object key)
        {
            var memStream = new MemoryStream();
            var armoredStream = new ArmoredOutputStream(memStream);
            
            if (key as PgpPublicKeyRing != null)
                ((PgpPublicKeyRing)key).Encode(armoredStream);
            else if (key as PgpPublicKeyRingBundle != null)
                ((PgpPublicKeyRingBundle)key).Encode(armoredStream);
            else if (key as PgpSecretKeyRing != null)
                ((PgpSecretKeyRing)key).Encode(armoredStream);
            else if (key as PgpSecretKey != null)
                ((PgpSecretKey)key).Encode(armoredStream);
            else if (key as PgpSecretKeyRingBundle != null)
                ((PgpSecretKeyRingBundle)key).Encode(armoredStream);
            else
                return null;

            armoredStream.Close();
            var ascString = Encoding.ASCII.GetString(memStream.ToArray());
            return ascString;
        }
        public static string ArmoredKey(PgpPublicKeyRing publicKeyRing)
        {
            return GetArmorString(publicKeyRing);
        }
        public static string ArmoredKey(PgpSecretKeyRing secretKeyRing)
        {
            return GetArmorString(secretKeyRing);
        }
        public static string ArmoredKey(PgpSecretKey secretKey)
        {
            return GetArmorString(secretKey);
        }
        public static byte[] PgpEncrypt(
            Stream toEncrypt,
            PgpPublicKey encryptionKey,
            bool armor = true,
            bool verify = false,
            CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Zip)
        {
            var encryptor = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, verify, new SecureRandom());
            var literalizer = new PgpLiteralDataGenerator();
            var compressor = new PgpCompressedDataGenerator(compressionAlgorithm);
            encryptor.AddMethod(encryptionKey);

            using var stream = new MemoryStream();
            using var armoredStream = armor ? new ArmoredOutputStream(stream) : stream as Stream;
            using var compressedStream = compressor.Open(armoredStream);

            var rawData = toEncrypt.ReadFully();
            var buffer = new byte[1024];
            using var literalOut = new MemoryStream();
            using var literalStream = literalizer.Open(literalOut, 'b', "STREAM", DateTime.UtcNow, buffer);
            literalStream.Write(rawData, 0, rawData.Length);
            literalStream.Close();
            var literalData = literalOut.ReadFully();

            using var encryptedStream = encryptor.Open(compressedStream, literalData.Length);
            encryptedStream.Write(literalData, 0, literalData.Length);
            encryptedStream.Close();
            compressedStream.Close();
            armoredStream.Close();
            
            stream.Position = 0;
            Stream outStream = new MemoryStream();
            var data = stream.ReadFully();
            outStream.Write(data, 0, data.Length);
            
            return data;
        }

        public static Stream PgpDecrypt(
            Stream encryptedData,
            string armoredPrivateKey,
            string privateKeyPassword,
            Encoding armorEncoding = null)
        {
            armorEncoding = armorEncoding ?? Encoding.UTF8;
            var stream = PgpUtilities.GetDecoderStream(encryptedData);
            var layeredStreams = new List<Stream> { stream }; //this is to clean up/ dispose of any layered streams.
            var dataObjectFactory = new PgpObjectFactory(stream);
            var dataObject = dataObjectFactory.NextPgpObject();
            Dictionary<long, PgpSecretKey> secretKeys;

            using (var privateKeyStream = armoredPrivateKey.Streamify(armorEncoding))
            {
                var secRings = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream)).GetKeyRings()
                                                                                               .OfType<PgpSecretKeyRing>();
                var pgpSecretKeyRings = secRings as PgpSecretKeyRing[] ?? secRings.ToArray();
                if (!pgpSecretKeyRings.Any()) throw new ArgumentException("No secret keys found.");
                secretKeys = pgpSecretKeyRings.SelectMany(x => x.GetSecretKeys().OfType<PgpSecretKey>())
                                              .ToDictionary(key => key.KeyId, value => value);
            }

            while (!(dataObject is PgpLiteralData) && dataObject != null)
            {
                try
                {
                    PgpCompressedData compressedData = null;
                    PgpEncryptedDataList listedData = null;

                    if (dataObject as PgpCompressedData != null) compressedData = dataObject as PgpCompressedData;
                    if (dataObject as PgpEncryptedDataList != null) listedData = dataObject as PgpEncryptedDataList;

                    if (compressedData == null && listedData == null) return null;
                        
                    //strip away the compression stream
                    if (compressedData != null)
                    {
                        stream = compressedData.GetDataStream();
                        layeredStreams.Add(stream);
                        dataObjectFactory = new PgpObjectFactory(stream);
                    }

                    //strip the PgpEncryptedDataList
                    if (listedData != null)
                    {
                        var encryptedDataList = listedData.GetEncryptedDataObjects().OfType<PgpPublicKeyEncryptedData>().First();
                        var decryptionKey = secretKeys[encryptedDataList.KeyId].ExtractPrivateKey(privateKeyPassword.ToCharArray());
                        stream = encryptedDataList.GetDataStream(decryptionKey);
                        layeredStreams.Add(stream);
                        dataObjectFactory = new PgpObjectFactory(stream);
                    }

                    dataObject = dataObjectFactory.NextPgpObject();
                } catch (Exception ex) {
                    throw new PgpException("Failed to strip encapsulating streams.", ex);
                }
            }

            foreach (var layeredStream in layeredStreams)
            {
                layeredStream.Close();
                layeredStream.Dispose();
            }

            if (dataObject == null) return null;

            var literalData = (PgpLiteralData)dataObject;
            var ms = new MemoryStream();
            using (var clearData = literalData.GetInputStream())
            {
                Streams.PipeAll(clearData, ms);
            }
            ms.Position = 0;
            return ms;
        }
    }
}

