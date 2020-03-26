namespace CryptoNotes.Enum
{
    public enum RSAKeySize : int
    {
        RSA1024 = 1024,
        RSA2048 = 2048,
        RSA3072 = 3072,
        RSA4096 = 4096
    }
    public enum DataModelType
    {
        AppData,
        BaseModel,
        SecureData
    }
    public enum KeyType
    {
        PublicKey,
        PrivateKey
    }

    public enum MessageAction
    {
        Encrypt,
        Decrypt
    }
}