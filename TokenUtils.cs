using System;
using System.IO;
using System.Security.Cryptography;

public class TokenUtils
{
    //public static RSA ReadPrivateKey(string path)
    //{
    //    byte[] keyBytes = File.ReadAllBytes(path);
    //    RSA rsa = RSA.Create();
    //    rsa.ImportPkcs8PrivateKey(keyBytes, out _);
    //    return rsa;
    //}

    public static RSA ReadPrivateKeyFromPem(string pemFilePath)
    {
        string pemContent = File.ReadAllText(pemFilePath);
        pemContent = pemContent.Replace("-----BEGIN PRIVATE KEY-----", "")
                               .Replace("-----END PRIVATE KEY-----", "")
                               .Replace("\n", "")
                               .Replace("\r", "");

        byte[] keyBytes = Convert.FromBase64String(pemContent);
        RSA rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(keyBytes, out _);
        return rsa;
    }

    public static int CurrentTimeInSecs()
    {
        return (int)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
    }
}
