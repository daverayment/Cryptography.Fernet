using System.Security.Cryptography;
using Utility;

namespace Cryptography.UnitTesting;

[TestClass]
public partial class FernetTests
{
    private const string TestMessage = "Test.";
    private static readonly byte[] KeyBytes = 
        RandomNumberGenerator.GetBytes(Fernet.KeySize);
    private static readonly string Key = Base64UrlEncoder.Encode(KeyBytes);
    private static readonly string TestToken =
        Fernet.Encrypt(Key, TestMessage);

    [TestMethod]
    public void DecryptThrowsIfKeyNotSupplied()
    {
        Assert.ThrowsException<ArgumentException>(() =>
            Fernet.Decrypt("", TestToken));
    }

    [TestMethod]
    public void DecryptThrowsIfKeyIsTooShort()
    {
        string shortKey = Base64UrlEncoder.Encode(
            KeyBytes.Take(Fernet.KeySize - 1).ToArray());
        Assert.ThrowsException<ArgumentException>(() =>
            Fernet.Encrypt(shortKey, TestMessage));
    }

    [TestMethod]
    public void DecryptThrowsIfKeyIsTooLong()
    {
        byte[] longKeyBytes = new byte[KeyBytes.Length + 1];
        KeyBytes.CopyTo(longKeyBytes, 0);
        Assert.ThrowsException<ArgumentException>(() =>
            Fernet.Encrypt(Base64UrlEncoder.Encode(longKeyBytes), TestMessage));
    }

    [TestMethod]
    public void DecryptThrowsIfKeyDoesNotMatch()
    {
        string key = Base64UrlEncoder.Encode(
            RandomNumberGenerator.GetBytes(Fernet.KeySize));
        Assert.ThrowsException<ArgumentException>(() =>
            Fernet.Decrypt(key, TestToken));
    }

    [TestMethod]
    public void DecryptThrowsIfFernetTokenVersionNumberDoesNotMatch()
    {
        byte[] testTokenBytes = Base64UrlEncoder.DecodeBytes(TestToken);
        testTokenBytes[0] = 0;
        Assert.ThrowsException<ArgumentException>(() => 
            Fernet.Decrypt(Key, Base64UrlEncoder.Encode(testTokenBytes)));
    }

    [TestMethod]
    public void DecryptThrowsIfHmacVerificationFails()
    {
        byte[] testTokenBytes = Base64UrlEncoder.DecodeBytes(TestToken);
        // Alter one of the timestamp bytes, as this isn't used in this
        // particular test. This will alter the subsequent message hash.
        // Timestamp starts at index 1 and is 8 bytes.
        testTokenBytes[1] = 1;
        Assert.ThrowsException<ArgumentException>(() =>
            Fernet.Decrypt(Key, Base64UrlEncoder.Encode(testTokenBytes)));
    }

    [TestMethod]
    public void DecryptThrowsIfTokenHasExpired()
    {
        string newToken = Fernet.Encrypt(Key, TestMessage);
        Thread.Sleep(1000);
        Assert.ThrowsException<ApplicationException>(() =>
            Fernet.Decrypt(Key, newToken, TimeSpan.FromSeconds(1)));
    }

    [TestMethod]
    public void DecryptSucceedsWhenTokenHasNotExpired()
    {
        string newToken = Fernet.Encrypt(Key, TestMessage);
        Fernet.Decrypt(Key, newToken, TimeSpan.FromSeconds(1));
    }
}
