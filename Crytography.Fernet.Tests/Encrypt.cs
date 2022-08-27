using System.Security.Cryptography;
using Utility;

namespace Cryptography.UnitTesting
{
    public partial class FernetTests
    {
        [TestMethod]
        public void EncryptThrowsIfKeyNotSupplied()
        {
            Assert.ThrowsException<ArgumentException>(() =>
                Fernet.Encrypt("", "Message."));
        }

        [TestMethod]
        public void EncryptPermitsEmptyPlaintext()
        {
            var token = Fernet.Encrypt(Key, string.Empty);
            Assert.IsTrue(token != null && token.Length > 0);
        }

        [TestMethod]
        public void EncryptThrowsIfKeyIsTooShort()
        {
            string shortKey = Base64UrlEncoder.Encode(
                RandomNumberGenerator.GetBytes(Fernet.KeySize - 1));
            Assert.ThrowsException<ArgumentException>(() =>
                Fernet.Encrypt(shortKey, "Test."));
        }

        [TestMethod]
        public void EncryptThrowsIfKeyIsTooLong()
        {
            string longKey = Base64UrlEncoder.Encode(
                RandomNumberGenerator.GetBytes(Fernet.KeySize + 1));
            Assert.ThrowsException<ArgumentException>(() =>
                Fernet.Encrypt(longKey, "Test."));
        }
    }
}
