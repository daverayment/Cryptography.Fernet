using System.Security.Cryptography;
using Utility;

namespace Cryptography.UnitTesting
{
    public partial class FernetTests
    {
        private const int LargeMessageSize = 4 * 1024 * 1024;

        [TestMethod]
        public void EncryptThrowsIfKeyIsBlank()
        {
            Assert.ThrowsException<ArgumentException>(() =>
                Fernet.Encrypt("", "Test"));
        }

        [TestMethod]
        public void EncryptPermitsEmptyPlaintext()
        {
            (_, string token) = Fernet.Encrypt(string.Empty);
            Assert.IsTrue(token != null && token.Length > 0);
        }

        [TestMethod]
        public void EncryptThrowsIfKeyIsTooShort()
        {
            string shortKey = Base64UrlEncoder.Encode(
                RandomNumberGenerator.GetBytes(Fernet.KeySize - 1));
            Assert.ThrowsException<ArgumentException>(() =>
                Fernet.Encrypt(shortKey, "Test"));
        }

        [TestMethod]
        public void EncryptThrowsIfKeyIsTooLong()
        {
            string longKey = Base64UrlEncoder.Encode(
                RandomNumberGenerator.GetBytes(Fernet.KeySize + 1));
            Assert.ThrowsException<ArgumentException>(() =>
                Fernet.Encrypt(longKey, "Test"));
        }

        [TestMethod]
        public void EncryptWithKeyAndMessageArguments()
        {
            byte[] key = new byte[Fernet.KeySize];
            RandomNumberGenerator.Fill(key);
            Fernet.Encrypt(Base64UrlEncoder.Encode(key), "Test");
        }

        [TestMethod]
        public void EncryptWithJustMessageArgument()
        {
            (string key, string token) = Fernet.Encrypt("Test");
            Assert.IsTrue(key != null && key.Length > 0);
            Assert.IsTrue(token != null && token.Length > 0);
            Assert.AreEqual(Fernet.Decrypt(key, token), "Test");
        }

        /// <summary>
        /// Confirm that a token can be created without the creation timestamp.
        /// </summary>
        [TestMethod]
        public void EncryptWithoutSavingTimestamp()
        {
            (_, string token) = Fernet.Encrypt("Test", saveTimestamp: false);

            // Check each timestamp byte is 0.
			Span<byte> decoded = Base64UrlEncoder.DecodeBytes(token).AsSpan();
            foreach (byte b in decoded.Slice(1, Fernet.TimestampSize))
            {
                Assert.AreEqual(b, 0);
            }
		}

        [TestMethod]
        public void EncryptAndDecryptLongMessage()
        {
            byte[] messageBytes = new byte[LargeMessageSize];
            RandomNumberGenerator.Fill(messageBytes);

            string message = Base64UrlEncoder.Encode(messageBytes);
            (string key, string token) = Fernet.Encrypt(message);
            string decrypted = Fernet.Decrypt(key, token);
            Assert.AreEqual(decrypted, message);
        }
	}
}
