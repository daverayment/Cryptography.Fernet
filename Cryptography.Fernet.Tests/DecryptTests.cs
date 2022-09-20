using System.Security.Cryptography;
using Utility;

namespace Cryptography.UnitTesting;

[TestClass]
public partial class FernetTests
{
	[TestMethod]
	public void DecryptThrowsIfKeyNotSupplied()
	{
		(string key, string token) = Fernet.Encrypt("Test.");
		Assert.ThrowsException<ArgumentException>(() =>
			Fernet.Decrypt("", token));
	}

	[TestMethod]
	public void DecryptThrowsIfKeyIsTooShort()
	{
		byte[] shortKeyBytes = new byte[Fernet.KeySize - 1];
		Assert.ThrowsException<ArgumentException>(() => 
			Fernet.Encrypt(Base64UrlEncoder.Encode(shortKeyBytes), "Test"));
	}

	[TestMethod]
	public void DecryptThrowsIfKeyIsTooLong()
	{
		byte[] longKeyBytes = new byte[Fernet.KeySize + 1];
		Assert.ThrowsException<ArgumentException>(() =>
			Fernet.Encrypt(Base64UrlEncoder.Encode(longKeyBytes), "Test"));
	}

	[TestMethod]
	public void DecryptThrowsIfKeyDoesNotMatch()
	{
		string fakeKey = Base64UrlEncoder.Encode(
			RandomNumberGenerator.GetBytes(Fernet.KeySize));
		(string _, string token) = Fernet.Encrypt("Test");
		Assert.ThrowsException<CryptographicException>(() =>
			Fernet.Decrypt(fakeKey, token));
	}

	[TestMethod]
	public void DecryptThrowsIfFernetTokenVersionNumberDoesNotMatch()
	{
		(string key, string token) = Fernet.Encrypt("Test");
		byte[] testTokenBytes = Base64UrlEncoder.DecodeBytes(token);
		testTokenBytes[0] = 0;
		Assert.ThrowsException<CryptographicException>(() => 
			Fernet.Decrypt(key, Base64UrlEncoder.Encode(testTokenBytes)));
	}

	[TestMethod]
	public void DecryptThrowsIfHmacVerificationFails()
	{
		(string key, string token) = Fernet.Encrypt("Test");
		byte[] testTokenBytes = Base64UrlEncoder.DecodeBytes(token);
		// Alter one of the timestamp bytes, as this isn't used in this
		// particular test. This will alter the subsequent message hash.
		// Timestamp starts at index 1 and is 8 bytes.
		testTokenBytes[1] = 1;
		Assert.ThrowsException<CryptographicException>(() =>
			Fernet.Decrypt(key, Base64UrlEncoder.Encode(testTokenBytes)));
	}

	[TestMethod]
	public void DecryptThrowsIfTokenHasExpired()
	{
		(string key, string token) = Fernet.Encrypt("Test");
		Thread.Sleep(1000);
		Assert.ThrowsException<CryptographicException>(() =>
			Fernet.Decrypt(key, token, TimeSpan.FromSeconds(1)));
	}

	[TestMethod]
	public void DecryptSucceedsWhenTokenHasNotExpired()
	{
		(string key, string token) = Fernet.Encrypt("Test");
		Fernet.Decrypt(key, token, TimeSpan.FromSeconds(1));
	}

	[TestMethod]
	public void DecryptTokenExpiryWorksWhenTokenLifetimeIsNegative()
	{
		(string key, string token) = Fernet.Encrypt("Test");
		Assert.ThrowsException<CryptographicException>(() =>
			Fernet.Decrypt(key, token, TimeSpan.FromSeconds(-10)));
	}

	[TestMethod]
	public void DecryptSucceedsForTokenWithNearFutureTimestamp()
	{
		byte[] keyBytes = new byte[Fernet.KeySize];
		RandomNumberGenerator.Fill(keyBytes);
		string key = Base64UrlEncoder.Encode(keyBytes);
		string token = Fernet.EncryptInternal(key, "Test",
			tokenCreationTimeUtc: DateTime.UtcNow.AddMinutes(1));

		Assert.AreEqual(Fernet.Decrypt(key, token), "Test");
	}
}
