namespace Cryptography.UnitTesting;

[TestClass]
public class Base64UrlEncoderTests
{
	[TestMethod]
	public void DecodeInvalidString()
	{
		Assert.ThrowsException<FormatException>(() =>
			Utility.Base64UrlEncoder.Decode("This is not a base64url string!"));
	}

	[TestMethod]
	public void DecodeThrowsWithInvalidPadding()
	{
		Assert.ThrowsException<FormatException>(() =>
			Utility.Base64UrlEncoder.Decode("QW4gZXhhbXBsZSBzdHJpbmcu="));
	}

	[TestMethod]
	public void DecodeStringEndingIn2PaddingChars()
	{
		Utility.Base64UrlEncoder.Decode("QW5vdGhlciBzbGlnaHRseSBsb25nZXIgc3RyaW5nLg==");
	}

	[TestMethod]
	public void DecodeStringNoPaddingChars()
	{
		Utility.Base64UrlEncoder.Decode("QUJDREVG");
	}

	[TestMethod]
	public void EncodeAndDecodeAllByteValues()
	{
		byte[] bytes = new byte[256];
		for (int i = 1; i < 256; i++)
		{
			bytes[i] = (byte)i;
		}
		string allBytesString = Utility.Base64UrlEncoder.Encode(bytes);
		byte[] decoded = Utility.Base64UrlEncoder.DecodeBytes(allBytesString);

		for (int i = 0; i < 256; i++)
		{
			Assert.AreEqual(bytes[i], decoded[i]);
		}
	}
}
