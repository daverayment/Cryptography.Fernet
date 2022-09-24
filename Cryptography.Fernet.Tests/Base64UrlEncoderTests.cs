namespace Cryptography.UnitTesting;

[TestClass]
public class Base64UrlEncoderTests
{
	/// <summary>
	/// Checks the decoder catches cases with characters outside of the valid 
	/// base64url alphabet.
	/// </summary>
	[TestMethod]
	public void DecodeThrowsWithInvalidCharacter()
	{
		Assert.ThrowsException<FormatException>(() =>
			Utility.Base64UrlEncoder.Decode("A*"));
	}

	/// <summary>
	/// Checks that the decoder throws an exception when the string passed in has
	/// invalid padding. (Only 1 or 2 padding characters are allowed.)
	/// </summary>
	[TestMethod]
	public void DecodeThrowsWith4PaddingChars()
	{
		Assert.ThrowsException<FormatException>(() =>
			Utility.Base64UrlEncoder.Decode("QW4g===="));
	}

	[TestMethod]
	public void DecodeThrowsWith1PaddingChar()
	{
		Assert.ThrowsException<FormatException>(() =>
			Utility.Base64UrlEncoder.Decode("Q"));
	}

	[TestMethod]
	public void DecodeStringEndingIn2PaddingChars()
	{
		Assert.AreEqual("More text.",
			Utility.Base64UrlEncoder.Decode("TW9yZSB0ZXh0Lg=="));
	}

	[TestMethod]
	public void DecodeStringEndingInNoPaddingChars()
	{
		Assert.AreEqual("ABCDEF", Utility.Base64UrlEncoder.Decode("QUJDREVG"));
	}

	/// <summary>
	/// Decode automatically pads inputs as necessary (otherwise, the Base 64
	/// decode would fail). This checks that 2-character padding works OK.
	/// </summary>
	[TestMethod]
	public void DecodeAdds2PaddingChars()
	{
		string toPad = Utility.Base64UrlEncoder.Decode("QQ");
		// Should decode to the same string.
		string padded = Utility.Base64UrlEncoder.Decode("QQ==");
		Assert.AreEqual("A", toPad);
		Assert.AreEqual("A", padded);
	}

	[TestMethod]
	public void DecodeAdds1PaddingChar()
	{
		string toPad = Utility.Base64UrlEncoder.Decode("QUI");
		string padded = Utility.Base64UrlEncoder.Decode("QUI=");
		Assert.AreEqual("AB", toPad);
		Assert.AreEqual("AB", padded);
	}

	[TestMethod]
	public void DecodeAcceptsBlankInput()
	{
		Assert.AreEqual("", Utility.Base64UrlEncoder.Decode(""));
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
