using System.Security.Cryptography;

namespace Cryptography.UnitTesting;

public partial class FernetTests
{
	/// <summary>
	/// Deterministically create a token with the parameters from the Fernet 
	/// specification repository's "generate.json" file then compare it to the
	/// token supplied by the spec authors. Confirms that token generation is 
	/// consistent with the spec.
	/// </summary>
	[TestMethod]
	public void EncryptSpecificationExampleDeterministicTokenGeneration()
	{
		string token = Fernet.EncryptInternal("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
			"hello", tokenCreationTimeUtc: DateTime.Parse("1985-10-26T01:20:00-07:00"),
			iv: new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });

		Assert.AreEqual(token,
			"gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==");
	}

	/// <summary>
	/// Decryption verification test from "verify.json" in the Fernet specification
	/// repository. Confirms that decryption and token lifetime checks are correct.
	/// </summary>
	[TestMethod]
	public void EncryptSpecificationVerificationExample()
	{
		string message = Fernet.DecryptInternal("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
			"gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
			tokenLifetime: TimeSpan.FromSeconds(60),
			currentTimeUtc: DateTime.Parse("1985-10-26T01:20:01-07:00").ToUniversalTime());

		Assert.AreEqual(message, "hello");
	}

	/// <summary>
	/// Exercises the "incorrect mac" example in the "invalid.json" file from the 
	/// Fernet specification repository. Tests for a mismatch with the message
	/// hash.
	/// </summary>
	[TestMethod]
	public void DecryptSpecificationExampleInvalidHmac()
	{
		Assert.ThrowsException<CryptographicException>(() =>
			Fernet.Decrypt("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
				"gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykQUFBQUFBQUFBQQ=="));
	}

	/// <summary>
	/// Exercises the "too short" example in the "invalid.json" file from the
	/// Fernet specification repository. Tests for the token being too short.
	/// </summary>
	[TestMethod]
	public void DecryptSpecificationExampleInvalidTooShort()
	{
		Assert.ThrowsException<CryptographicException>(() =>
			Fernet.Decrypt("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
				"gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPA=="));
	}

	/// <summary>
	/// Exercises the "invalid base64" example in the "invalid.json" file from
	/// the Fernet specification repository. Tests for invalid characters in the
	/// token's base64url representation.
	/// </summary>
	[TestMethod]
	public void DecryptSpecificationExampleInvalidBase64()
	{
		Assert.ThrowsException<FormatException>(() =>
			Fernet.Decrypt("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
				"%%%%%%%%%%%%%AECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q=="));
	}

	/// <summary>
	/// Exercises the "payload size not a multiple of block size" example in the
	/// "invalid.json" file from the Fernet specification repository. Tests for
	/// the input data not aligning to a block boundary, which is required for 
	/// AES CBC.
	/// </summary>
	[TestMethod]
	public void DecryptSpecificationExampleInvalidPayloadSize()
	{
		Assert.ThrowsException<CryptographicException>(() =>
			Fernet.Decrypt("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
				"gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPOm73QeoCk9uGib28Xe5vz6oxq5nmxbx_v7mrfyudzUm"));
	}

	/// <summary>
	/// Exercises the "payload padding error" example in the "invalid.json"
	/// file from the Fernet specification repository. Tests for incorrect
	/// padding on the input data. Padding must always be applied and must
	/// conform to the PKCS #7 specification.
	/// </summary>
	/// <remarks>This library uses .NET's AES crypto, which handles PKCS padding
	/// transparently, so this should never be a problem for our tokens.</remarks>
	/// <see cref="https://www.rfc-editor.org/rfc/rfc2315"/>
	/// <seealso cref="https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method"/>
	[TestMethod]
	public void DecryptSpecificationExampleInvalidPayloadPadding()
	{
		Assert.ThrowsException<CryptographicException>(() =>
			Fernet.Decrypt("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
				"gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0ODz4LEpdELGQAad7aNEHbf-JkLPIpuiYRLQ3RtXatOYREu2FWke6CnJNYIbkuKNqOhw=="));
	}

	/// <summary>
	/// Exercises the "far-future TS (unacceptable clock skew)" example in the
	/// "invalid.json" file from the Fernet specification repository. Tests for
	/// a token having an inaccurate creation time, i.e. one which cannot be
	/// explained by natural clock drift.
	/// </summary>
	/// <remarks>Although the validation tests include this example, there is
	/// no mention of clock skew in the specification itself. This means that
	/// checks are implementation-specific. The token in the example is 10
	/// hours ahead of the "current" time, which seems unreasonably large for a
	/// clock drift value. The default for this implementation may be changed 
	/// by editing the <see cref="Fernet.MaxClockDrift"/> TimeSpan field in the 
	/// main project's "Fernet.cs" source file.
	/// </remarks>
	[TestMethod]
	public void DecryptSpecificationExampleFarFutureTimeStamp()
	{
		// Note: the token's UTC timestamp is 18:20:01 on 26/8/1985.
		Assert.ThrowsException<CryptographicException>(() =>
			Fernet.DecryptInternal("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
				"gAAAAAAdwStRAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAnja1xKYyhd-Y6mSkTOyTGJmw2Xc2a6kBd-iX9b_qXQcw==",
				currentTimeUtc: DateTime.Parse("1985-10-26T01:20:01-07:00").ToUniversalTime()));
	}

	/// <summary>
	/// Exercises the "expired TTL" example in the "invalid.json" file from the
	/// Fernet specification repository. Confirms the time-to-live parameter and
	/// expiry logic is correct.
	/// </summary>
	[TestMethod]
	public void DecryptSpecificationExampleExpiredTTL()
	{
		Assert.ThrowsException<CryptographicException>(() =>
			Fernet.DecryptInternal(
				"cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
				"gAAAAAAdwStRAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAnja1xKYyhd-Y6mSkTOyTGJmw2Xc2a6kBd-iX9b_qXQcw==",
				tokenLifetime: TimeSpan.FromSeconds(60),
				currentTimeUtc: DateTime.Parse("1985-10-26T01:21:31-07:00").ToUniversalTime()));
	}

	/// <summary>
	/// Exercises the "incorrect IV (causes padding error)" example in the 
	/// "invalid.json" file from the Fernet specification repository. Tests that
	/// an incorrectly-stored IV will result in a token which cannot be
	/// decrypted.
	/// </summary>
	[TestMethod]
	public void DecryptSpecificationExampleIncorrectIV()
	{
		Assert.ThrowsException<CryptographicException>(() =>
			Fernet.Decrypt("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
				"gAAAAAAdwJ6xBQECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAkLhFLHpGtDBRLRTZeUfWgHSv49TF2AUEZ1TIvcZjK1zQ=="));
	}
}
