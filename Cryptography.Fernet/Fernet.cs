using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Utility;

[assembly: InternalsVisibleTo("Cryptography.Fernet.Tests")]

namespace Cryptography;

/// <summary>
/// An implementation of the Fernet symmetric encryption standard.
/// </summary>
public static class Fernet
{
	/// <summary>
	/// The size of the Fernet key field in bytes.
	/// </summary>
	public const int KeySize = SigningKeySize + EncryptionKeySize;
	/// <summary>
	/// A token should fail validation if it is created in the "far-future".
	/// The exact value is not detailed in the specification, so a default is 
	/// given here.
	/// </summary>
	public static readonly TimeSpan MaxClockDrift = TimeSpan.FromHours(1);

	private const byte FernetVersion = 0x80;
	private const int SigningKeySize = 16;
	private const int EncryptionKeySize = 16;
	private const int IVSize = 16;
	internal const int TimestampSize = 8;
	// Ciphertext starts after Version, Timestamp and IV fields.
	private const int CiphertextStart = 1 + TimestampSize + IVSize;
	private const int HmacSize = 32;

	/// <summary>
	/// Encrypt a plaintext message into a Fernet token.
	/// </summary>
	/// <param name="key">The key to use to encrypt the message. Consists of
	/// 16-byte signing key and 16-byte encryption key joined together. Encoded
	/// as base64url.</param>
	/// <param name="message">The plaintext you wish to encrypt.</param>
	/// <param name="saveTimestamp">Optional. Determines whether the creation 
	/// time is stored as part of the token or not. This control is a security
	/// measure, as the timestamp may be seen as sensitive information for 
	/// certain scenarios. Defaults to true.</param>
	/// <returns>The newly-generated token in base64url format.</returns>
	public static string Encrypt(string key, string message,
		bool saveTimestamp = true)
	{
		return EncryptInternal(key, message, saveTimestamp);
	}

	/// <summary>
	/// Convenience method which creates a cryptographically-strong key for you
	/// before encrypting the message provided.
	/// </summary>
	/// <param name="message">The plaintext string to encrypt.</param>
	/// <param name="saveTimestamp">Optional. Determines whether the creation 
	/// time is stored as part of the token or not. This control is a security
	/// measure, as the timestamp may be seen as sensitive information for 
	/// certain scenarios. Defaults to true.</param>
	/// <returns>A tuple containing the key and the Fernet token, both in 
	/// base64url format.</returns>
	public static (string key, string token) Encrypt(string message,
		bool saveTimestamp = true)
	{
		byte[] key = new byte[KeySize];
		RandomNumberGenerator.Fill(key);
		string keyBase64 = Base64UrlEncoder.Encode(key);
		string token = EncryptInternal(keyBase64, message, saveTimestamp);

		return (keyBase64, token);
	}

	internal static string EncryptInternal(byte[] key, byte[] message,
		bool saveTimestamp = true, DateTime? tokenCreationTimeUtc = null,
		byte[]? iv = null)
	{
		ulong timestamp = 0;

		if (saveTimestamp)
		{
			// Creation time is the number of seconds since midnight Jan 1st
			// 1970 UTC.
			DateTime now = tokenCreationTimeUtc ?? DateTime.UtcNow;
			timestamp = (ulong)new DateTimeOffset(now).ToUnixTimeSeconds();
		}

		using var aes = Aes.Create();
		// Use the second half of the key byte array as the AES encryption key.
		aes.Key = key[SigningKeySize..];
		if (iv is null)
		{
			aes.GenerateIV();
		}
		else
		{
			aes.IV = iv;
		}

		// TODO: encryptcbc has an overload which fills in a span directly. Use that?
		byte[] encryptedMessage = aes.EncryptCbc(message, aes.IV);

		int tokenSizeMinusHmac = CiphertextStart + encryptedMessage.Length;
		byte[] token = new byte[tokenSizeMinusHmac + HmacSize];
		token[0] = FernetVersion;
		if (saveTimestamp)
		{
			byte[] timeBytes = BitConverter.GetBytes(timestamp);
			// The time field must be stored in big-endian format.
			if (BitConverter.IsLittleEndian)
			{
				timeBytes = timeBytes.Reverse().ToArray();
			}

			timeBytes.CopyTo(token, 1);
		}
		aes.IV.CopyTo(token, 1 + TimestampSize);
		encryptedMessage.CopyTo(token, CiphertextStart);

		using var hmac = new HMACSHA256(key[..SigningKeySize]);
		var hash = hmac.ComputeHash(token, 0, tokenSizeMinusHmac);
		hash.CopyTo(token, tokenSizeMinusHmac);

		return Base64UrlEncoder.Encode(token);
	}

	internal static string EncryptInternal(string key, string message,
		bool saveTimestamp = true, DateTime? tokenCreationTimeUtc = null,
		byte[]? iv = null)
	{
		return EncryptInternal(ValidateAndDecodeKeyString(key),
			Encoding.UTF8.GetBytes(message), saveTimestamp,
			tokenCreationTimeUtc, iv);
	}

	/// <summary>
	/// Verify and decrypt a fernet token.
	/// </summary>
	/// <param name="key">The fernet key used to encrypt the token. 
	/// Consists of a 16-byte signing key and 16-byte encryption key
	/// concatenated together. Encoded as base64url.
	/// </param>
	/// <param name="token">The fernet token to verify and decrypt. Fields
	/// are packed in Version|Timestamp|IV|Ciphertext|HMAC order.</param>
	/// <param name="tokenLifetime">Optional <see cref="TimeSpan"/> which 
	/// provides a time-to-live for the token. If this parameter is given, 
	/// expired tokens will throw an exception. The precision is whole seconds
	/// only because the creation time is stored as a UNIX timestamp.</param>
	/// <returns>The decrypted text.</returns>
	/// <exception cref="ArgumentException">The key or token parameters are
	/// missing or are the incorrect size.
	/// </exception>
	/// <exception cref="FormatException">The key or token parameters are not
	/// correctly base64url encoded.</exception>
	/// <exception cref="CryptographicException">The provided token has an
	/// incompatible version number, the HMAC is incorrect, or the token has
	/// already expired.</exception>
	public static string Decrypt(string key, string token,
		TimeSpan? tokenLifetime = null)
	{
		return DecryptInternal(key, token, tokenLifetime);
	}

	/// <summary>
	/// Verify and decrypt a fernet token. Internal-only with optional current
	/// time overload for unit testing.
	/// </summary>
	/// <param name="key">The fernet key used to encrypt the token. 
	/// Consists of a 16-byte signing key and 16-byte encryption key
	/// concatenated together. Encoded as base64url.
	/// </param>
	/// <param name="token">The fernet token to verify and decrypt. Fields
	/// are packed in Version|Timestamp|IV|Ciphertext|HMAC order.</param>
	/// <param name="tokenLifetime">Optional <see cref="TimeSpan"/> which 
	/// provides a time-to-live for the token. If this parameter is given, 
	/// expired tokens will throw an exception. The precision is whole seconds
	/// only because the creation time is stored as a UNIX timestamp.</param>
	/// <param name="currentTimeUtc">Optional DateTime to use as the current
	/// time. This is used for unit tests against the specification examples.
	/// </param>
	/// <returns>The decrypted text.</returns>
	/// <exception cref="ArgumentException">The key or token parameters are
	/// missing or are the incorrect size.
	/// </exception>
	/// <exception cref="FormatException">The key or token parameters are not
	/// correctly base64url encoded.</exception>
	/// <exception cref="CryptographicException">The provided token has an
	/// incompatible version number, the HMAC is incorrect, the token has
	/// already expired, or the token's creation timestamp is too far in the
	/// future.</exception>
	internal static string DecryptInternal(
		string key, string token, TimeSpan? tokenLifetime = null,
		DateTime? currentTimeUtc = null)
	{
		if (token.Length == 0)
		{
			throw new ArgumentException("A Fernet token must be provided.",
				nameof(token));
		}

		DateTime timeCalled = currentTimeUtc ?? DateTime.UtcNow;
		byte[] keyBytes = ValidateAndDecodeKeyString(key);

		Span<byte> decoded = Base64UrlEncoder.DecodeBytes(token).AsSpan();
		if (decoded[0] != FernetVersion)
		{
			throw new CryptographicException(
				$"Fernet version must be 0x{FernetVersion:X}.",
				nameof(token));
		}

		// The signing key is the first half of the decoded key parameter.
		var keySpan = keyBytes.AsSpan();
		byte[] signingKey = keySpan[..SigningKeySize].ToArray();

		// Recompute HMAC from the other fields and the signing key.
		using var hmac = new HMACSHA256(signingKey);
		var computedHash = hmac.ComputeHash(
			decoded.Slice(0, decoded.Length - HmacSize).ToArray());

		// Verify the computed hash against the one stored in the token.
		if (!new ReadOnlySpan<byte>(computedHash)
			.SequenceEqual(decoded.Slice(decoded.Length - HmacSize, HmacSize)))
		{
			throw new CryptographicException(
				"Invalid token. HMAC is incorrect.", nameof(token));
		}

		var timeBytes = decoded.Slice(1, TimestampSize);

		// The timestamp is stored in big-endian format, so we may need to
		// reverse the byte order before conversion.
		if (BitConverter.IsLittleEndian)
		{
			timeBytes.Reverse();
		}
		var seconds = BitConverter.ToUInt64(timeBytes);
		var timestamp = DateTime.UnixEpoch.AddSeconds(seconds);
		if (BitConverter.IsLittleEndian)
		{
			// Restore the original token contents.
			timeBytes.Reverse();
		}
		// Is the creation time valid? We allow this to exist in the future to
		// account for clock skew/drift, but values outside that margin must be
		// flagged.
		if (timestamp > timeCalled.Add(MaxClockDrift))
		{
			throw new CryptographicException("The token's creation timestamp " +
				$"is invalid. {timestamp} is too far in the future. Current " +
				$"time is {timeCalled}.");
		}

		// Check for token expiry if a time-to-live has been supplied.
		if (tokenLifetime.HasValue)
		{
			var expiry = timestamp.Add(tokenLifetime.Value);
			if (timeCalled > expiry)
			{
				throw new CryptographicException(
					$"Token expired at {expiry:G}. Current time is {timeCalled:G}.");
			}
		}

		// Decrypt the ciphertext using AES.
		using var aes = Aes.Create();
		aes.Key = keySpan[^EncryptionKeySize..].ToArray();
		aes.IV = decoded.Slice(1 + TimestampSize, IVSize).ToArray();

		byte[] ciphertext = decoded.Slice(
			CiphertextStart, decoded.Length - CiphertextStart - HmacSize).ToArray();
		byte[] decrypted = aes.DecryptCbc(ciphertext, aes.IV);

		// Clear AES state and secret key copy.
		aes.Clear();
		Array.Clear(keyBytes);

		return Encoding.UTF8.GetString(decrypted);
	}

	/// <summary>
	/// Converts a base64url-encoded Fernet key into a byte array.
	/// </summary>
	/// <param name="key">The key in base64url format.</param>
	/// <returns>The base64url-decoded representation of the key as a byte
	/// array.</returns>
	/// <exception cref="ArgumentException">The key was not the correct size.
	/// Fernet keys must be 32 bytes long (16-byte signing key and 16-byte
	/// encryption key concatenated together).</exception>
	private static byte[] ValidateAndDecodeKeyString(string key)
	{
		if (key.Length == 0)
		{
			throw new ArgumentException(
				"A Fernet key must be provided.", nameof(key));
		}

		byte[] keyBytes = Base64UrlEncoder.DecodeBytes(key);
		if (keyBytes.Length != KeySize)
		{
			throw new ArgumentException("Decoded key field must be " +
				$"{SigningKeySize + EncryptionKeySize} bytes.",
				nameof(key));
		}

		return keyBytes;
	}
}
