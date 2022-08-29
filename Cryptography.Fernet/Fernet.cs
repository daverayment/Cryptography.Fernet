using System.Security.Cryptography;
using System.Text;
using Utility;

namespace Cryptography;

/// <summary>
/// An implementation of the Fernet symmetric encryption standard.
/// </summary>
public static class Fernet
{
    private const byte FernetVersion = 0x80;
    private const int SigningKeySize = 16;
    private const int EncryptionKeySize = 16;
    public const int KeySize = SigningKeySize + EncryptionKeySize;
    private const int IVSize = 16;
    private const int TimestampSize = 8;
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
    public static string Encrypt(string key, string message)
    {
        byte[] keyBytes = ValidateAndDecodeKeyString(key);
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);

        // Creation time is the number of seconds since midnight Jan 1st
        // 1970 UTC.
        ulong timestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        byte[] timeBytes = BitConverter.GetBytes(timestamp);
        // The time field must be stored in big-endian format.
        if (BitConverter.IsLittleEndian)
        {
            timeBytes = timeBytes.Reverse().ToArray();
        }

        using var aes = Aes.Create();
        // Use the second half of the key byte array as the AES encryption key.
        aes.Key = keyBytes[SigningKeySize..];
        aes.GenerateIV();
        // TODO: encryptcbc has an overload which fills in a span directly. Use that?
        byte[] encryptedMessage = aes.EncryptCbc(messageBytes, aes.IV);

        int tokenSizeMinusHmac = CiphertextStart + encryptedMessage.Length;
        byte[] token = new byte[tokenSizeMinusHmac + HmacSize];
        token[0] = FernetVersion;
        timeBytes.CopyTo(token, 1);
        aes.IV.CopyTo(token, 1 + TimestampSize);
        encryptedMessage.CopyTo(token, CiphertextStart);

        using var hmac = new HMACSHA256(keyBytes[..SigningKeySize]);
        var hash = hmac.ComputeHash(token, 0, tokenSizeMinusHmac);
        hash.CopyTo(token, tokenSizeMinusHmac);

        return Base64UrlEncoder.Encode(token);
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
    /// <exception cref="ArgumentException">The key or token parameters 
    /// are incorrectly formatted, or the HMAC check failed.</exception>
    /// <exception cref="ApplicationException">The provided token has 
    /// already expired.</exception>
    public static string Decrypt(
        string key, string token, TimeSpan? tokenLifetime = null)
    {
        if (token.Length == 0)
        {
            throw new ArgumentException("A Fernet token must be provided.",
                nameof(token));
        }

        DateTime timeCalled = DateTime.UtcNow;
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

        // Check for token expiry if a time-to-live has been supplied.
        if (tokenLifetime.HasValue)
        {
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
    /// Converts a base64url-encoded fernet key into a byte array.
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
