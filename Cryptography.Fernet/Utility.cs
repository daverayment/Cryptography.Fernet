﻿using System.Text;

namespace Utility;

/// <summary>
/// Converts to and from URL-safe Base64 encoding.
/// </summary>
/// <remarks>See RFC here: https://datatracker.ietf.org/doc/html/rfc4648#section-5</remarks>
public static class Base64UrlEncoder
{
    /// <summary>
    /// Decode a URL-safe Base64 encoded string into a byte array.
    /// </summary>
    /// <param name="str">The encoded string in URL-safe Base64 format.
    /// </param>
    /// <returns>A new byte array containing the decoded output.</returns>
    /// <exception cref="ArgumentException">Raised if the input string had 
    /// invalid padding. Only 2 or 3 padding characters ('=') are valid.
    /// </exception>
    public static byte[] DecodeBytes(string str)
    {
        str = str.Replace('-', '+').Replace('_', '/') +
            (str.Length % 4) switch
            {
                1 => throw new ArgumentException(
                    "Illegal padding. Cannot decode Base64 URL string.",
                    nameof(str)),
                2 => "==",
                3 => "=",
                _ => ""
            };

        return Convert.FromBase64String(str);
    }

    /// <summary>
    /// Encode a byte array into base64url format.
    /// </summary>
    /// <param name="message">The bytes to encode into base64url format.
    /// </param>
    /// <returns>The encoded result.</returns>
    public static string Encode(byte[] message)
    {
        return Convert.ToBase64String(message)
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>
    /// Decode a URL-safe Base64 encoded string and convert it into a UTF-8
    /// string.
    /// </summary>
    /// <param name="str">The encoded string in URL-safe Base64 format.</param>
    /// <returns>A new UTF-8 string containing the decoded output.</returns>
    public static string Decode(string str)
    {
        return Encoding.UTF8.GetString(DecodeBytes(str));
    }
}