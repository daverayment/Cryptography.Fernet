# Cryptography.Fernet
A .NET implementation of the full Fernet symmetric encryption standard.


## Introduction
This .NET library provides routines to create and decrypt Fernet tokens. All features of the current (and only!) 0x80 specification version are included and unit-tested.

The Fernet standard is described [here](https://github.com/fernet/spec/blob/master/Spec.md).


## Getting Started
### Encrypting a message
The simplest method to create a Fernet token is to call `Encrypt` with your plaintext string. No other parameters are needed. A cryptographically-secure key will be generated for you and returned along with the new token.

```csharp
(string key, string token) = Cryptography.Fernet.Encrypt("My plaintext message.");
// Now save the key for decrypting the token later on...
```

Note: internally, .NET's `System.Security.Cryptography.RandomNumberGenerator` is used to generate the key.

### Decrypting a message
To retrieve the original message, you will need the token and the key used to originally encrypt it. Pass both into `Decrypt` to obtain the original plaintext. The key and token must be in base64url format (the values returned from `Encrypt` are in this format).

```csharp
string originalMessage = Cryptography.Fernet.Decrypt(key, token);
```

If your key and/or token are not in base64url already, use the included `Utility.Base64UrlEncoder` to convert them (see [below](Base64url-Encoding) for more information).


## Additional Features

### Encryption with a Key
To encrypt a plaintext message with a pre-existing key, pass it in as the first argument:

```csharp
string token = Cryptography.Fernet.Encrypt(key, plaintext);
```

The key must be in base64url format.

### Token Lifetime
The creation time is stored within each Fernet token. You can control the lifetime of a token by passing in a `TimeSpan` to `Decrypt`'s `tokenLifetime` parameter. For example, a value of 10 seconds means that the token will expire 10 seconds after being created. `Decrypt` will throw an exception if the token has expired.

Here's an example of the syntax:

```csharp
// Throws an exception if it has been 20 minutes or longer since the token was created.
string originalMessage = Cryptography.Fernet.Decrypt(key, token, TimeSpan.FromMinutes(20));
```

Note: a limitation of the Fernet specification is that the original token creation time is stored as whole seconds. As a result of this, sub-second accuracy for token expiry is not possible.

### How to Create a Token Without a Timestamp
The token's timestamp field is recorded unencrypted and may in some circumstances be seen as sensitive information. For maximum security, you may wish to skip generation of the timestamp; doing this sets the creation time to the Unix Epoch of 00:00:00 January 1st 1970.

To create a token without a timestamp, set the `saveTimestamp` parameter of `Encrypt` to `false`.

### Timestamp Validation and Clock Drift
A token may be decrypted on a machine which didn't generate it. To account for differences in the values of internal clocks between machines, it is permitted to have tokens whose creation times appear to be in the future. However, a maximum is built in to the library, and timestamps which are skewed by more than this value are deemed invalid. An exception will be thrown if you attempt to decrypt one.

The maximum time a token timestamp can be in the future is determined by the `MaxClockDrift` field in `Fernet.cs`. To customise this, you will have to edit this value and rebuild from the source code.


## Base64url Encoding
Fernet keys and tokens must be in 'base64url' format. This is identical to plain base64 but with 2 character substitutions to make the strings usable in URLs and as filenames. It is described as part of RFC 4648 [here](https://www.rfc-editor.org/rfc/rfc4648#section-5).

This project includes a `Utility.Base64UrlEncoder` class which can be used to convert byte arrays to and from this format.

The following example shows how to use the encoder class before calling `Encrypt` to generate the Fernet token.

```csharp
// Create a byte array of the correct size and fill it with random bytes.
byte[] key = new byte[Cryptography.Fernet.KeySize];
System.Security.Cryptography.RandomNumberGenerator.Fill(key);
// Encode the key as a base64url string with the Utility class' Base64UrlEncoder.
string keyString = Utility.Base64UrlEncoder.Encode(key);
// Create the Fernet token.
string token = Encrypt(keyString, "My plaintext message.");
```

If you have no need to use a specific key, it is recommended to use the `Encrypt` overload detailed in the Getting Started section, which has only the plaintext parameter; this will handle creating a secure key for you.


## Testing
A separate MSTest project is included as part of the source code repository. Test cases for the complete Fernet specification are covered, including all validation tests detailed in the original project's repository. Tests for the `Base64UrlEncoder` are also included.

To run the tests, start by cloning the repository to your machine. Then either:

1. Open the solution in Visual Studio, build the solution, and use the Test Explorer (within the `Test` main menu) to run them, or;
1. Open a command prompt, navigate to the solution folder and execute `dotnet test`.

## Attributions
[File icons created by Payungkead - Flaticon](https://www.flaticon.com/free-icons/file "file icons")
