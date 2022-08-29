# Cryptography.Fernet
A .NET implementation of the Fernet symmetric encryption standard.

## Introduction
This .NET library provides routines to create and decrypt Fernet tokens.

The Fernet standard is described here: https://github.com/fernet/spec/blob/master/Spec.md.

The current (and only!) 0x80 version of Fernet is supported.

## Usage
### Encryption without a Key
The simplest token creation method doesn't require you to pre-generate a Fernet key. A cryptographically-secure key is generated for you and returned along with the encrypted token in a Tuple. All you need to supply is the plaintext you want to encrypt.

```csharp
(string key, string token) = Cryptography.Fernet.Encrypt(plaintext);
// Now save the key for decrypting the token later on...
```

Note: internally, the `System.Security.Cryptography.RandomNumberGenerator` is used to generate the key.

### Encryption with a Key
To encrypt a plaintext message with a pre-existing key, pass it in as the first parameter:

```csharp
string token = Cryptography.Fernet.Encrypt(key, plaintext);
```

#### A Note on the Fernet Key Format
Fernet Keys must be in 'base64url' format. This is identical to plain base64 but with 2 character substitutions to make the strings usable in URLs and as filenames. It is described as part of RFC 4648 here: https://www.rfc-editor.org/rfc/rfc4648#section-5.

This project includes a `Utility.Base64UrlEncoder` class which can be used to convert byte arrays to and from this format.

The following example shows how to use the encoder class before calling `Encrypt` to generate the Fernet token.

```csharp
// Create a byte array of the correct size and fill it with random bytes.
byte[] key = new byte[Cryptography.Fernet.KeySize];
System.Security.Cryptography.RandomNumberGenerator.Fill(key);
// Encode the key as a string, using the utility class' Base64UrlEncoder.
string keyString = Utility.Base64UrlEncoder.Encode(key);
// Create the Fernet token.
string token = Encrypt(keyString, "My plaintext string.");
```

If you have no need to use a specific key, it is recommended to use the `Encrypt` overload detailed above which has only the plaintext parameter; this will handle creating a secure key for you.

### Decryption
To retrieve the original plaintext contents, pass the Fernet key and the encrypted token to the `Decrypt` method:

```csharp
string originalMessage = Cryptography.Fernet.Decrypt(key, token);
```

### Decryption with Token Expiry
Fernet tokens store their creation time and you can control their expiration by passing in a `TimeSpan` parameter to `Decrypt`. The TimeSpan determines the token's lifetime, e.g. a value of 10 seconds means the token will be judged to have expired 10 seconds after being created. If the current time equals or exceeds the calculated expiry time, an exception is raised and the token will not be decrypted.

An example of the syntax:

```csharp
// Throws an exception if it has been 20 minutes or longer since the token was created.
string originalMessage = Cryptography.Fernet.Decrypt(key, token, TimeSpan.FromMinutes(20));
```

A limitation of the Fernet specification is that the original token creation time is stored as whole seconds. As a result of this, sub-second accuracy for token expiry is not possible.

## Testing
A separate MSTest project with several unit tests is included in the solution.

To run the tests, either use the Test Explorer within Visual Studio (within the `Test` main menu) or open a command prompt, navigate to the solution folder and execute the following:

```
dotnet test
```

You should see results similar to this:

![image](https://user-images.githubusercontent.com/7127766/187106455-29046500-9a64-4cb0-8eeb-838fd110d04f.png)

## Attributions
<a href="https://www.flaticon.com/free-icons/file" title="file icons">File icons created by Payungkead - Flaticon</a>