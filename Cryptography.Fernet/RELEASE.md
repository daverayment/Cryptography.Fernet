# Version 1.1.1

Minor bugfix release to correct the package link to the `RELEASE.md` file. Also fixed the formatting of the description text for NuGet.

# Version 1.1.0

## New functionality
- A `saveTimestamp` parameter was added to `Encrypt`. This defaults to `true`, which provides the same functionality as prior releases. Setting to `false` means the token will be generated with a zeroed-out creation timestamp. This is a solution for certain scenarios where unencrypted timestamps such as Fernet's are regarded as sensitive information.
- `Decrypt` now features automatic validation for 'clock drift' situations. This is where the decrypting system's internal clock differs from the system which generated the token. An exception is thrown if a token's creation timestamp is too far in the future. The maximum discrepancy is stored within the `MaxClockDrift` TimeSpan in the main project's `Fernet.cs` file.

## Testing
A significant number of new tests were added to the unit test project, bringing the total up to more than 30:
- Tests added to exercise the entire specification, validation and generation documentation from the Fernet project repository.
- Tests added for the `Utility.Base64UrlEncoder` class.

Most tests now include at least summary documentation.

## API Changes
- `Base64UrlEncoder.DecodeBytes` now throws a `System.FormatException` instead of a `System.ArgumentException` if the string passed in is invalid.

# Version 1.0.1
Minor documentation edit to fix a link which was rendered incorrectly on NuGet.

# Version 1.0.0
First deployment to NuGet. Encryption, Decryption, base64url utilities etc. all tested working. Unit test project included. Compatibility tested with Python implementation and token examples given in the specification repository.