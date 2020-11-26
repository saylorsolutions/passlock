# Password Lock
This library provides an easy to use and well tested method to AES encrypt data
based on a user provided password generated key.

It's certainly better to use more randomly generated keys, but this process is still
sufficiently secure as to make passive compromise of data all but impossible.

## Evaluate Your Risk
While we make every attempt to adhere to encryption best practices and mitigate
known and potential vulnerabilities, bugs happen, and people make mistakes. This
library has not been independently reviewed or vetted by an independent security
research individual or organization. This is not intended to hide information from
well funded government agencies or NGOs. It relies on algorithms thought
to be secure at the time of this writing, but these things change. Please refer
to the tech notes and vulnerability reporting guidelines below to evaluate your
own level of risk and report security issues. Please see the LICENSE file for full
terms and conditions of use.

## Using the Library
Since the idea is to make this as easy to use as possible, there are a total of 2
functions provided by this library. One for encryption, and one for decryption.

### Encrypt Data
Use the `EncryptBytes` function with the password and data as parameters to generate
a salted key from the password bytes, check the error return value, and create the
cipher text. The GCM and password salts are both added to the cipher text, so there's
no need to track anything other than the password to decrypt the data.

### Decrypt Data
Decryption works the same way. The same password should be provided to `DecryptBytes`
along with the cipher text to get the plain text. If the authenticity of the cipher text
cannot be verified with the salt, then the data will not be decrypted, and the error
returned will be non-nil. Of course, if the password and salt does not generate the
correct key, then the data will not be decrypted, and the returned error will be non-nil.

## Technical details
* Uses `golang.org/x/crypto` for all crypto functions. No "roll-your-own"s here.
* Uses a scrypt generated key to nullify the risk of rainbow tables, and to ensure that
the password generation process is costly enough that brute forcing the password is
highly impractical.
* The encryption key bytes are fed into an AES GCM block cipher which encrypts the data.

# Reporting Security Issues
If you believe you've found a security vulnerability in this library, please email
support@saylorsolutions.com from a deliverable email address explaining the
situation, so we can verify and fix the problem without endangering users.

Thank you!
