```
                    .___                                  __
                  __| _/____   ___________ ___.__._______/  |_
                 / __ |/ __ \_/ ___\_  __ <   |  |\____ \   __\
                / /_/ \  ___/\  \___|  | \/\___  ||  |_> >  |
                \____ |\___  >\___  >__|   / ____||   __/|__|
                     \/    \/     \/       \/     |__|

                        Original author: Michael Zalewski <mjz@hexize.com>
                        New maintainer: Gareth Anderson
```

DECRYPT is a set of Splunk commands which provide encryption and
decryption routines commonly used in malware communication and data
exfiltration.

# SplunkBase
A vailable on SplunkBase as [DECRYPT2](https://splunkbase.splunk.com/app/5565)

# Installation
DECRYPT is a standard Splunk App and requires no special configuration.

# Usage
DECRYPT is implemented as a single search command which exposes a number of data manipulation functions. It takes the required field to manipulate and then one or more functions as arguments.

`Usage: decrypt [field=<name>] FUNCTIONS...`

The following example will transform the sourcetype field into its hex representation:

`... | decrypt field=sourcetype hex() emit('sourcetype')`

If the emit function is not mentioned, an `emit('decrypted')` is automatically added so the data is output

_Note: Fields must be output via the emit function. The input field is not modified in place._

# Arguments
## field
The field argument specifies the Splunk field to use as input.

`... | decrypt field="hostname" ...`
If no field argument is passed then _raw will be used by default.

_Note: If a field argument is passed and the field does not exist in the current record being processed, no error or warning will be given._

# FUNCTIONS
Each function passed as an argument will be executed in order, with the output of the previous function provided as input to the next.

`... | decrypt field=hostname b64 xor('s\x65cr\x65t') hex emit('decrypted')`
The above example can be explained as:

- Pass the value of the `hostname` field to `b64` as input
- Pass the output of `b64` to `xor` as input with the argument `'s\x65cr\x65t'`
- Pass the output of `xor` to `hex` as input
- Pass the output of `hex` to `emit` with the argument `'decrypted'`, creating a `decrypted` field

## Functions
### `btoa()`
- Encodes input to a Base64 string.

`b64(), atob()`
- Decodes a Base64 encoded string.

`b32()`
- Decodes a Base32 encoded string.

`b58()`
- Decodes a Base58 encoded string.

`rotx(count)`
- Implements Caesarian shift. The count argument specifies the amount to shift and must be an integer.

`rol(count)`
- Implements rotate-on-left to each character within the string using an 8 bit boundary. The count argument specifies the amount to rotate and must be an integer.

`ror(count)`
- Implements rotate-on-right to each character within the string using an 8 bit boundary. 
- The count argument specifies the amount to rotate and must be an integer.

`xor(key)`
- Implements basic XOR cipher against the field with the supplied key. 
- The key can be provided as a string or integer.

`rc4('key')`
- Implements the RC4 cipher against the field with the supplied key. 
- The key provided must be a string.

`hex()`
- Transforms input into its hexadecimal representation.

`unhex()`
- Transforms hexadecimal input into its byte form.

`save('name')`
- Saves the current state to memory as name.

`load('name')`
- Recalls the previously saved state name from memory.

`ascii()`
- Transforms input into ASCII output. Non-printable characters will be replaced with a period.

`emit('name')`
- Outputs the current state as UTF-8 to the field name.

`substr(offset, count)`
- Returns a substring of the input, starting at the index offset with the number of characters count. 
- Set the count to `'null'` to return from the start offset to the end of the input.

`slice(start, end)`
- Returns a slice of the input, starting at start offset to the end offset. 
- Set the end to `'null'` to go to the end of the input.

`decode('codec')`
- Returns a decoded version of the input based on the codec.
- Python codec list is available on https://docs.python.org/3/library/codecs.html#standard-encodings

`escape`
- Returns a string where control characters, \, and non-ASCII characters are backslash escaped (e.g. `\x0a`, `\\`, `\x80`).

`unescape`
- Returns a string run through python unicode_escape (i.e. return the unicode point(s)). Reverses `escape`. 
- Also unescapes Unicode codepoints (`\uxxxx` or `\Uxxxxxxxx`), which `escape` does not produce.

`htmlescape`
- Returns a string with `&`, `<`, and `>` XML escaped like `&amp;`.

`htmlunescape`
- Returns a string with HTML references like `&gt;` and `&#62;` unescaped to `>`.

`tr('from', 'to')`
- Takes an argument to translate "from" and an argument of characters to translate "to" and then returns a result with the result (similar to `tr` in Unix).

`rev()`
- Returns the input in reverse order.

`find('subseq', start)`
- Returns the index of a subsequence "subseq" starting at index "start", or `-1` if the subsequence is not found.

`b32re()`
- Returns a reverse-endian base32 decoded string, as used in the SunBurst DGA.

`b64re()`
- Returns a reverse-endian base64 decoded string.

`zlib_inflate()`
- Returns zlib.decompress() inflated bytes. 
- Default window size of -15 (raw inflate) is used if a wbits value is not provided.

`zlib_deflate()`
- Returns zlib.compress() deflated bytes. 
- Default level of -1 (currently 6) and window size of -15 (raw deflate) if values are not provided.

`entropy()`
- Returns base2 entropy of input. The maximum entropy for Unicode strings can be greater than 8.

_Note: you must use **single quotes** around the strings._

# Function Arguments
## Strings
Strings can be specified by encapsulating values in apostrophes (single quote). Strings accept Pythonic escape sequences, so hexadecimal and octal values can be specified with `\xhh` and `\ooo` respectively.
Unicode values can be expressed as `\u0000` or `\U00000000`

`'This is a valid string'`

`'This is also \x61 valid string.'`

Quotation marks (double quotes) **cannot** be used.

`"This is not a valid string"`

## Integers
Integers can be specified numerically or as hexadecimal representations by prefixing values with a 0x.

The value 256 could be passed as is or as its hexadecimal representation 0x100.

## Field References
The value of Splunk fields can be used in function parameters by passing the field name as an argument. All referenced fields must be complete words unbroken by whitespace.

`... | decrypt field=_raw xor(sourcetype) ...`
The above example demonstrates passing the sourcetype field as the key to the xor function.

Fields saved using the save command can also be referenced.

`... | decrypt field=_raw substr(0,1) save('1byte') substr(1, 4096) xor(1byte) ...`

## Style
Functions which take no arguments do not need parenthesis in order for syntax checking to pass. The following examples will pass syntax checks and execute the same.

`... | decrypt field=_raw b64 hex unhex`

`... | decrypt field=_raw b64() hex() unhex()`

`... | decrypt field=_raw b64() hex unhex`

New lines can be used to break up command sequences for easier readability.
```
... | decrypt field=_raw
      b64
      hex
      unhex
```
# Recipes
## XOR
`... | decrypt field=data xor('secret') emit('result')`
## ROT13 cipher
`... | decrypt field=data rotx(13) emit('result')`
## Base64 decode, XOR
`... | decrypt field=data b64 xor('secret') emit('result')`
## Base64 decode, XOR with first byte
```
... | decrypt field=data
      b64
      save('bin')
      substr(0, 1) emit('key')
      load('bin')
      substr(1, 9999) xor(key) emit('result')
```
## Brute force RC4
```
... | decrypt field=data
      b64
      save('orig') rc4('secret') emit('rc4-secret')
      load('orig') rc4('password') emit('rc4-password')
      load('orig') rc4('abc123') emit('rc4-abc123')
      load('orig') rc4('aabbccdd') emit('rc4-aabbccdd')
```
## Brute force XOR key
```
... | decrypt field=data
      b64
      save('data') xor(0x01) emit('xor0x01')
      load('data') xor(0x02) emit('xor0x02')
      load('data') xor(0x03) emit('xor0x03')
      ...
```
## Reverse the data field
`... | decrypt field=data rev`

## Find the index of a subsequence in a data field
`... | decrypt field=data find('subseq', 0)`

## Decrypt SunBurst DGA with reverse endian base32
`... | decrypt field=data tr('ph2eifo3n5utg1j8d94qrvbmk0sal76c', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567') b32re`

# Troubleshooting
Scenario - Email alert fails to trigger when a decrypted field is used in the results. Solution: In this case the base64 had special characters which were not rendered by the browser, when running the python b64decode the \x00 characters were visible, but in the Splunk UI it was completely invisible. Adding an ascii() into the decrypt2 arguments after the 64 resulted in the special characters just becoming "." symbols which are easily escaped with a rex mode=sed
Alternatively, using escape() you can see in the browser what it looks like.

# Contributors
Shannon Davis (Splunk)
Steven (malvidin on github)

# Release Notes
## 2.4.3
Updated splunk python SDK from 2.0.1 to 2.0.2 as per Splunk cloud compatibility requirements

## 2.4.2
Updated python SDK to 2.0.1

## 2.4.1
- Added support for null argument padding, so `find('decrypt2')` is equivalent to `find('decrypt2', 0)`
- Added zlib_deflate for internal validation of zlib_inflate, which can also be used for information analysis
- Add basic entropy calculation

## 2.4.0
Merged pull request from Steven (malvidin on github)

This new version includes:
- Removal of python2 support
- Cleanup code formatting
- Remove unused COMMA handling
- Add slice function

Note that 2.3.14 will be the last version of decrypt2 supporting python2

## 2.3.14
Merged pull request from Steven (malvidin on github)

This new version includes:
- Improved handling of negative integers
- Update so xor doesn't accept negative integers
- substr now accepts a null as count to return to end of string

## 2.3.13
Merged pull request from Steven (malvidin on github)

This new version includes:
- Added zlib_inflate function
- Updated Splunk python SDK to 1.7.3

## 2.3.12
Merged pull request from Steven (malvidin on github)

This new version includes:
- A fix to base58 to deal with empty input
- A setting for slice length and max length on base58

## 2.3.11
Merged pull request from Steven (malvidin on github)

This new version includes:
- New base58 decode function (b58)
- Updated python SDK to 1.7.2

## 2.3.10
Merged pull request from Steven (malvidin on github)

When Splunk sends a CSV that contains null bytes to Python 3.7, the CSV Reader error is not helpful
This update provides a warning to advise of the null character in the data (sed/rex/eval/replace can be used to remove the NUL character)

## 2.3.9
Updated Splunk python SDK to 1.6.20

## 2.3.8
Merged pull request from Steven (malvidin on github)

- New find function
- New b32re, and b64re functions that use the reverse endian decoding used by the SunBurst DGA

## 2.3.7
Merged pull request from Steven (malvidin on github)

- New rev function
- Decreased differences with python2

Updated Splunk python SDK to 1.6.19

## 2.3.6
Updated metdata file to include `sc_admin` role for Splunk Cloud

## 2.3.5
Merged pull request from Steven (malvidin on github)

- Escape ASCII control characters
- New functionality based on pull requests by Steven (malvidin) on GitHub

`htmlescape`
`htmlunescape`

_Note: `htmlescape` is not implemented for Python 2_

Updated Splunk python SDK to 1.6.18


## 2.3.4
- New functionality based on pull requests by Steven (malvidin) on GitHub

`decode`
`escape`
`unescape`
`tr`

## 2.3.3
- Minor update to license file
- The field `.decrypt_failure__` is not only output when there is an error (previously always output)
- If the emit function is omitted, the output now defaults to 'decrypted' as the field name

## 2.3.2
Fork of version 2.3.1 of DECRYPT app from SplunkBase (under MIT license)
- Updated python SDK to version 1.6.15
- default.meta file now includes read * and write to admin, power
- Created a README.md file

## 2.3.1
Feb. 16, 2021
- Bug fix for distributed search environments

## 2.3.0
- Unicode support
- Introduce ascii command
- Command change to SCPv2
- Changes to save/load command mechanics

## 2.2.1
- Bug fix and minor package metadata updates

## 2.2
- Addition of Base32 decoding
- Addition of Base64 decoding alias (b64)

## 2.1
- Works with Splunk 8.x
- Bug fix to work in distributed search environments

## 2.0
- Rearchitected due to a limitation with passing binary data between commands
- Introduced SAVE/LOAD/EMIT/HEX/UNHEX functions

## 1.0
- Initial release
