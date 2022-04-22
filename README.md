                                                                               
                    .___                                  __                   
                  __| _/____   ___________ ___.__._______/  |_                 
                 / __ |/ __ \_/ ___\_  __ <   |  |\____ \   __\                
                / /_/ \  ___/\  \___|  | \/\___  ||  |_> >  |                  
                \____ |\___  >\___  >__|   / ____||   __/|__|                  
                     \/    \/     \/       \/     |__|v2.3.5                   
                                                                               
                        Original author: Michael Zalewski <mjz@hexize.com>     
                        New maintainer: Gareth Anderson                        
                                                                               

DECRYPT is a set of Splunk commands which provide encryption and
decryption routines commonly used in malware communication and data
exfiltration.

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
`btoa()`
Encodes input to a Base64 string.

`b64(), atob()`
Decodes a Base64 encoded string.

`b32()`
Decodes a Base32 encoded string.

`rotx(count)`
Implements Caesarian shift. The count argument specifies the amount to shift and must be an integer.

`rol(count)`
Implements rotate-on-left to each character within the string using an 8 bit boundary. The count argument specifies the amount to rotate and must be an integer.

`ror(count)`
Implements rotate-on-right to each character within the string using an 8 bit boundary. The count argument specifies the amount to rotate and must be an integer.

`xor(key)`
Implements basic XOR cipher against the field with the supplied key. The key can be provided as a string or integer.

`rc4('key')`
Implements the RC4 cipher against the field with the supplied key. The key provided must be a string.

`hex()`
Transforms input into its hexadecimal representation.

`unhex()`
Transforms hexadecimal input into its byte form.

`save('name')`
Saves the current state to memory as name.

`load('name')`
Recalls the previously saved state name from memory.

`ascii()`
Transforms input into ASCII output. Non-printable characters will be replaced with a period.

`emit('name')`
Outputs the current state as UTF-8 to the field name.

`substr(offset, count)`
Returns a substring of the input, starting at the index offset with the number of characters count.

`decode('codec')`
Returns a decoded version of the input based on the codec, python codec list is available on https://docs.python.org/3/library/codecs.html#standard-encodings

`escape`
Returns a string where control characters, \, and non-ASCII characters are backslash escaped (e.g. `\x0a`, `\\`, `\x80`).

`unescape`
Returns a string run through python unicode_escape (i.e. return the unicode point(s)). Reverses `escape`. Also unescapes Unicode codepoints (`\uxxxx` or `\Uxxxxxxxx`), which `escape` does not produce.

`htmlescape`
Returns a string with `&`, `<`, and `>` XML escaped like `&amp;`.

`htmlunescape`
Returns a string with HTML references like `&gt;` and `&#62;` unescaped to `>`.

`tr('from', 'to')`
Takes an argument to translate "from" and an argument of characters to translate "to" and then returns a result with the result (similar to `tr` in Unix).

_Note: you must use **single quotes** around the strings._

# Function Arguments
## Strings
Strings can be specified by encapsulating values in apostrophes (single quote). Strings accept Pythonic escape sequences, so hexadecimal and octal values can be specified with \xhh and \ooo respectively.

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

`... | decrypt field=_raw`
`      b64`
`      hex`
`      unhex`
# Recipes
## XOR
`... | decrypt field=data xor('secret') emit('result')`
## ROT13 cipher
`... | decrypt field=data rotx(13) emit('result')`
## Base64 decode, XOR
`... | decrypt field=data b64 xor('secret') emit('result')`
## Base64 decode, XOR with first byte
`... | decrypt field=data`
      `b64`
      `save('bin')`
      `substr(0, 1) emit('key')`
      `load('bin')`
      `substr(1, 9999) xor(key) emit('result')`
## Brute force RC4
`... | decrypt field=data`
      `b64`
      `save('orig') rc4('secret') emit('rc4-secret')`
      `load('orig') rc4('password') emit('rc4-password')`
      `load('orig') rc4('abc123') emit('rc4-abc123')`
      `load('orig') rc4('aabbccdd') emit('rc4-aabbccdd')`
## Brute force XOR key
`... | decrypt field=data`
      `b64`
      `save('data') xor(0x01) emit('xor0x01')`
      `load('data') xor(0x02) emit('xor0x02')`
      `load('data') xor(0x03) emit('xor0x03')`
      `...`
# Contributors
Shannon Davis (Splunk)
Steven (malvidin on github)

# Release Notes
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
