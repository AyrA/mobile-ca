# mobile-ca
Mobile Certificate Authority

This is a mobile certificate authority written in C#.
It works portable and can be used from console as well as a web service.

## Features

- Can be used from command line or from windows explorer. It detects and acts accordingly
- Integrated Webserver for a graphical user interface.
- Import and export certificates in/out of the local certificate store
- Will automatically launch Webserver if not used as command line application

## Portability

The utility is self contained and can be copied/moved freely.
We recommend that the "Data" directory is kept too,
otherwise you lose acces to the generated keys and certificates.

## Installation

There is no installation per se.
This application depends on OpenSSL.
If the binaries are not present, it will download them and exit.

## Quick Start

1. Double click to start the web service
2. Press the [ESC] key in the console once you are done

## Command Line mode

For the complete command line reference, run `mobile-ca /?`.

## Web Server

To start the webserver, double click on `mobile-ca`.
If you run it from the command line you need to specify arguments.
Example: `/http 55555 /b`

Click on `?` in the top right corner to get instructions

# Licenses

This utility depends on 3rd party components in order to properly work.
Below is a list of components, when they are used and their License.

- OpenSSL (Command Line + HTTP); [License (Custom)](https://www.openssl.org/source/license.html)
- JSON.NET (HTTP); [License (MIT)](https://github.com/JamesNK/Newtonsoft.Json/blob/master/LICENSE.md)
- Bootstrap (HTTP); [License (MIT)](https://github.com/twbs/bootstrap/blob/v4-dev/LICENSE)
- jQuery (HTTP); [License (MIT)](https://github.com/jquery/jquery/blob/master/LICENSE.txt)
- popper.js (HTTP); [License (MIT)](https://github.com/FezVrasta/popper.js/blob/master/LICENSE.md)
