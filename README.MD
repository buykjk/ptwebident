```
 ____            _                        _____           _     
|  _ \ ___ _ __ | |_ ___ _ __ ___ _ __   |_   _|__   ___ | |___ 
| |_) / _ \ '_ \| __/ _ \ '__/ _ \ '_ \    | |/ _ \ / _ \| / __|
|  __/  __/ | | | ||  __/ | |  __/ |_) |   | | (_) | (_) | \__ \
|_|   \___|_| |_|\__\___|_|  \___| .__/    |_|\___/ \___/|_|___/
                                 |_|
```

# ptwebident

This tool identifies the technologies used in a web application
(operating system, web server, programming language).
It is a part of the Penterep platform.

## Installation

```
$ git clone https://github.com/buykjk/ptwebident.git
$ cd ptwebident && sudo pip install .
```

This tools uses Nmap to perform OS detection scanning.
To use this functionality, Nmap has to be installed.

## Options

### General

```
-u  --url           <url>           Test specified URL
-d  --delay         <delay>         Delay between each HTTP request (milliseconds)
-p  --proxy         <proxy>         Set proxy (e.g. http://127.0.0.1:8080)
-c  --cookies       <cookie=value>  Set cookie(s)
-H  --headers       <header:value>  Set custom header(s)
-ua --user-agent    <user-agent>    Set user agent
    --ua-random                     Use a random user agent
    --probe                         Health-check before analysis
-j  --json                          Output in JSON format
    --write         <file>          Append CSV analysis data to a file
    --write-header                  Include CSV headers in file write (--write extension)
-v  --version                       Show script version and exit
-h  --help                          Show help message and exit
```

### Identification methods

--all               All identification methods

--chk               All --chk methods
--chk-headers       Check response headers
--chk-default-page  Check web server's default page
--chk-icons         Check presence of /icons folder and its contents
--chk-rsvd-names    Check responses to reserved and special names
--chk-nonexistent   Check response to a non-existent resource request

--det               All --det methods
--det-case-sens     Detect case sensitivity
--det-file-ext      Detect file extension

--bad               All --bad methods
--bad-url           Illegal characters in URL
--bad-method        Invalid HTTP request methods
--bad-http-vsn      Invalid HTTP protocol version

--long              All --long methods
--long-url          Increasingly long URL
--long-headers      Increasingly long headers

--nmap-os           Nmap OS detection

## Usage examples

```
$ sudo ptwebident -u http://example.com/ --all
$ ptwebident -u http://example.com:8080/ --det -j
$ ptwebident -u http://example.com/ --chk --bad --long
$ ptwebident -u http://example.com/ --chk-headers --proxy http://127.0.0.1:8080
$ sudo ptwebident -u http://example.com/ --nmap-os
$ sudo ptwebident -u http://example.com/ --all --write output.csv --write-header
```

## Version History

* 0.1 - first public release as a bachelor thesis project

## Licence

Copyright (c) 2020 HACKER Consulting s.r.o.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.