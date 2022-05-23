```
 ____            _                        _____           _     
|  _ \ ___ _ __ | |_ ___ _ __ ___ _ __   |_   _|__   ___ | |___ 
| |_) / _ \ '_ \| __/ _ \ '__/ _ \ '_ \    | |/ _ \ / _ \| / __|
|  __/  __/ | | | ||  __/ | |  __/ |_) |   | | (_) | (_) | \__ \
|_|   \___|_| |_|\__\___|_|  \___| .__/    |_|\___/ \___/|_|___/
                                 |_|
```

# scriptname

## Installation

```
$ git clone scriptname
$ cd scriptname && sudo pip install .
```

## Installation (ptmanager) 

```
$ sudo ptmanager -ut scriptname
```

## Options
```
-u   --url         <url>           Connect to URL
-c   --cookie      <cookie>        Set cookie
-H   --headers     <header:value>  Set custom headers
-ua  --user-agent  <user-agent>    Set user agent
-j   --json                        Enable JSON output
-v   --version                     Show script version and exit
-h   --help                        Show this help message and exit
```

## Usage examples
```
$ scriptname -u example.com
$ scriptname -f domain_list.txt
```

## Version History

* 0.1.0

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
