#!/usr/bin/python3

__version__ = "0.1.0"

import argparse
import ctypes
import os
import re
import sys
from enum import auto, Flag
from ptlibs import ptmisclib
from ptlibs.ptjsonlib import ptjsonlib

# Custom modules
from ptwebident.analysis import Analysis
from ptwebident.csvformat import DatasetLabel, append_results
from ptwebident.results_data import NmapData


# (Edited) regEx from https://github.com/django/django/blob/stable/1.3.x/django/core/validators.py#L45
urlRegEx = re.compile(
    r'^https?://' + # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' + #domain...
    r'localhost|' + #localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' + # ...or ip
    r'(?::\d+)?' + # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE
)


class IDMethod(Flag):
    """Identification methods configuration"""
    none             = 0
    chk_headers      = auto()
    chk_default_page = auto()
    chk_icons        = auto()
    chk_rsvd_names   = auto()
    chk_nonexistent  = auto()
    chk              = chk_headers | chk_default_page | chk_icons | chk_rsvd_names | chk_nonexistent
    det_case_sens    = auto()
    det_file_ext     = auto()
    det              = det_case_sens | det_file_ext
    bad_url          = auto()
    bad_method       = auto()
    bad_http_vsn     = auto()
    bad              = bad_url | bad_method | bad_http_vsn
    long_url         = auto()
    long_headers     = auto()
    long             = long_url | long_headers
    nmap_os          = auto()
    nmap             = nmap_os
    all              = chk | det | bad | long | nmap


class PtWebIdent:

    def __init__(self, args):
        """Process and clean arguments"""

        # Initialize JSON output data
        self.use_json: bool = args.json
        self.ptjsonlib = ptjsonlib(self.use_json)

        self.json_no = self.ptjsonlib.add_json('')
        self.ptjsonlib.json_list[self.json_no].pop('test_code', None)
        self.ptjsonlib.json_list[self.json_no] = {'testcode': 'ptwebident'} | self.ptjsonlib.json_list[self.json_no]

        # Validate URL
        if re.match(urlRegEx, args.url) is None:
            self.error(f'URL "{args.url}" is invalid')
        
        # Clean webroot URL
        self.url = '/'.join(str(args.url).split('/')[:3]) + '/'

        # Validate proxy
        if args.proxy is not None and re.match(urlRegEx, args.proxy) is None:
            self.error(f'Proxy "{args.proxy}" is invalid')

        # General options configuration
        self.probe: bool= args.probe
        self.proxy: str | None = args.proxy
        self.cookies: list[str] | None = args.cookies # ["name1=value1", "name2=value2", ...]
        self.headers: list[str] | None = args.headers # ["name1:value1", "name2:value2", ...]
        self.user_agent: str = args.user_agent
        self.ua_random: bool = args.ua_random
        self.delay: int | None = args.delay
        self.write: str | None = args.write
        self.write_header: bool = args.write_header

        # Identification methods configuration
        self.methods: IDMethod = (
            (IDMethod.chk_headers      if args.chk_headers      else IDMethod.none) |
            (IDMethod.chk_default_page if args.chk_default_page else IDMethod.none) |
            (IDMethod.chk_icons        if args.chk_icons        else IDMethod.none) |
            (IDMethod.chk_rsvd_names   if args.chk_rsvd_names   else IDMethod.none) |
            (IDMethod.chk_nonexistent  if args.chk_nonexistent  else IDMethod.none) |
            (IDMethod.chk              if args.chk              else IDMethod.none) |
            (IDMethod.det_case_sens    if args.det_case_sens    else IDMethod.none) |
            (IDMethod.det_file_ext     if args.det_file_ext     else IDMethod.none) |
            (IDMethod.det              if args.det              else IDMethod.none) |
            (IDMethod.bad_url          if args.bad_url          else IDMethod.none) |
            (IDMethod.bad_method       if args.bad_method       else IDMethod.none) |
            (IDMethod.bad_http_vsn     if args.bad_http_vsn     else IDMethod.none) |
            (IDMethod.bad              if args.bad              else IDMethod.none) |
            (IDMethod.long_url         if args.long_url         else IDMethod.none) |
            (IDMethod.long_headers     if args.long_headers     else IDMethod.none) |
            (IDMethod.long             if args.long             else IDMethod.none) |
            (IDMethod.nmap_os          if args.nmap_os          else IDMethod.none) |
            #(ID.nmap             if args.nmap             else ID.none) |
            (IDMethod.all              if args.all              else IDMethod.none)
        )

        # Methods selection check
        if self.methods is IDMethod.none:
            self.error("No identification method selected")

        # Need administrative privileges for Nmap OS scan
        if IDMethod.nmap_os in self.methods:
            admin: bool = False
            try:
                # Linux - root check
                admin = os.getuid() == 0
            except AttributeError:
                # Windows - Administrator check
                admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            
            if not admin:
                self.error("Nmap OS fingerprinting requires admin rights")


    def error(self, message: str) -> None:
        """Print error message and exit"""
        # Error output format = {'testcode': 'ptwebident', 'status': 'error', 'message': '...'}

        self.ptjsonlib.set_status(self.json_no, 'error', message)
        self.ptjsonlib.json_list[self.json_no].pop('data', None)
        self.ptjsonlib.json_list[self.json_no].pop('vulnerable', None)

        if self.use_json:
            print(self.ptjsonlib.get_json(self.json_no))
        else:
            print(f'Error: {message}')
        exit()


    def run(self) -> None:
        """Perform chosen identification methods and print results"""
        analysis = Analysis(self.url,
                            self.user_agent, self.ua_random,
                            self.proxy,
                            self.cookies,
                            self.headers,
                            self.delay,
                            self.probe,
                            self.error)

        # Collect analysis data using chosen identification methods

        if IDMethod.chk_headers in self.methods:
            analysis.chk_headers()

        if IDMethod.chk_default_page in self.methods:
            analysis.chk_default_page()

        if IDMethod.chk_icons in self.methods:
            analysis.chk_icons()

        if IDMethod.chk_rsvd_names in self.methods:
            analysis.chk_rsvd_names()

        if IDMethod.chk_nonexistent in self.methods:
            analysis.chk_nonexistent()

        if IDMethod.det_case_sens in self.methods:
            analysis.det_case_sens()

        if IDMethod.det_file_ext in self.methods:
            analysis.det_file_ext()

        if IDMethod.bad_url in self.methods:
            analysis.bad_url()

        if IDMethod.bad_method in self.methods:
            analysis.bad_method()

        if IDMethod.bad_http_vsn in self.methods:
            analysis.bad_http_vsn()

        if IDMethod.long_url in self.methods:
            analysis.long_url()

        if IDMethod.long_headers in self.methods:
            analysis.long_headers()

        if IDMethod.nmap_os in self.methods:
            analysis.nmap_os()

        # Identify technologies from analysed data
        identResults = analysis.identify()

        # Print results
        serverHeader = analysis.results.headers.server if analysis.results.headers is not None else None
        self.output(serverHeader, identResults, analysis.results.nmap)

        # Optionally write CSV results
        if self.write is not None:
            append_results(analysis.results, analysis.url, analysis.ip, self.write, self.write_header)


    def output(self, serverHeader: str | None, identification: dict[str, dict[str, float]], nmap: NmapData | None) -> None:
        """Print results - JSON or pretty format (depends on self.use_json)"""

        # Prepend application's Server header
        out = {'serverHeader': serverHeader} | identification

        if self.use_json:
            self.ptjsonlib.add_data(self.json_no, out)
            print(self.ptjsonlib.get_all_json())
        else:
            print(f'Server name contained in "Server" header: {serverHeader if serverHeader is not None else "---"}\n')

            server = out[DatasetLabel.server.name]
            progLang = out[DatasetLabel.progLang.name]
            os = out[DatasetLabel.os.name]
            print(f'Server name:\t\t{server if server is not None else "---"}')
            print(f'Programming language:\t{progLang if progLang is not None else "---"}')
            print(f'OS family:\t\t{os if os is not None else "---"}')

            print(f'Nmap OS guess:\t\t{nmap.osName if nmap is not None else "---"}')


def get_help():
    return [
        {"description": ["This tool attempts to identify the web server, the programming language and the operating system of a web application."]},
        {"usage": [f"{SCRIPTNAME} <options> <identification method>"]},
        {"usage_example": [
            f"{SCRIPTNAME} -u https://www.example.com --all",
        ]},
        {"options": [
            ["-u",  "--url",          "<url>",          "Test specified URL"],
            ["-d",  "--delay",        "<delay>",        "Delay between each HTTP request (milliseconds)"],
            ["-p",  "--proxy",        "<proxy>",        "Set proxy (e.g. http://127.0.0.1:8080)"],
            ["-c",  "--cookies",      "<cookie=value>", "Set cookie(s)"],
            ["-H",  "--headers",      "<header:value>", "Set custom header(s)"],
            ["-ua", "--user-agent",   "<user-agent>",   "Set user agent"],
            ["",    "--ua-random",    "",               "Use a random user agent"],
            ["",    "--probe",        "",               "Health-check before analysis"],
            ["-j",  "--json",         "",               "Output in JSON format"],
            ["",    "--write",        "<file>",         "Append CSV analysis data to a file"],
            ["",    "--write-header", "",               "Include CSV headers in file write (--write extension)"],
            ["-v",  "--version",      "",               "Show script version and exit"],
            ["-h",  "--help",         "",               "Show this help message and exit"]
        ]},
        {"identification_methods": [
            ["", "--all",              "", "All identification methods"],
            [],
            ["", "--chk",              "", "All --chk methods"],
            ["", "--chk-headers",      "", "Check response headers"],
            ["", "--chk-default-page", "", "Check web server's default page"],
            ["", "--chk-icons",        "", "Check presence of /icons folder and its contents"],
            ["", "--chk-rsvd-names",   "", "Check responses to reserved and special names"],
            ["", "--chk-nonexistent",  "", "Check response to a non-existent resource request"],
            [],
            ["", "--det",              "", "All --det methods"],
            ["", "--det-case-sens",    "", "Detect case sensitivity"],
            ["", "--det-file-ext",     "", "Detect file extension"],
            [],
            ["", "--bad",              "", "All --bad methods"],
            ["", "--bad-url",          "", "Illegal characters in URL"],
            ["", "--bad-method",       "", "Invalid HTTP request methods"],
            ["", "--bad-http-vsn",     "", "Invalid HTTP protocol version"],
            [],
            ["", "--long",             "", "All --long methods"],
            ["", "--long-url",         "", "Increasingly long URL"],
            ["", "--long-headers",     "", "Increasingly long headers"],
            [],
            #["", "--nmap",             "", "All --nmap methods"],
            ["", "--nmap-os",          "", "Nmap OS detection"]
        ]}]


def parse_args():
    """Process command line arguments"""
    parser = argparse.ArgumentParser(add_help=False, usage=f"{SCRIPTNAME} <modes> <options>")

    # Options
    parser.add_argument("-u",  "--url",        type=str)
    parser.add_argument("-d",  "--delay",      type=int)
    parser.add_argument("-p",  "--proxy",      type=str)
    parser.add_argument("-c",  "--cookies",    type=str, nargs="+")
    parser.add_argument("-H",  "--headers",    type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-ua", "--user-agent", type=str, default="Penterep Tools")
    parser.add_argument("--ua-random",         action="store_true")
    parser.add_argument("--probe",             action="store_true")
    parser.add_argument("-j",  "--json",       action="store_true")
    parser.add_argument("--write",             type=str)
    parser.add_argument("--write-header",      action="store_true")
    parser.add_argument("-v",  "--version",    action="version", version=f"%(prog)s {__version__}")

    # Identification methods
    parser.add_argument("--all",              action="store_true")

    parser.add_argument("--chk",              action="store_true")
    parser.add_argument("--chk-headers",      action="store_true")
    parser.add_argument("--chk-default-page", action="store_true")
    parser.add_argument("--chk-icons",        action="store_true")
    parser.add_argument("--chk-rsvd-names",   action="store_true")
    parser.add_argument("--chk-nonexistent",  action="store_true")

    parser.add_argument("--det",              action="store_true")
    parser.add_argument("--det-case-sens",    action="store_true")
    parser.add_argument("--det-file-ext",     action="store_true")

    parser.add_argument("--bad",              action="store_true")
    parser.add_argument("--bad-url",          action="store_true")
    parser.add_argument("--bad-method",       action="store_true")
    parser.add_argument("--bad-http-vsn",     action="store_true")

    parser.add_argument("--long",             action="store_true")
    parser.add_argument("--long-url",         action="store_true")
    parser.add_argument("--long-headers",     action="store_true")

    #parser.add_argument("--nmap",             action="store_true")
    parser.add_argument("--nmap-os",          action="store_true")

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptmisclib.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)
    args = parser.parse_args()

    ptmisclib.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptwebident"
    args = parse_args()

    script = PtWebIdent(args)
    script.run()


if __name__ == "__main__":
    main()
