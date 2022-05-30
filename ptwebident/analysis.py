import dataclasses
import nmap3
import pandas as pd
import pathlib
import random
import re
import requests as r
import socket
import time
from http.client import HTTPConnection
from typing import Callable

# Custom modules
from ptwebident.csvformat import DatasetLabel, Labeled, analysisToCsv
from ptwebident.results_data import (
    AnalysisData,
    HeadersData,
    IconsData,
    ReservedNamesData,
    NmapData,
    LongSequencesData
)
from ptwebident.urlattributes_htmlparser import URLAttributesHTMLParser
from ptwebident.utils import hash_bytes, random_number, random_string


class Analysis:
    """Web application analysis"""

    #region Constants

    # Composed from many sources, not ideal
    _static_extensions = re.compile(r'\.(' +
        r'jpg|jpeg|jpe|jif|jfif|jfi|pjpeg|pjp' +
        r'|png|apng|webp|svg|svgz|avif|avifs' +
        r'|gif|jxl|jp2|j2c|j2k|jpx|jpf|bmp|dib' +
        r'|crw|cr2|raw|rw2|nef|nrw|orf|tiff|tif' +
        r'|eps|epsi|epsf|heif|heifs' +
        r'|pct|pict|pic|pcx|pdf|psd|pdd' +
        r'|tga|wmf|emf|wmz|emz|ico|cur' +
        r'|mp4|mp3|avi|mov|wmv|flv|f4v|swf|mkv|webm' +
        r'|txt' +
    r')$')

    # Top 15 from https://techblog.willshouse.com/2012/01/03/most-common-user-agents/
    _user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36'
    ]

    #endregion Constants


    def __init__(self, url: str,
                 ua: str, ua_random: bool,
                 proxy: str | None,
                 cookies: list[str] | None,
                 headers: list[str] | None,
                 delay: int | None,
                 probe: bool,
                 error: Callable[[str], None]) -> None:
        """Analysis configuration"""

        self.url = url
        self._domain = url.split('/')[2].split(':')[0]
        self.ip = socket.gethostbyname(self._domain)

        # Delay in milliseconds
        self._delay = delay / 1000 if delay is not None else None

        # Initiate delay timer (used later if delay is not None)
        self._delay_last = time.perf_counter()

        # Proxy
        self._proxy: dict[str, str] | None = None
        if proxy is not None:
            proxy_ = proxy.split('/')[2]
            self._proxy = {'http': proxy_, 'https': proxy_}

        # User-agent + headers
        ua_ = ua if not ua_random else random.choice(self._user_agents)
        self._headers: dict[str, str] = {'User-Agent': ua_}
        if headers is not None:
            for header in headers:
                header_ = header.split(':')
                self._headers[header_[0]] = header_[1]

        # Cookies
        self._cookies: dict[str, str] | None = None
        if cookies is not None:
            self._cookies = {}
            for cookie in cookies:
                cookie_ = cookie.split('=')
                self._cookies[cookie_[0]] = cookie_[1]

        # Instantiate empty results
        self.results = AnalysisData()

        # Disable urllib3 security checks
        ## Disable SSL/TLS warnings
        r.urllib3.disable_warnings()

        ## Do not url encode these characters
        r.urllib3.util.url.PATH_CHARS.add('%')
        
        ## Never match a request method as illegal (invalid regex - will never match)
        r.urllib3.connection._CONTAINS_CONTROL_CHAR_RE = re.compile(r"$a")

        # Health-check
        if probe and self._request(self.url) is None:
            error(f"'{self.url}' does not respond")


    #region Chk methods

    def chk_headers(self) -> None:
        """Check response headers (on the webroot), including cookies"""

        res = self._request(self.url)

        if res is None:
            return

        # Response headers
        headers_list = list(res.headers.keys())
        all = hash_bytes(str(headers_list).encode())
        server = res.headers.get('server')
        x_powered_by = res.headers.get('x-powered-by')
        x_generator = res.headers.get('x-generator')

        # Set-cookie cookies
        cookies: str | None = None

        if res.cookies:
            cookiesList: list[str] = res.cookies.keys()
            cookiesHash = hash_bytes(str(cookiesList).encode())
            
            cookies = cookiesHash
        
        self.results.headers = HeadersData(
            all=all,
            server=server,
            x_powered_by=x_powered_by,
            x_generator=x_generator,
            cookies=cookies
        )


    def chk_default_page(self) -> None:
        """Attempt to inspect the default welcome page"""

        res = self._request(url=self.url, headers={'Host': self.ip})

        if res is not None and res.status_code == 200:
            self.results.defaultPage = hash_bytes(res.content)
            return

        # Default page check failed
        self.results.defaultPage = None


    def chk_icons(self) -> None:
        """Check response codes to known icons"""

        icons_path = self.url + 'icons/'

        # Icons alias
        res = self._request(icons_path)

        alias = res.status_code if res is not None else None

        # Whether to check specific images
        checkIcons: bool = alias is not None
        # Does '200' /icons have "Index of" title?
        if alias == 200 and res is not None:
            titleMatch = re.search(br'(?:<title>)(.*)(?:</title>)', res.content, flags=re.DOTALL)

            # No title at all
            if titleMatch is None:
                checkIcons = False
            else:
                # Title is not 'Index of'
                if re.match(br'^Index of', titleMatch[1], re.IGNORECASE) is None:
                    checkIcons = False

        # Specific icons
        apache_pb2: str | None = None
        poweredby: str | None = None

        if checkIcons:
            apache_pb2 = self._try_hash_resource(icons_path + 'apache_pb2.gif')
            poweredby = self._try_hash_resource(icons_path + 'poweredby.png')
        
        self.results.icons = IconsData(
            alias=alias,
            apache_pb2gif=apache_pb2,
            poweredbypng=poweredby
        )


    def _try_hash_resource(self, path: str, code: int | None = None) -> str | None:
        """Try to get a hash of a given resource"""

        res = self._request(path)
        if res is not None and res.status_code == 200:
            return hash_bytes(res.content)
        else:
            return None


    def chk_rsvd_names(self) -> None:
        """Check responses to known reserved resource names"""

        # Apache specific
        apacheht = self._try_status_code(self.url + '.htaccess')

        # Windows specific
        com1 = self._try_status_code(self.url + 'COM1')
        lpt1 = self._try_status_code(self.url + 'LPT1')
        aux = self._try_status_code(self.url + 'AUX')

        self.results.reservedNames = ReservedNamesData(
            apacheht=apacheht,
            COM1=com1,
            LPT1=lpt1,
            AUX=aux
        )


    def _try_status_code(self, path: str) -> int | None:
        """Try to get the status code of a given resource"""

        res = self._request(path)
        if res is not None:
            return res.status_code
        else:
            return None


    def chk_nonexistent(self) -> None:
        """Check application's response to a random non-existent resource"""
        
        # 5 attempts to make sure a nonexistent resource is generated
        for _ in range(1, 5):
            self._request(self.url + random_string())

    #endregion Chk methods

    #region Det methods

    def det_case_sens(self) -> None:
        """Detect application's case sensitivity"""

        # First try favicon.ico, if it's not present, parse all URL links from HTML
        favicon = self._url_case_sens(self.url + 'favicon.ico')

        if favicon is not None:
            self.results.caseSensitive = favicon
            return

        # Check if application is responding
        res = self._request(self.url)

        if res is None:
            self.results.caseSensitive = None
            return

        # Extract URLs from HTML attributes
        parser = URLAttributesHTMLParser()
        parser.feed(res.text)

        # Clean the parsed URLs
        # using Sets to keep only unique links
        links: set[str] = set()

        for link in parser.urls_found:
            # Remove parameters and URI fragments
            link = link.split('?')[0]
            link = link.split('#')[0]

            # Non-empty after fragment filter
            if len(link) != 0:
                link_lower = link.lower()

                # http/s or protocol relative URLs ('//')
                if link_lower.startswith("http") or link_lower.startswith("//"):
                    # Same domain (excluding subdomains)
                    if self._domain.lower() == link_lower.split('/')[2]:
                        links.add(link)
                # Relative links, that are not webroot ('/')
                elif ':' not in link and re.match(r'^/+$', link) is None:
                    links.add(link)

        # Filter links that reference a specific resource (not just the webroot)
        resources = {link for link in links if re.match(r'^https?://[^/]+/?$', link) is None}

        # Filter non-directory resources
        resources_non_dir = {resource for resource in resources if resource[-1] != '/'}

        # Filter files that have an extension
        files_ext = {non_dir for non_dir in resources_non_dir if re.search(r'\.[^/\.]+$', non_dir)}

        # Filter images and other static resources - best resources for case-sensitivity detection
        files_ext_static = {file for file in files_ext if self._static_extensions.search(file)}

        # Differentiate remaining groups of links
        files_ext_notstatic = files_ext - files_ext_static
        files_noext = resources_non_dir - files_ext
        directories = resources - resources_non_dir

        # Iterate over links - files with static file extension (e.g. jpg) are
        # most reliable for case sensitivity detection
        for links_list in [files_ext_static, files_ext_notstatic, files_noext, directories]:
            for link in links_list:

                # Construct URL
                url = link if link.startswith('http') else self.url + link

                # Check URL's case sensitivity
                sens = self._url_case_sens(url)

                if sens is not None:
                    self.results.caseSensitive = sens
                    return
    
        # Case sensitivity check failed
        self.results.caseSensitive = None


    def _url_case_sens(self, url: str) -> bool | None:
        """Check case sensitivity of a given url"""

        res = self._request(url)
        # Nonexistent resource - skip
        if res is None or res.status_code == 404:
            return None

        # Swap all character cases
        res_swapAll = self._request(url.swapcase())
        # No response for swapped case -> sensitive
        if res_swapAll is None:
            return True

        # Swap last character case
        lastCharSwapped = url[:len(url)-1] + url[-1].swapcase()
        res_swapLast = self._request(lastCharSwapped)
        # No response for swapped case -> sensitive
        if res_swapLast is None:
            return True

        codes = [res.status_code, res_swapAll.status_code, res_swapLast.status_code]
        res_contents = [res.content, res_swapAll.content, res_swapLast.content]

        codes_same = all(code == codes[0] for code in codes)
        contents_same = all(content == res_contents[0] for content in res_contents)

        if not codes_same or not contents_same:
            return True
        else:
            return False


    def det_file_ext(self) -> None:
        """Attempt to find the file extension of the application's source code files"""

        # Can't determine the file extension, if the server yields the home page as a fallback
        res_root = self._request(self.url)
        res_random = self._request(self.url + random_string())

        if res_root is None or res_random is None:
            self.results.fileExtension = None
            return

        if res_root.status_code == res_random.status_code:
            self.results.fileExtension = None
            return

        # Some files I thought could be common
        # Inspired byhttps://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-small-files.txt
        common_files = ['index', 'default', 'home', 'search', 'login', 'register', 'admin', 'download', 'upload', 'contact_us', 'faq']

        # Edited https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/extensions-most-common.fuzz.txt
        common_extensions = ['asp', 'aspx', 'php', 'php3', 'php4', 'php5', 'shtm', 'shtml', 'phtm', 'phtml', 'jhtml', 'jsp', 'cfm', 'cfml']

        # Try all combinations of common filenames and extensions
        for file in common_files:
            for ext in common_extensions:
                filename = file + "." + ext
                res = self._request(self.url + filename)

                if res is not None and res.status_code != 404:
                    self.results.fileExtension = ext
                    return
        
        # File extension check failed
        self.results.fileExtension = None

    #endregion Det methods

    #region Bad methods

    def bad_url(self) -> None:
        """Attempt to cause an error page using illegal characters in URL"""

        bad_strings = ['%%', '%00']

        for bad in bad_strings:
            self._request(self.url + bad)


    def bad_method(self) -> None:
        """Attempt to cause an error using an invalid/unsupported HTTP method"""
        methods = ['zxcvbn', '1234', '}{', 'TRACE', 'CONNECT', 'DELETE', 'PUT', 'HEAD', 'OPTIONS', 'POST', 'GET']
        
        # Random long resource name, so methods like DELETE won't cause any harm
        rand = random_string(16)

        for m in methods:
            self._request(url=self.url+rand, method=m)


    def bad_http_vsn(self) -> None:
        """Attempt to cause an error using an invalid HTTP protocol version"""
        http_vsn_str_original = HTTPConnection._http_vsn_str
        HTTPConnection._http_vsn_str = f'HTTP/{random_number()}'

        self._request(self.url)
        
        HTTPConnection._http_vsn_str = http_vsn_str_original

    #endregion Bad methods

    #region Long methods

    def long_url(self) -> None:
        """Inspect responses to long URLs"""

        # Sequence of response codes
        url20k_codes: list[int | None] = []

        for i in range(1, 20):
            res = self._request(self.url + "A" * (i * 1000 + 1))

            if res is not None:
                url20k_codes.append(res.status_code)
            else:
                url20k_codes.append(None)

        url20k = hash_bytes(str(url20k_codes).encode())

        if self.results.longSequences is None:
            self.results.longSequences = LongSequencesData()

        self.results.longSequences.url20k = url20k

        # Ultra long URLs - attempt to trigger more error pages
        for i in range(5, 10):
            self._request(self.url + "A" * (i * 10000 + 1))


    def long_headers(self) -> None:
        """Inspect responses to long request headers"""

        # Sequence of response codes for a single long header
        header20k_codes: list[int | None] = []
        
        # First error length of a single header
        # fallback value in case no error is encountered in the first header loop (10 to match half of the first loop)
        firstErrLen = 10

        # First response code to determine when the response codes change
        firstCode = 0

        for i in range(1, 20):
            res = self._request(url=self.url, headers={random_string(): "A" * (i * 1000 + 1)})

            if res is None:
                header20k_codes.append(None)
                continue

            if firstCode == 0:
                firstCode = res.status_code
            elif firstCode != res.status_code:
                firstErrLen = i

            header20k_codes.append(res.status_code)
        
        header20k = hash_bytes(str(header20k_codes).encode())

        # Sequence of response codes for two long headers
        doubleHeaders_codes: list[int | None] = []

        # Match the error length of a single header
        for i in range(1, firstErrLen):
            res = self._request(url=self.url,
                                headers={
                                    random_string(): "A" * (i * 500 + 1),
                                    random_string(): "B" * (i * 500)
                                })

            if res is None:
                doubleHeaders_codes.append(None)
                continue

            doubleHeaders_codes.append(res.status_code)

        doubleHeaders = hash_bytes(str(doubleHeaders_codes).encode())

        if self.results.longSequences is None:
            self.results.longSequences = LongSequencesData()

        self.results.longSequences.header20k = header20k
        self.results.longSequences.doubleHeaders = doubleHeaders

    #endregion Long methods

    #region Nmap methods

    def nmap_os(self) -> None:
        """Perform Nmap OS detection scan"""

        nmap = nmap3.Nmap()
        nmap_out = nmap.nmap_os_detection(self.ip)

        try:
            osMatch = nmap_out[self.ip]['osmatch']
        except KeyError:
            osMatch = None
        
        if osMatch:
            osName = osMatch[0].get('name')
            osClass = osMatch[0].get('osclass')
        else:
            osName = None
            osClass = None
        
        self.results.nmap = NmapData(
            osName=osName,
            osClass=hash_bytes(str(osClass).encode('utf-8')),
            osFull=hash_bytes(str(osMatch).encode('utf-8'))
        )

    #endregion Nmap methods

    #region request processing

    def _request(self, url: str, method: str = 'GET', headers: dict[str, str] | None = None) -> r.Response | None:
        """Python Requests' wrapper to catch exceptions, call _process_response() and apply delay"""

        # Apply optional delay
        if self._delay is not None:
            elapsed = time.perf_counter() - self._delay_last

            if elapsed < self._delay:
                time.sleep(self._delay - elapsed)
            
            self._delay_last = time.perf_counter()

        # Append specific headers
        if headers is not None:
            headers_ = self._headers | headers
        else:
            headers_ = self._headers

        try:
            res = r.request(method=method, url=url,
                            headers=headers_, cookies=self._cookies,
                            proxies=self._proxy, verify=False)
            
            # Process every response
            self._process_response(res)
        except r.RequestException:
            res = None

        return res


    def _process_response(self, res: r.Response) -> None:
        """Save response hash if it's a new response code"""

        # Save hash if it's not 200 response, and if it's the first occurence of such status code
        if (res.status_code != 200
            and hasattr(self.results.responsePages, f'r{res.status_code}')
            and getattr(self.results.responsePages, f'r{res.status_code}') is None):

            # RegEx match reflected URL path
            path = '/'.join(res.url.split('/')[3:]) # "http://example.com/reflected_path" -> "/reflected_path"
            pathPattern = re.compile(re.escape(path.encode('utf-8')), re.IGNORECASE)
            
            # Remove reflected URL path
            resCleaned = pathPattern.sub(b'', res.content)

            # Hash the whole page
            setattr(self.results.responsePagesFull, f'r{res.status_code}', hash_bytes(resCleaned))

            # Hash the <head> section
            headSection = re.search(br'<head>.*</head>', resCleaned, flags=re.DOTALL)

            if headSection:
                setattr(self.results.responsePages, f'r{res.status_code}', hash_bytes(headSection[0]))

    #region request processing

    def identify(self, filename: str = 'default', csv_separator: str = ';') -> dict[str, dict[str, float]]:
        """Identify target's technologies using analysis data and an identification dataset"""

        # Default dataset path
        if filename == 'default':
            # Get dataset.csv file which is in the same directory as this source code
            filename = str(pathlib.Path(__file__).parent.resolve().joinpath('dataset.csv'))

        # Convert AnalysisData to CsvEntry
        csvResults = analysisToCsv(self.results)

        # Read dataset as pandas.DataFrame
        dataset = pd.read_csv(filename, sep=csv_separator)

        # Matches for each dataset label
        matches: dict[DatasetLabel, dict[str, int]] = {
            DatasetLabel.server:   {},
            DatasetLabel.progLang: {},
            DatasetLabel.os:       {}
        }

        # Iterate over results' fields, skip first 2 (url, ipAddr) and last 3 (labels)
        fields = dataclasses.fields(csvResults)
        for i in range(2, len(fields) - 3):

            element: Labeled = getattr(csvResults, fields[i].name)

            # Skip empty fields
            if element.value is None:
                continue

            # Filter dataset rows that match the current column
            filter = [str(row) == element.value for row in dataset.iloc[:, i]]
            filtered_dataset: pd.DataFrame = dataset[filter]

            if not filtered_dataset.empty:
                # Count occurences of corresponding labels
                match = matches[element.label]

                for value, count in filtered_dataset[element.label.value].value_counts().iteritems():
                    if match.get(value) is None:
                        match[value] = count
                    else:
                        match[value] += count

        # Total matches for each label (for percentage calculation)
        sums: dict[DatasetLabel, int] = {
            DatasetLabel.server:   0,
            DatasetLabel.progLang: 0,
            DatasetLabel.os:       0
        }

        # Percentages for each matched technology in each label
        outs: dict[str, dict[str, float] | None] = {
            DatasetLabel.server.name:   None,
            DatasetLabel.progLang.name: None,
            DatasetLabel.os.name:       None
        }

        # Do the calculations for each label
        for dictKey in matches:
            match = matches[dictKey]

            # Sum number of matches
            for key in match:
                sums[dictKey] += match[key]

            # Calculate percentages for top 3 matches
            if len(match) != 0:
                outs[dictKey.name] = {}
                for key, value in sorted(match.items(), key=lambda item: item[1], reverse=True)[:3]:
                    outs[dictKey.name][key] = round((value / sums[dictKey]), 2)

        return outs