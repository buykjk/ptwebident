from dataclasses import dataclass


@dataclass
class NmapData:
    """
    Data class for Nmap OS scan results.
    """
    osName:  str | None
    osClass: str | None
    osFull:  str | None


@dataclass
class IconsData:
    """
    Data class for alias status code and icons hashes.
    """
    alias:         int | None
    apache_pb2gif: str | None
    poweredbypng:  str | None


@dataclass
class HeadersData:
    """
    Data class for HTTP response headers, including cookies.
    """
    all:          str | None
    server:       str | None
    x_powered_by: str | None
    x_generator:  str | None
    cookies:      str | None


@dataclass
class ReservedNamesData:
    """
    Data class for reserved names response codes
    """
    apacheht: int | None
    COM1:     int | None
    LPT1:     int | None
    AUX:      int | None


@dataclass
class LongSequencesData:
    """
    Data class for hashes of long requests response codes lists.
    """
    url20k:        str | None = None
    header20k:     str | None = None
    doubleHeaders: str | None = None


@dataclass
class ResponsePagesData:
    """
    Data class for response page hashes
    """
    r400: str | None = None
    r403: str | None = None
    r404: str | None = None
    r405: str | None = None
    r413: str | None = None
    r414: str | None = None
    r431: str | None = None
    r501: str | None = None
    r505: str | None = None


@dataclass
class AnalysisData:
    """
    Data class for all analysis data.
    """
    caseSensitive:     bool | None              = None
    fileExtension:     str | None               = None
    defaultPage:       str | None               = None
    headers:           HeadersData | None       = None
    icons:             IconsData | None         = None
    reservedNames:     ReservedNamesData | None = None
    longSequences:     LongSequencesData | None = None
    nmap:              NmapData | None          = None
    responsePages:     ResponsePagesData        = ResponsePagesData() # <head> section hashes
    responsePagesFull: ResponsePagesData        = ResponsePagesData() # full page hashes