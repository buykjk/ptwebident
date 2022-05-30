from dataclasses import dataclass, asdict
from enum import Enum

# Custom modules
from ptwebident.results_data import AnalysisData


class DatasetLabel(Enum):
    """Dataset label-column names"""
    # These labels have to match with dataset column names and CsvEntry fields

    server   = "serverNameLabel"
    progLang = "progLangLabel"
    os       = "osLabel"
    none     = None


@dataclass
class Labeled:
    """CSV field belonging to a DatasetLabel"""
    label: DatasetLabel
    value: str | None = None


@dataclass
class CsvEntry:
    """CSV form of AnalysisData (it's its flattened version)"""
    url:              Labeled = Labeled(DatasetLabel.none)
    ipAddr:           Labeled = Labeled(DatasetLabel.none)
    caseSensitive:    Labeled = Labeled(DatasetLabel.os)
    fileExtension:    Labeled = Labeled(DatasetLabel.progLang)
    defaultPage:      Labeled = Labeled(DatasetLabel.server)
    allHeaders:       Labeled = Labeled(DatasetLabel.server)
    serverHeader:     Labeled = Labeled(DatasetLabel.server)
    xPoweredByHeader: Labeled = Labeled(DatasetLabel.progLang)
    xGeneratorHeader: Labeled = Labeled(DatasetLabel.progLang)
    cookies:          Labeled = Labeled(DatasetLabel.progLang)
    iconsAlias:       Labeled = Labeled(DatasetLabel.server)
    apache_pb2gif:    Labeled = Labeled(DatasetLabel.server)
    poweredbypng:     Labeled = Labeled(DatasetLabel.os)
    apacheht:         Labeled = Labeled(DatasetLabel.server)
    COM1:             Labeled = Labeled(DatasetLabel.os)
    LPT1:             Labeled = Labeled(DatasetLabel.os)
    AUX:              Labeled = Labeled(DatasetLabel.os)
    url20k:           Labeled = Labeled(DatasetLabel.server)
    header20k:        Labeled = Labeled(DatasetLabel.server)
    doubleHeaders:    Labeled = Labeled(DatasetLabel.server)
    nmapOsName:       Labeled = Labeled(DatasetLabel.os)
    nmapOsClass:      Labeled = Labeled(DatasetLabel.os)
    nmapOsFull:       Labeled = Labeled(DatasetLabel.os)
    r400:             Labeled = Labeled(DatasetLabel.server)
    r403:             Labeled = Labeled(DatasetLabel.server)
    r404:             Labeled = Labeled(DatasetLabel.server)
    r405:             Labeled = Labeled(DatasetLabel.server)
    r413:             Labeled = Labeled(DatasetLabel.server)
    r414:             Labeled = Labeled(DatasetLabel.server)
    r431:             Labeled = Labeled(DatasetLabel.server)
    r501:             Labeled = Labeled(DatasetLabel.server)
    r505:             Labeled = Labeled(DatasetLabel.server)
    r400F:            Labeled = Labeled(DatasetLabel.server)
    r403F:            Labeled = Labeled(DatasetLabel.server)
    r404F:            Labeled = Labeled(DatasetLabel.server)
    r405F:            Labeled = Labeled(DatasetLabel.server)
    r413F:            Labeled = Labeled(DatasetLabel.server)
    r414F:            Labeled = Labeled(DatasetLabel.server)
    r431F:            Labeled = Labeled(DatasetLabel.server)
    r501F:            Labeled = Labeled(DatasetLabel.server)
    r505F:            Labeled = Labeled(DatasetLabel.server)
    serverNameLabel:  Labeled = Labeled(DatasetLabel.none)
    progLangLabel:    Labeled = Labeled(DatasetLabel.none)
    osLabel:          Labeled = Labeled(DatasetLabel.none)


def analysisToCsv(r: AnalysisData, url: str | None = None, ip: str | None = None) -> CsvEntry:
    """Convert AnalysisData to CsvEntry"""
    e = CsvEntry()

    e.url.value = url
    e.ipAddr.value = ip

    # Prevent 'None' string from being placed into the entry
    if r.caseSensitive is not None:
        e.caseSensitive.value = str(r.caseSensitive)

    e.fileExtension.value = r.fileExtension
    e.defaultPage.value = r.defaultPage

    if r.headers is not None:
        e.allHeaders.value = r.headers.all
        e.serverHeader.value = r.headers.server
        e.xPoweredByHeader.value = r.headers.x_powered_by
        e.xGeneratorHeader.value = r.headers.x_generator
        e.cookies.value = r.headers.cookies

    if r.icons is not None:
        e.iconsAlias.value = str(r.icons.alias)
        e.apache_pb2gif.value = r.icons.apache_pb2gif
        e.poweredbypng.value = r.icons.poweredbypng

    if r.reservedNames is not None:
        e.apacheht.value = str(r.reservedNames.apacheht)
        e.COM1.value = str(r.reservedNames.COM1)
        e.LPT1.value = str(r.reservedNames.LPT1)
        e.AUX.value = str(r.reservedNames.AUX)

    if r.longSequences is not None:
        e.url20k.value = r.longSequences.url20k
        e.header20k.value = r.longSequences.header20k
        e.doubleHeaders.value = r.longSequences.doubleHeaders

    if r.nmap is not None:
        e.nmapOsName.value = r.nmap.osName
        e.nmapOsClass.value = r.nmap.osClass
        e.nmapOsFull.value = r.nmap.osFull

    e.r400.value = r.responsePages.r400
    e.r403.value = r.responsePages.r403
    e.r404.value = r.responsePages.r404
    e.r405.value = r.responsePages.r405
    e.r413.value = r.responsePages.r413
    e.r414.value = r.responsePages.r414
    e.r431.value = r.responsePages.r431
    e.r501.value = r.responsePages.r501
    e.r505.value = r.responsePages.r505
    e.r400F.value = r.responsePagesFull.r400
    e.r403F.value = r.responsePagesFull.r403
    e.r404F.value = r.responsePagesFull.r404
    e.r405F.value = r.responsePagesFull.r405
    e.r413F.value = r.responsePagesFull.r413
    e.r414F.value = r.responsePagesFull.r414
    e.r431F.value = r.responsePagesFull.r431
    e.r501F.value = r.responsePagesFull.r501
    e.r505F.value = r.responsePagesFull.r505

    return e


def append_results(results: AnalysisData, url: str, ip: str,
                   filename: str, header: bool, csv_separator: str = ';') -> None:
    """Append analysis results to a CSV file"""
    with open(filename, 'a', encoding='UTF8', newline='') as f:

        # Convert AnalysisData to CsvEntry dictionary
        dictResults = asdict(analysisToCsv(results, url, ip))

        # Gather field values
        values = [x['value'] for x in dictResults.values()]

        # Substitute None with '' for file output
        not_none = [v if v is not None else '' for v in values]

        # Optionally write header
        if header:
            f.write(csv_separator.join(dictResults.keys()) + '\n')

        # Write row
        f.write(csv_separator.join(not_none) + '\n')