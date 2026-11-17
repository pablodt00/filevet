import zipfile
import zlib
from xml.etree.ElementTree import ParseError

from defusedxml import DefusedXmlException

ZIP_ERRORS = (zipfile.BadZipFile, OSError, EOFError, RuntimeError, NotImplementedError, zlib.error)
XML_ERRORS = (ParseError, DefusedXmlException, LookupError)


class ScanError(Exception):
    pass
