#!/


import hashlib
import time
import binascii
import string
import os, sys

import utilities

try:
    import bs4
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False

try:
    import magic
    HAVE_MAGIC = True
except ImportError:
    HAVE_MAGIC = False

try:
    import pefile
    import peutils
    HAVE_PEFILE = True
except ImportError:

    
    HAVE_PEFILE = False


try:
    from macholib.MachO import MachO
    from macholib.mach_o import *
    from macholib.ptypes import *
    from macholib.SymbolTable import SymbolTable
    HAVE_MACHOLIB = True
except ImportError:
    HAVE_MACHOLIB = False

try:
    import M2Crypto
    HAVE_MCRYPTO = True
except ImportError:
    HAVE_MCRYPTO = False

try:
    import oletools.olevba
    HAVE_OLETOOLS = True
except ImportError:
    HAVE_OLETOOLS = False

try:
    import peepdf.PDFCore
    import peepdf.JSAnalysis
    HAVE_PEEPDF = True
except ImportError:
    HAVE_PEEPDF = False

try:
    import PyV8
    HAVE_PYV8 = True

    PyV8  # Fake usage.
except:
    HAVE_PYV8 = False








def check_verinfo(self, pe):
        """ Determine the version info in a PE file """
        ret = []
        
        if hasattr(pe, 'VS_VERSIONINFO'):
            if hasattr(pe, 'FileInfo'):
                for entry in pe.FileInfo:
                    if hasattr(entry, 'StringTable'):
                        for st_entry in entry.StringTable:
                            for str_entry in st_entry.entries.items():
                                ret.append(utilities.convert_to_printable(str_entry[0]) + ': ' + utilities.convert_to_printable(str_entry[1]) )
                    elif hasattr(entry, 'Var'):
                        for var_entry in entry.Var:
                            if hasattr(var_entry, 'entry'):
                                ret.append(utilities.convert_to_printable(var_entry.entry.keys()[0]) + ': ' + var_entry.entry.values()[0])
        return '\n'.join(ret) 

def analyzePefile(file, output):
    #Is file?
    if utilities.isFile(file) == False:
        return print("The file is incorrect.")
    if utilities.isCorrectExtension(file, 'exe'):

        runPE()

    else:
        print("Wrong extension.")   

def runPE(self):
    """Run Analysis
    @return: analysis results dict or None
    """

    if not utilities.isFile(self.file_path):
        return {}
    try:
        self.pe = pefile.PE(self.file_path)
    except:
        return {}

# Partially taken from
# http://malwarecookbook.googlecode.com/svn/trunk/3/8/pescanner.py
class PortableExecutable(object):
    """PE Analysis"""

    def __init__(self, file_path):
        """@param file_path: file path."""

        self.file_path = file_path
        self.pe = None
    
    def _getfiletype(self, data):
        """Gets filetype, uses libmagic if available.
        @param data: data to be analyzed.
        @return: file type or None.
        """

        if not HAVE_MAGIC:
            return None

        try:
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            file_type = ms.buffer(data)
        except:
            try:
                file_type = magic.from_buffer(data)
            except Exception:
                return None

        finally:
            try:
                ms.close()
            except:
                pass

        return file_type

    def __get_peid_signatures(self):
        """Gets PEID Signatures.
        @return: matches signatures or None."""

        #try:
        #    sig_path = os.path.join()