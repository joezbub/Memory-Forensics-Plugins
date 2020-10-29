import argparse
import ctypes
import os
import re
import struct
import sys
import time
import timeit
import json
import io

from elftools import __version__
from Dependencies.readelf import ReadElf
from elftools.elf.descriptions import describe_sh_type
from elftools.elf.sections import SymbolTableSection

SCRIPT_DESCRIPTION = 'Display information about the contents of ELF format files'
VERSION_STRING = '%%(prog)s: based on pyelftools %s' % __version__
OUTPUT_PATH_READELF = "./ScriptOutputs/ReadElf.txt"
OUTPUT_PATH_PROFILE = "./ScriptOutputs/profile_py.txt"
SYMBOLS = {}
class symbol:
    def __init__(self, st_name, st_address, st_size):
        self.st_name = st_name
        self.st_address = st_address
        self.st_size = st_size


def profile_make(names, addresses, sizes):
    for i, name in enumerate(names):
        _symbol = symbol(name,hex(addresses[i]),sizes[i])
        SYMBOLS[name] = _symbol
    json_read = {}
    json_read['globals'] = []
    json_read['structs'] = []
    for sym in SYMBOLS:
        json_read['globals'].append({
            'name': SYMBOLS[sym].st_name,
            'offset': SYMBOLS[sym].st_address,
            'size': SYMBOLS[sym].st_size})

    with open(OUTPUT_PATH_PROFILE, 'w+') as profile:
        json.dump(json_read, profile,indent=4)
    return


def parse_args_():
    # parse the command-line arguments and invoke ReadElf
    argparser = argparse.ArgumentParser(
            usage='usage: %(prog)s [options] <elf-file>',
            description=SCRIPT_DESCRIPTION,
            add_help=False, # -h is a real option of readelf
            prog='readelf.py')
    argparser.add_argument('file',
            nargs='?', default=None,
            help='ELF file to parse')
    argparser.add_argument('-v', '--version',
            action='version', version=VERSION_STRING)
    argparser.add_argument('-d', '--dynamic',
            action='store_true', dest='show_dynamic_tags',
            help='Display the dynamic section')
    argparser.add_argument('-H', '--help',
            action='store_true', dest='help',
            help='Display this information')
    argparser.add_argument('-h', '--file-header',
            action='store_true', dest='show_file_header',
            help='Display the ELF file header')
    argparser.add_argument('-l', '--program-headers', '--segments',
            action='store_true', dest='show_program_header',
            help='Display the program headers')
    argparser.add_argument('-S', '--section-headers', '--sections',
            action='store_true', dest='show_section_header',
            help="Display the sections' headers")
    argparser.add_argument('-e', '--headers',
            action='store_true', dest='show_all_headers',
            help='Equivalent to: -h -l -S')
    argparser.add_argument('-s', '--symbols', '--syms',
            action='store_true', dest='show_symbols',
            help='Display the symbol table')
    argparser.add_argument('-n', '--notes',
            action='store_true', dest='show_notes',
            help='Display the core notes (if present)')
    argparser.add_argument('-r', '--relocs',
            action='store_true', dest='show_relocs',
            help='Display the relocations (if present)')
    argparser.add_argument('-x', '--hex-dump',
            action='store', dest='show_hex_dump', metavar='<number|name>',
            help='Dump the contents of section <number|name> as bytes')
    argparser.add_argument('-p', '--string-dump',
            action='store', dest='show_string_dump', metavar='<number|name>',
            help='Dump the contents of section <number|name> as strings')
    argparser.add_argument('-V', '--version-info',
            action='store_true', dest='show_version_info',
            help='Display the version sections (if present)')
    argparser.add_argument('-A', '--arch-specific',
            action='store_true', dest='show_arch_specific',
            help='Display the architecture-specific information (if present)')
    argparser.add_argument('--debug-dump',
            action='store', dest='debug_dump_what', metavar='<what>',
            help=(
                'Display the contents of DWARF debug sections. <what> can ' +
                'one of {info,decodedline,frames,frames-interp}'))
    args = argparser.parse_args()
    if args.help or not args.file:
        argparser.print_help()
        sys.exit(0)
    return argparser


def read_dyn_sym(readElf):
    readElf._init_versioninfo()

    symbol_tables = [s for s in readElf.elffile.iter_sections()
                     if isinstance(s, SymbolTableSection)]

    if not symbol_tables and readElf.elffile.num_sections() == 0:
        return

    names, sizes, addresses = [], [], []

    for section in symbol_tables:
        if not isinstance(section, SymbolTableSection):
            continue

        if str(describe_sh_type(section['sh_type'])) != 'DYNSYM':  # CONTINUES IF NOT LOOKING AT DYNAMIC SYMBOLS
            continue

        if section['sh_entsize'] == 0:
            continue
        for nsym, symbol in enumerate(section.iter_symbols()):
            names.append(symbol.name)
            addresses.append(symbol['st_value'])
            sizes.append(symbol['st_size'])
    return names, sizes, addresses


def main():
    streamOut = open(OUTPUT_PATH_READELF, 'w+')
    args = parse_args_().parse_args()
    file_h = open(args.file,'rb+')
    readElf = ReadElf(file_h, streamOut)

    names, sizes, addresses = read_dyn_sym(readElf)
    profile_make(names,addresses,sizes)

    streamOut.close()
    file_h.close()


if __name__ == '__main__':
    main()
    #profile_make()
