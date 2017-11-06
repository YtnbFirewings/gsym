#!/usr/bin/python

import binascii
import cmd
import commands
import dict_utils
import dwarf
import file_extract
import optparse
import os
import re
import shlex
import struct
import string
import StringIO
import sys
import term_colors
import uuid
# Mach header "magic" constants
MH_MAGIC                    = 0xfeedface
MH_CIGAM                    = 0xcefaedfe
MH_MAGIC_64                 = 0xfeedfacf
MH_CIGAM_64                 = 0xcffaedfe
FAT_MAGIC                   = 0xcafebabe
FAT_CIGAM                   = 0xbebafeca
FAT_MAGIC_64                = 0xcafebabf
FAT_CIGAM_64	            = 0xbfbafeca

# Mach haeder "filetype" constants
MH_OBJECT                   = 0x00000001
MH_EXECUTE                  = 0x00000002
MH_FVMLIB                   = 0x00000003
MH_CORE                     = 0x00000004
MH_PRELOAD                  = 0x00000005
MH_DYLIB                    = 0x00000006
MH_DYLINKER                 = 0x00000007
MH_BUNDLE                   = 0x00000008
MH_DYLIB_STUB               = 0x00000009
MH_DSYM                     = 0x0000000a
MH_KEXT_BUNDLE              = 0x0000000b

# Mach haeder "flag" constant bits
MH_NOUNDEFS                 = 0x00000001
MH_INCRLINK                 = 0x00000002
MH_DYLDLINK                 = 0x00000004
MH_BINDATLOAD               = 0x00000008
MH_PREBOUND                 = 0x00000010
MH_SPLIT_SEGS               = 0x00000020
MH_LAZY_INIT                = 0x00000040
MH_TWOLEVEL                 = 0x00000080
MH_FORCE_FLAT               = 0x00000100
MH_NOMULTIDEFS              = 0x00000200
MH_NOFIXPREBINDING          = 0x00000400
MH_PREBINDABLE              = 0x00000800
MH_ALLMODSBOUND             = 0x00001000
MH_SUBSECTIONS_VIA_SYMBOLS  = 0x00002000
MH_CANONICAL                = 0x00004000
MH_WEAK_DEFINES             = 0x00008000
MH_BINDS_TO_WEAK            = 0x00010000
MH_ALLOW_STACK_EXECUTION    = 0x00020000
MH_ROOT_SAFE                = 0x00040000
MH_SETUID_SAFE              = 0x00080000
MH_NO_REEXPORTED_DYLIBS     = 0x00100000
MH_PIE                      = 0x00200000
MH_DEAD_STRIPPABLE_DYLIB    = 0x00400000
MH_HAS_TLV_DESCRIPTORS      = 0x00800000
MH_NO_HEAP_EXECUTION        = 0x01000000

# Mach load command constants
LC_REQ_DYLD                 = 0x80000000
LC_SEGMENT                  = 0x00000001
LC_SYMTAB                   = 0x00000002
LC_SYMSEG                   = 0x00000003
LC_THREAD                   = 0x00000004
LC_UNIXTHREAD               = 0x00000005
LC_LOADFVMLIB               = 0x00000006
LC_IDFVMLIB                 = 0x00000007
LC_IDENT                    = 0x00000008
LC_FVMFILE                  = 0x00000009
LC_PREPAGE                  = 0x0000000a
LC_DYSYMTAB                 = 0x0000000b
LC_LOAD_DYLIB               = 0x0000000c
LC_ID_DYLIB                 = 0x0000000d
LC_LOAD_DYLINKER            = 0x0000000e
LC_ID_DYLINKER              = 0x0000000f
LC_PREBOUND_DYLIB           = 0x00000010
LC_ROUTINES                 = 0x00000011
LC_SUB_FRAMEWORK            = 0x00000012
LC_SUB_UMBRELLA             = 0x00000013
LC_SUB_CLIENT               = 0x00000014
LC_SUB_LIBRARY              = 0x00000015
LC_TWOLEVEL_HINTS           = 0x00000016
LC_PREBIND_CKSUM            = 0x00000017
LC_LOAD_WEAK_DYLIB          = 0x00000018 | LC_REQ_DYLD
LC_SEGMENT_64               = 0x00000019
LC_ROUTINES_64              = 0x0000001a
LC_UUID                     = 0x0000001b
LC_RPATH                    = 0x0000001c | LC_REQ_DYLD
LC_CODE_SIGNATURE           = 0x0000001d
LC_SEGMENT_SPLIT_INFO       = 0x0000001e
LC_REEXPORT_DYLIB           = 0x0000001f | LC_REQ_DYLD
LC_LAZY_LOAD_DYLIB          = 0x00000020
LC_ENCRYPTION_INFO          = 0x00000021
LC_DYLD_INFO                = 0x00000022
LC_DYLD_INFO_ONLY           = 0x00000022 | LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB        = 0x00000023 | LC_REQ_DYLD
LC_VERSION_MIN_MACOSX       = 0x00000024
LC_VERSION_MIN_IPHONEOS     = 0x00000025
LC_FUNCTION_STARTS          = 0x00000026
LC_DYLD_ENVIRONMENT         = 0x00000027
LC_MAIN                     = 0x00000028 | LC_REQ_DYLD
LC_DATA_IN_CODE             = 0x00000029
LC_SOURCE_VERSION           = 0x0000002A
LC_DYLIB_CODE_SIGN_DRS      = 0x0000002B
LC_ENCRYPTION_INFO_64       = 0x0000002C
LC_LINKER_OPTION            = 0x0000002D
LC_LINKER_OPTIMIZATION_HINT = 0x0000002E
LC_VERSION_MIN_TVOS         = 0x0000002F
LC_VERSION_MIN_WATCHOS      = 0x00000030

# Segment flags
SG_HIGHVM                   = 0x00000001
SG_FVMLIB                   = 0x00000002
SG_NORELOC                  = 0x00000004
SG_PROTECTED_VERSION_1      = 0x00000008

# Section flags
SECTION_TYPE	    = 0x000000ff
SECTION_ATTRIBUTES	= 0xffffff00

# Section type constants
S_REGULAR                               = 0x0
S_ZEROFILL		                        = 0x1
S_CSTRING_LITERALS	                    = 0x2
S_4BYTE_LITERALS	                    = 0x3
S_8BYTE_LITERALS	                    = 0x4
S_LITERAL_POINTERS	                    = 0x5
S_NON_LAZY_SYMBOL_POINTERS              = 0x6
S_LAZY_SYMBOL_POINTERS		            = 0x7
S_SYMBOL_STUBS			                = 0x8
S_MOD_INIT_FUNC_POINTERS	            = 0x9
S_MOD_TERM_FUNC_POINTERS	            = 0xa
S_COALESCED			                    = 0xb
S_GB_ZEROFILL			                = 0xc
S_INTERPOSING			                = 0xd
S_16BYTE_LITERALS		                = 0xe
S_DTRACE_DOF			                = 0xf
S_LAZY_DYLIB_SYMBOL_POINTERS	        = 0x10
S_THREAD_LOCAL_REGULAR                  = 0x11
S_THREAD_LOCAL_ZEROFILL                 = 0x12
S_THREAD_LOCAL_VARIABLES                = 0x13
S_THREAD_LOCAL_VARIABLE_POINTERS        = 0x14
S_THREAD_LOCAL_INIT_FUNCTION_POINTERS   = 0x15

# Section attribute constants
SECTION_ATTRIBUTES_USR      = 0xff000000
S_ATTR_PURE_INSTRUCTIONS    = 0x80000000
S_ATTR_NO_TOC 		        = 0x40000000
S_ATTR_STRIP_STATIC_SYMS    = 0x20000000
S_ATTR_NO_DEAD_STRIP	    = 0x10000000
S_ATTR_LIVE_SUPPORT	        = 0x08000000
S_ATTR_SELF_MODIFYING_CODE  = 0x04000000
S_ATTR_DEBUG		        = 0x02000000
SECTION_ATTRIBUTES_SYS	    = 0x00ffff00
S_ATTR_SOME_INSTRUCTIONS    = 0x00000400
S_ATTR_EXT_RELOC	        = 0x00000200
S_ATTR_LOC_RELOC	        = 0x00000100

# Mach CPU constants
CPU_ARCH_MASK               = 0xff000000
CPU_ARCH_ABI64              = 0x01000000
CPU_TYPE_ANY                = 0xffffffff
CPU_TYPE_VAX                = 1
CPU_TYPE_MC680x0            = 6
CPU_TYPE_I386               = 7
CPU_TYPE_X86_64             = CPU_TYPE_I386 | CPU_ARCH_ABI64
CPU_TYPE_MIPS               = 8
CPU_TYPE_MC98000            = 10
CPU_TYPE_HPPA               = 11
CPU_TYPE_ARM                = 12
CPU_TYPE_MC88000            = 13
CPU_TYPE_SPARC              = 14
CPU_TYPE_I860               = 15
CPU_TYPE_ALPHA              = 16
CPU_TYPE_POWERPC            = 18
CPU_TYPE_POWERPC64          = CPU_TYPE_POWERPC | CPU_ARCH_ABI64

# VM protection constants
VM_PROT_READ    = 1
VM_PROT_WRITE   = 2
VM_PROT_EXECUTE = 4

# VM protection constants
N_STAB          = 0xe0
N_PEXT          = 0x10
N_TYPE          = 0x0e
N_EXT           = 0x01

# Values for nlist N_TYPE bits of the "Mach.NList.type" field.
N_UNDF          = 0x0
N_ABS           = 0x2
N_SECT          = 0xe
N_PBUD          = 0xc
N_INDR          = 0xa

# Section indexes for the "Mach.NList.sect_idx" fields
NO_SECT         = 0
MAX_SECT        = 255

# Stab defines
N_GSYM          = 0x20
N_FNAME         = 0x22
N_FUN           = 0x24
N_STSYM         = 0x26
N_LCSYM         = 0x28
N_BNSYM         = 0x2e
N_OPT           = 0x3c
N_RSYM          = 0x40
N_SLINE         = 0x44
N_ENSYM         = 0x4e
N_SSYM          = 0x60
N_SO            = 0x64
N_OSO           = 0x66
N_LSYM          = 0x80
N_BINCL         = 0x82
N_SOL           = 0x84
N_PARAMS        = 0x86
N_VERSION       = 0x88
N_OLEVEL        = 0x8A
N_PSYM          = 0xa0
N_EINCL         = 0xa2
N_ENTRY         = 0xa4
N_LBRAC         = 0xc0
N_EXCL          = 0xc2
N_RBRAC         = 0xe0
N_BCOMM         = 0xe2
N_ECOMM         = 0xe4
N_ECOML         = 0xe8
N_LENG          = 0xfe

vm_prot_names = [ '---', 'r--', '-w-', 'rw-', '--x', 'r-x', '-wx', 'rwx' ]

def get_version32_as_string(v):
    return "%u.%u.%u" % (v >> 16, (v >> 8) & 0xff, v & 0xff)

def int_to_hex16(i):
    return '0x%4.4x' % (i)

def int_to_hex32(i):
    return '0x%8.8x' % (i)

def int_to_hex64(i):
    return '0x%16.16x' % (i)

def address_to_str(addr, is_64):
    if is_64:
        return int_to_hex64(addr)
    else:
        return int_to_hex32(addr)

def address_range_to_str(i, j, is_64):
    if is_64:
        return '[%s - %s)' % (int_to_hex64(i), int_to_hex64(j))
    else:
        return '[%s - %s)' % (int_to_hex32(i), int_to_hex32(j))

def dump_memory(base_addr, data, num_per_line, outfile):

    data_len = len(data)
    hex_string = binascii.hexlify(data)
    addr = base_addr
    ascii_str = ''
    i = 0
    while i < data_len:
        print >>outfile, int_to_hex32(addr+i),
        bytes_left = data_len - i
        if bytes_left >= num_per_line:
            curr_data_len = num_per_line
        else:
            curr_data_len = bytes_left
        hex_start_idx = i * 2
        hex_end_idx = hex_start_idx + curr_data_len * 2
        curr_hex_str = hex_string[hex_start_idx:hex_end_idx]
        # 'curr_hex_str' now contains the hex byte string for the
        # current line with no spaces between bytes
        t = iter(curr_hex_str)
        # Print hex bytes separated by space
        print >>outfile, ' '.join(a+b for a,b in zip(t, t)),
        # Print two spaces
        print >>outfile, '  ',
        # Calculate ASCII string for bytes into 'ascii_str'
        ascii_str = ''
        for j in range(i, i+curr_data_len):
            ch = data[j]
            if ch in string.printable and ch not in string.whitespace:
                ascii_str += '%c' % (ch)
            else:
                ascii_str += '.'
        # Print ASCII representation and newline
        print >>outfile, ascii_str
        i = i + curr_data_len
    print >>outfile



def swap_unpack_char():
    """Returns the unpack prefix that will for non-native endian-ness."""
    if struct.pack('H', 1).startswith("\x00"):
        return '<'
    return '>'


def dump_hex_bytes(addr, s, bytes_per_line=16):
    i = 0
    line = ''
    for ch in s:
        if (i % bytes_per_line) == 0:
            if line:
                print line
            line = '%#8.8x: ' % (addr + i)
        line += "%02X " % ord(ch)
        i += 1
    print line

def dump_hex_byte_string_diff(addr, a, b, bytes_per_line=16):
    i = 0
    line = ''
    a_len = len(a)
    b_len = len(b)
    if a_len < b_len:
        max_len = b_len
    else:
        max_len = a_len
    tty_colors = term_colors.TerminalColors (True)
    for i in range(max_len):
        ch = None
        if i < a_len:
            ch_a = a[i]
            ch = ch_a
        else:
            ch_a = None
        if i < b_len:
            ch_b = b[i]
            if not ch:
                ch = ch_b
        else:
            ch_b = None
        mismatch = ch_a != ch_b
        if (i % bytes_per_line) == 0:
            if line:
                print line
            line = '%#8.8x: ' % (addr + i)
        if mismatch: line += tty_colors.red()
        line += "%02X " % ord(ch)
        if mismatch: line += tty_colors.default()
        i += 1

    print line

class Mach:
    """Class that does everything mach-o related"""

    class Arch:
        """Class that implements mach-o architectures"""

        def __init__(self, c=0, s=0):
            self.cpu=c
            self.sub=s

        def set_cpu_type(self, c):
            self.cpu=c
        def set_cpu_subtype(self, s):
            self.sub=s
        def set_arch(self, c, s):
            self.cpu=c
            self.sub=s
        def is_64_bit(self):
            return (self.cpu & CPU_ARCH_ABI64) != 0
        def get_addr_size(self):
            if self.is_64_bit():
                return 8
            return 4
        cpu_infos = [
            [ "arm"         , CPU_TYPE_ARM       , CPU_TYPE_ANY ],
            [ "arm"         , CPU_TYPE_ARM       , 0            ],
            [ "armv4"       , CPU_TYPE_ARM       , 5            ],
            [ "armv6"       , CPU_TYPE_ARM       , 6            ],
            [ "armv5"       , CPU_TYPE_ARM       , 7            ],
            [ "xscale"      , CPU_TYPE_ARM       , 8            ],
            [ "armv7"       , CPU_TYPE_ARM       , 9            ],
            [ "armv7f"      , CPU_TYPE_ARM       , 10           ],
            [ "armv7k"      , CPU_TYPE_ARM       , 12           ],
            [ "armv7s"      , CPU_TYPE_ARM       , 11           ],
            [ "arm64"       , CPU_TYPE_ARM | CPU_ARCH_ABI64, 0  ],
            [ "ppc"         , CPU_TYPE_POWERPC   , CPU_TYPE_ANY ],
            [ "ppc"         , CPU_TYPE_POWERPC   , 0            ],
            [ "ppc601"      , CPU_TYPE_POWERPC   , 1            ],
            [ "ppc602"      , CPU_TYPE_POWERPC   , 2            ],
            [ "ppc603"      , CPU_TYPE_POWERPC   , 3            ],
            [ "ppc603e"     , CPU_TYPE_POWERPC   , 4            ],
            [ "ppc603ev"    , CPU_TYPE_POWERPC   , 5            ],
            [ "ppc604"      , CPU_TYPE_POWERPC   , 6            ],
            [ "ppc604e"     , CPU_TYPE_POWERPC   , 7            ],
            [ "ppc620"      , CPU_TYPE_POWERPC   , 8            ],
            [ "ppc750"      , CPU_TYPE_POWERPC   , 9            ],
            [ "ppc7400"     , CPU_TYPE_POWERPC   , 10           ],
            [ "ppc7450"     , CPU_TYPE_POWERPC   , 11           ],
            [ "ppc970"      , CPU_TYPE_POWERPC   , 100          ],
            [ "ppc64"       , CPU_TYPE_POWERPC64 , 0            ],
            [ "ppc970-64"   , CPU_TYPE_POWERPC64 , 100          ],
            [ "i386"        , CPU_TYPE_I386      , 3            ],
            [ "i486"        , CPU_TYPE_I386      , 4            ],
            [ "i486sx"      , CPU_TYPE_I386      , 0x84         ],
            [ "i386"        , CPU_TYPE_I386      , CPU_TYPE_ANY ],
            [ "x86_64"      , CPU_TYPE_X86_64    , 3            ],
            [ "x86_64h"     , CPU_TYPE_X86_64    , 8            ],
            [ "x86_64"      , CPU_TYPE_X86_64    , CPU_TYPE_ANY ],
        ]
        def set_arch_by_name(self, arch_name):
            for info in self.cpu_infos:
                if info[0] == arch_name:
                    self.cpu=info[1]
                    self.sub=info[2]
                    return
            raise ValueError("unsupported architecture name '%s'" % (arch_name))


        def __str__(self):
            for info in self.cpu_infos:
                if self.cpu == info[1] and (self.sub & 0x00ffffff) == info[2]:
                    return info[0]
            return "{0}.{1}".format(self.cpu,self.sub)


    class Magic(dict_utils.Enum):

        enum = {
            'MH_MAGIC'      : MH_MAGIC,
            'MH_CIGAM'      : MH_CIGAM,
            'MH_MAGIC_64'   : MH_MAGIC_64,
            'MH_CIGAM_64'   : MH_CIGAM_64,
            'FAT_MAGIC'     : FAT_MAGIC,
            'FAT_CIGAM'     : FAT_CIGAM
        }

        def __init__(self, initial_value = 0):
            dict_utils.Enum.__init__(self, initial_value, self.enum)

        def is_skinny_mach_file(self):
            return self.value == MH_MAGIC or self.value == MH_CIGAM or self.value == MH_MAGIC_64 or self.value == MH_CIGAM_64

        def is_universal_mach_file(self):
            return self.value == FAT_MAGIC or self.value == FAT_CIGAM

        def unpack(self, data):
            data.set_byte_order('native')
            self.value = data.get_uint32()

        def get_byte_order(self):
            if self.value == MH_CIGAM or self.value == MH_CIGAM_64 or self.value == FAT_CIGAM:
                return swap_unpack_char()
            else:
                return '='

        def is_64_bit(self):
            return self.value == MH_MAGIC_64 or self.value == MH_CIGAM_64

    def __init__(self):
        self.magic = Mach.Magic()
        self.content = None
        self.path = None

    def extract (self, path, extractor):
        self.path = path
        self.unpack(extractor)

    def parse(self, path):
        self.path = path
        try:
            f = open(self.path)
            file_extractor = file_extract.FileExtract(f, '=')
            self.unpack(file_extractor)
            #f.close()
        except IOError as (errno, strerror):
            print "I/O error({0}): {1}".format(errno, strerror)
        except ValueError:
            print "Could not convert data to an integer."
        except:
            print "Unexpected error:", sys.exc_info()[0]
            raise

    def get_num_archs(self):
        return self.content.get_num_archs()

    def get_architecture(self, index):
        return self.content.get_architecture(index)

    def get_architecture_slice(self, arch_name):
        return self.content.get_architecture_slice(arch_name)

    def compare(self, rhs):
        self.content.compare(rhs.content)

    def dump(self, options = None):
        self.content.dump(options)

    def dump_header(self, dump_description = True, options = None):
        self.content.dump_header(dump_description, options)

    def dump_load_commands(self, dump_description = True, options = None):
        self.content.dump_load_commands(dump_description, options)

    def dump_sections(self, dump_description = True, options = None):
        self.content.dump_sections(dump_description, options)

    def dump_section_contents(self, options):
        self.content.dump_section_contents(options)

    def dump_symtab(self, dump_description = True, options = None):
        self.content.dump_symtab(dump_description, options)

    def dump_symbol_names_matching_regex(self, regex, file=None):
        self.content.dump_symbol_names_matching_regex(regex, file)

    def description(self):
        return self.content.description()

    def unpack(self, data):
        self.magic.unpack(data)
        if self.magic.is_skinny_mach_file():
            self.content = Mach.Skinny(self.path)
        elif self.magic.is_universal_mach_file():
            self.content = Mach.Universal(self.path)
        else:
            self.content = None

        if self.content != None:
            self.content.unpack(data, self.magic)

    def is_valid(self):
        return self.content != None

    class Universal:

        def __init__(self, path):
            self.path       = path
            self.type       = 'universal'
            self.file_off   = 0
            self.magic      = None
            self.nfat_arch  = 0
            self.archs      = list()

        def get_num_archs(self):
            return len(self.archs)

        def get_architecture(self, index):
            if index < len(self.archs):
                return self.archs[index].arch
            return None

        def get_architecture_slice(self, arch_name):
            for arch in self.archs:
                if str(arch.arch) == arch_name:
                    return arch.mach
            return None

        def description(self):
            s = '%#8.8x: %s (' % (self.file_off, self.path)
            archs_string = ''
            for arch in self.archs:
                if len(archs_string):
                    archs_string += ', '
                archs_string += '%s' % arch.arch
            s += archs_string
            s += ')'
            return s

        def unpack(self, data, magic = None):
            self.file_off = data.tell()
            if magic is None:
                self.magic = Mach.Magic()
                self.magic.unpack(data)
            else:
                self.magic = magic
                self.file_off = self.file_off - 4
            # Universal headers are always in big endian
            data.set_byte_order('big')
            self.nfat_arch = data.get_uint32()
            for i in range(self.nfat_arch):
                self.archs.append(Mach.Universal.ArchInfo())
                self.archs[i].unpack(data)
            for i in range(self.nfat_arch):
                self.archs[i].mach = Mach.Skinny(self.path)
                data.seek (self.archs[i].offset, 0)
                skinny_magic = Mach.Magic()
                skinny_magic.unpack (data)
                self.archs[i].mach.unpack(data, skinny_magic)

        def compare(self, rhs):
            print 'error: comparing two universal files is not supported yet'
            return False

        def dump(self, options):
            if options.dump_header:
                print
                print "Universal Mach File: magic = %s, nfat_arch = %u" % (self.magic, self.nfat_arch)
                print
            if self.nfat_arch > 0:
                if options.dump_header:
                    self.archs[0].dump_header(True, options)
                    for i in range(self.nfat_arch):
                        self.archs[i].dump_flat(options)
                if options.dump_header:
                    print
                for i in range(self.nfat_arch):
                    self.archs[i].mach.dump(options)

        def dump_header(self, dump_description = True, options = None):
            if dump_description:
                print self.description()
            for i in range(self.nfat_arch):
                self.archs[i].mach.dump_header(True, options)
                print

        def dump_load_commands(self, dump_description = True, options = None):
            if dump_description:
                print self.description()
            for i in range(self.nfat_arch):
                self.archs[i].mach.dump_load_commands(True, options)
                print

        def dump_sections(self, dump_description = True, options = None):
            if dump_description:
                print self.description()
            for i in range(self.nfat_arch):
                self.archs[i].mach.dump_sections(True, options)
                print

        def dump_section_contents(self, options):
            for i in range(self.nfat_arch):
                self.archs[i].mach.dump_section_contents(options)
                print

        def dump_symtab(self, dump_description = True, options = None):
            if dump_description:
                print self.description()
            for i in range(self.nfat_arch):
                self.archs[i].mach.dump_symtab(True, options)
                print

        def dump_symbol_names_matching_regex(self, regex, file=None):
            for i in range(self.nfat_arch):
                self.archs[i].mach.dump_symbol_names_matching_regex(regex, file)

        class ArchInfo:

            def __init__(self):
                self.arch   = Mach.Arch(0,0)
                self.offset = 0
                self.size   = 0
                self.align  = 0
                self.mach   = None

            def unpack(self, data):
                # Universal headers are always in big endian
                data.set_byte_order('big')
                self.arch.cpu, self.arch.sub, self.offset, self.size, self.align = data.get_n_uint32(5)

            def dump_header(self, dump_description = True, options = None):
                if options.verbose:
                    print "CPU        SUBTYPE    OFFSET     SIZE       ALIGN"
                    print "---------- ---------- ---------- ---------- ----------"
                else:
                    print "ARCH       FILEOFFSET FILESIZE   ALIGN"
                    print "---------- ---------- ---------- ----------"
            def dump_flat(self, options):
                if options.verbose:
                    print "%#8.8x %#8.8x %#8.8x %#8.8x %#8.8x" % (self.arch.cpu, self.arch.sub, self.offset, self.size, self.align)
                else:
                    print "%-10s %#8.8x %#8.8x %#8.8x" % (self.arch, self.offset, self.size, self.align)
            def dump(self):
                print "   cputype: %#8.8x" % self.arch.cpu
                print "cpusubtype: %#8.8x" % self.arch.sub
                print "    offset: %#8.8x" % self.offset
                print "      size: %#8.8x" % self.size
                print "     align: %#8.8x" % self.align
            def __str__(self):
                return "Mach.Universal.ArchInfo: %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x" % (self.arch.cpu, self.arch.sub, self.offset, self.size, self.align)
            def __repr__(self):
                return "Mach.Universal.ArchInfo: %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x" % (self.arch.cpu, self.arch.sub, self.offset, self.size, self.align)

    class Flags:

        def __init__(self, b):
            self.bits = b

        def __str__(self):
            s = ''
            if self.bits & MH_NOUNDEFS:
                s += 'MH_NOUNDEFS | '
            if self.bits & MH_INCRLINK:
                s += 'MH_INCRLINK | '
            if self.bits & MH_DYLDLINK:
                s += 'MH_DYLDLINK | '
            if self.bits & MH_BINDATLOAD:
                s += 'MH_BINDATLOAD | '
            if self.bits & MH_PREBOUND:
                s += 'MH_PREBOUND | '
            if self.bits & MH_SPLIT_SEGS:
                s += 'MH_SPLIT_SEGS | '
            if self.bits & MH_LAZY_INIT:
                s += 'MH_LAZY_INIT | '
            if self.bits & MH_TWOLEVEL:
                s += 'MH_TWOLEVEL | '
            if self.bits & MH_FORCE_FLAT:
                s += 'MH_FORCE_FLAT | '
            if self.bits & MH_NOMULTIDEFS:
                s += 'MH_NOMULTIDEFS | '
            if self.bits & MH_NOFIXPREBINDING:
                s += 'MH_NOFIXPREBINDING | '
            if self.bits & MH_PREBINDABLE:
                s += 'MH_PREBINDABLE | '
            if self.bits & MH_ALLMODSBOUND:
                s += 'MH_ALLMODSBOUND | '
            if self.bits & MH_SUBSECTIONS_VIA_SYMBOLS:
                s += 'MH_SUBSECTIONS_VIA_SYMBOLS | '
            if self.bits & MH_CANONICAL:
                s += 'MH_CANONICAL | '
            if self.bits & MH_WEAK_DEFINES:
                s += 'MH_WEAK_DEFINES | '
            if self.bits & MH_BINDS_TO_WEAK:
                s += 'MH_BINDS_TO_WEAK | '
            if self.bits & MH_ALLOW_STACK_EXECUTION:
                s += 'MH_ALLOW_STACK_EXECUTION | '
            if self.bits & MH_ROOT_SAFE:
                s += 'MH_ROOT_SAFE | '
            if self.bits & MH_SETUID_SAFE:
                s += 'MH_SETUID_SAFE | '
            if self.bits & MH_NO_REEXPORTED_DYLIBS:
                s += 'MH_NO_REEXPORTED_DYLIBS | '
            if self.bits & MH_PIE:
                s += 'MH_PIE | '
            if self.bits & MH_DEAD_STRIPPABLE_DYLIB:
                s += 'MH_DEAD_STRIPPABLE_DYLIB | '
            if self.bits & MH_HAS_TLV_DESCRIPTORS:
                s += 'MH_HAS_TLV_DESCRIPTORS | '
            if self.bits & MH_NO_HEAP_EXECUTION:
                s += 'MH_NO_HEAP_EXECUTION | '
            # Strip the trailing " |" if we have any flags
            if len(s) > 0:
                s = s[0:-2]
            return s

    class FileType(dict_utils.Enum):

        enum = {
            'MH_OBJECT'         : MH_OBJECT        ,
            'MH_EXECUTE'        : MH_EXECUTE       ,
            'MH_FVMLIB'         : MH_FVMLIB        ,
            'MH_CORE'           : MH_CORE          ,
            'MH_PRELOAD'        : MH_PRELOAD       ,
            'MH_DYLIB'          : MH_DYLIB         ,
            'MH_DYLINKER'       : MH_DYLINKER      ,
            'MH_BUNDLE'         : MH_BUNDLE        ,
            'MH_DYLIB_STUB'     : MH_DYLIB_STUB    ,
            'MH_DSYM'           : MH_DSYM          ,
            'MH_KEXT_BUNDLE'    : MH_KEXT_BUNDLE
        }

        def __init__(self, initial_value = 0):
            dict_utils.Enum.__init__(self, initial_value, self.enum)

    class Skinny:

        def __init__(self, path):
            self.path       = path
            self.type       = 'skinny'
            self.data       = None
            self.file_off   = 0
            self.magic      = 0
            self.arch       = Mach.Arch(0,0)
            self.filetype   = Mach.FileType(0)
            self.ncmds      = 0
            self.sizeofcmds = 0
            self.flags      = Mach.Flags(0)
            self.uuid       = None
            self.commands   = list()
            self.segments   = list()
            self.sections   = list()
            self.symbols    = list()
            self.sections.append(Mach.Section())
            self.dwarf      = -1

        def get_file_type(self):
            return 'mach-o'

        def get_num_archs(self):
            return 1

        def get_architecture(self, index):
            if index == 0:
                return self.arch
            return None

        def get_architecture_slice(self, arch_name):
            if str(self.arch) == arch_name:
                return self
            return None

        def description(self):
            return '%#8.8x: %s (%s)' % (self.file_off, self.path, self.arch)

        # @classmethod
        # def create(class, arch, file_type, load_commands, section_dict, encoder):
        # segment_names = []
        # for lc in load_commands:
        #     if lc.command.value == LC_SEGMENT or lc.command.value == LC_SEGMENT_64:
        #         raise ValueError("load_commands can't have LC_SEGMENT or LC_SEGMENT_64 load commands")
        # for section_name in section_dict:
        #     section = section_dict[section_name]['section']
        #     if not section.segname in segment_names:
        #         segment_names.append(section.segname)
        #
        #
        # # Write the correct magic value
        # if arch.is_64_bit():
        #     mach_file.put_uint32(mach_o.MH_MAGIC_64)
        # else:
        #     mach_file.put_uint32(mach_o.MH_MAGIC)
        # mach_file.put_uint32(arch.cpu) # cputype
        # mach_file.put_uint32(arch.sub) # cpusubtype
        # mach_file.put_uint32(file_type.value)  # filetype
        # mach_file.put_uint32(1)  # ncmds
        # sizeofcmds_offset = mach_file.file.tell()
        # mach_file.put_uint32(0)  # sizeofcmds
        # mach_file.put_uint32(0)  # flags


        def unpack(self, data, magic = None):
            self.data = data
            self.file_off = data.tell()
            if magic is None:
                self.magic = Mach.Magic()
                self.magic.unpack(data)
            else:
                self.magic = magic
                self.file_off = self.file_off - 4
            data.set_byte_order(self.magic.get_byte_order())
            self.arch.cpu, self.arch.sub, self.filetype.value, self.ncmds, self.sizeofcmds, bits = data.get_n_uint32(6)
            self.flags.bits = bits

            if self.is_64_bit():
                data.get_uint32() # Skip reserved word in mach_header_64

            for i in range(0,self.ncmds):
                lc = self.unpack_load_command (data)
                self.commands.append (lc)

        def get_data(self):
            if self.data:
                self.data.set_byte_order(self.magic.get_byte_order())
                return self.data
            return None

        def unpack_load_command (self, data):
            lc = Mach.LoadCommand()
            lc.unpack (self, data)
            lc_command = lc.command.get_enum_value()
            if (lc_command == LC_SEGMENT or
                lc_command == LC_SEGMENT_64):
                lc = Mach.SegmentLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_LOAD_DYLIB or
                  lc_command == LC_ID_DYLIB or
                  lc_command == LC_LOAD_WEAK_DYLIB or
                  lc_command == LC_REEXPORT_DYLIB):
                lc = Mach.DylibLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_LOAD_DYLINKER or
                  lc_command == LC_SUB_FRAMEWORK or
                  lc_command == LC_SUB_CLIENT or
                  lc_command == LC_SUB_UMBRELLA or
                  lc_command == LC_SUB_LIBRARY or
                  lc_command == LC_ID_DYLINKER or
                  lc_command == LC_RPATH):
                lc = Mach.LoadDYLDLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_DYLD_INFO_ONLY):
                lc = Mach.DYLDInfoOnlyLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_SYMTAB):
                lc = Mach.SymtabLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_DYSYMTAB):
                lc = Mach.DYLDSymtabLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_UUID):
                lc = Mach.UUIDLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_CODE_SIGNATURE or
                  lc_command == LC_SEGMENT_SPLIT_INFO or
                  lc_command == LC_FUNCTION_STARTS or
                  lc_command == LC_DATA_IN_CODE or
                  lc_command == LC_DYLIB_CODE_SIGN_DRS or
                  lc_command == LC_LINKER_OPTIMIZATION_HINT):
                lc = Mach.DataBlobLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_UNIXTHREAD):
                lc = Mach.UnixThreadLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_ENCRYPTION_INFO):
                lc = Mach.EncryptionInfoLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_MAIN):
                lc = Mach.MainLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_VERSION_MIN_MACOSX or lc_command == LC_VERSION_MIN_IPHONEOS):
                lc = Mach.VersionMinLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_SOURCE_VERSION):
                lc = Mach.SourceVersionLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_LINKER_OPTION):
                lc = Mach.LinkerOptionLoadCommand(lc)
                lc.unpack(self, data)
            lc.skip(data)
            return lc

        def compare(self, rhs):
            print "\nComparing:"
            print "a) %s %s" % (self.arch, self.path)
            print "b) %s %s" % (rhs.arch, rhs.path)
            result = True
            if self.type == rhs.type:
                for lhs_section in self.sections[1:]:
                    rhs_section = rhs.get_section_by_section(lhs_section)
                    if rhs_section:
                        print 'comparing %s.%s...' % (lhs_section.segname, lhs_section.sectname),
                        sys.stdout.flush()
                        lhs_data = lhs_section.get_contents (self)
                        rhs_data = rhs_section.get_contents (rhs)
                        if lhs_data and rhs_data:
                            if lhs_data == rhs_data:
                                print 'ok'
                            else:
                                lhs_data_len = len(lhs_data)
                                rhs_data_len = len(rhs_data)
                                # if lhs_data_len < rhs_data_len:
                                #     if lhs_data == rhs_data[0:lhs_data_len]:
                                #         print 'section data for %s matches the first %u bytes' % (lhs_section.sectname, lhs_data_len)
                                #     else:
                                #         # TODO: check padding
                                #         result = False
                                # elif lhs_data_len > rhs_data_len:
                                #     if lhs_data[0:rhs_data_len] == rhs_data:
                                #         print 'section data for %s matches the first %u bytes' % (lhs_section.sectname, lhs_data_len)
                                #     else:
                                #         # TODO: check padding
                                #         result = False
                                # else:
                                result = False
                                print 'error: sections differ'
                                #print 'a) %s' % (lhs_section)
                                # dump_hex_byte_string_diff(0, lhs_data, rhs_data)
                                #print 'b) %s' % (rhs_section)
                                # dump_hex_byte_string_diff(0, rhs_data, lhs_data)
                        elif lhs_data and not rhs_data:
                            print 'error: section data missing from b:'
                            print 'a) %s' % (lhs_section)
                            print 'b) %s' % (rhs_section)
                            result = False
                        elif not lhs_data and rhs_data:
                            print 'error: section data missing from a:'
                            print 'a) %s' % (lhs_section)
                            print 'b) %s' % (rhs_section)
                            result = False
                        elif (lhs_section.offset or rhs_section.offset) and (lhs_section.size > 0 or rhs_section.size > 0):
                            print 'error: section data missing for both a and b:'
                            print 'a) %s' % (lhs_section)
                            print 'b) %s' % (rhs_section)
                            result = False
                        else:
                            print 'ok'
                    else:
                        result = False
                        print 'error: section %s is missing in %s' % (lhs_section.sectname, rhs.path)
            else:
                print 'error: comaparing a %s mach-o file with a %s mach-o file is not supported' % (self.type, rhs.type)
                result = False
            if not result:
                print 'error: mach files differ'
            return result
        def dump_header(self, dump_description = True, options = None):
            if options.verbose:
                print "MAGIC      CPU        SUBTYPE    FILETYPE   NUM CMDS SIZE CMDS  FLAGS"
                print "---------- ---------- ---------- ---------- -------- ---------- ----------"
            else:
                print "MAGIC        ARCH       FILETYPE       NUM CMDS SIZE CMDS  FLAGS"
                print "------------ ---------- -------------- -------- ---------- ----------"

        def dump_flat(self, options):
            if options.verbose:
                print "%#8.8x %#8.8x %#8.8x %#8.8x %#8u %#8.8x %#8.8x" % (self.magic, self.arch.cpu , self.arch.sub, self.filetype.value, self.ncmds, self.sizeofcmds, self.flags.bits)
            else:
                print "%-12s %-10s %-14s %#8u %#8.8x %s" % (self.magic, self.arch, self.filetype, self.ncmds, self.sizeofcmds, self.flags)

        def get_dwarf(self):
            if self.dwarf is -1:
                self.dwarf = None
                debug_abbrev_data = self.get_section_contents_by_name('__debug_abbrev')
                debug_info_data = self.get_section_contents_by_name('__debug_info')
                if debug_abbrev_data or debug_info_data:
                    debug_aranges_data = self.get_section_contents_by_name('__debug_aranges')
                    debug_line_data = self.get_section_contents_by_name('__debug_line')
                    debug_ranges_data = self.get_section_contents_by_name('__debug_ranges')
                    debug_str_data = self.get_section_contents_by_name('__debug_str')
                    apple_names_data = self.get_section_contents_by_name('__apple_names')
                    apple_types_data = self.get_section_contents_by_name('__apple_types')
                    self.dwarf = dwarf.DWARF(debug_abbrev_data, debug_aranges_data, debug_info_data, debug_line_data, debug_ranges_data, debug_str_data, apple_names_data, apple_types_data)
            return self.dwarf

        def dump(self, options):
            if options.dump_header:
                self.dump_header(True, options)
            if options.dump_load_commands:
                self.dump_load_commands(False, options)
            if options.dump_sections:
                self.dump_sections(False, options)
            if options.section_names:
                self.dump_section_contents(options)
            if options.dump_symtab:
                symbols = self.get_symtab()
                if len(symbols):
                    self.dump_symtab(False, options)
                else:
                    print "No symbols"
            if options.find_mangled:
                self.dump_symbol_names_matching_regex (re.compile('^_?_Z'))

            dwarf.handle_dwarf_options(options, self)

        def dump_header(self, dump_description = True, options = None):
            if dump_description:
                print self.description()
            print "Mach Header"
            print "       magic: %#8.8x %s" % (self.magic.value, self.magic)
            print "     cputype: %#8.8x %s" % (self.arch.cpu, self.arch)
            print "  cpusubtype: %#8.8x" % self.arch.sub
            print "    filetype: %#8.8x %s" % (self.filetype.get_enum_value(), self.filetype.get_enum_name())
            print "       ncmds: %#8.8x %u" % (self.ncmds, self.ncmds)
            print "  sizeofcmds: %#8.8x" % self.sizeofcmds
            print "       flags: %#8.8x %s" % (self.flags.bits, self.flags)

        def dump_load_commands(self, dump_description = True, options = None):
            if dump_description:
                print self.description()
            for lc in self.commands:
                print lc

        def get_section_by_name (self, name):
            for section in self.sections:
                if section.sectname and section.sectname == name:
                    return section
            return None

        def read_data(self, offset, size):
            '''Read raw data from the file at offset and size and return a
               file_extract.FileExtract that has the byte order and address
               size set correctly.'''
            self.data.push_offset_and_seek(offset)
            bytes = self.data.read_size(size)
            self.data.pop_offset_and_seek()
            return file_extract.FileExtract(StringIO.StringIO(bytes),
                                            self.data.get_byte_order(),
                                            self.data.get_addr_size())

        def get_section_contents_by_name(self, name):
            section = self.get_section_by_name(name)
            if section:
                return section.get_contents_as_extractor (self)
            return None

        def get_section_by_section (self, other_section):
            for section in self.sections:
                if section.sectname == other_section.sectname and section.segname == other_section.segname:
                    return section
            return None

        def dump_sections(self, dump_description = True, options = None):
            if dump_description:
                print self.description()
            num_sections = len(self.sections)
            if num_sections > 1:
                self.sections[1].dump_header()
                for sect_idx in range(1,num_sections):
                    print "%s" % self.sections[sect_idx]

        def dump_section_contents(self, options):
            saved_section_to_disk = False
            for sectname in options.section_names:
                section = self.get_section_by_name(sectname)
                if section:
                    sect_bytes = section.get_contents (self)
                    if options.outfile:
                        if not saved_section_to_disk:
                            outfile = open(options.outfile, 'w')
                            print "Saving section %s to '%s'" % (sectname, options.outfile)
                            outfile.write(sect_bytes)
                            outfile.close()
                            saved_section_to_disk = True
                        else:
                            print "error: you can only save a single section to disk at a time, skipping section '%s'" % (sectname)
                    else:
                        print 'section %s:\n' % (sectname)
                        section.dump_header()
                        print '%s\n' % (section)
                        dump_memory (0, sect_bytes, 16, sys.stdout)
                else:
                    print 'error: no section named "%s" was found' % (sectname)

        def get_segment(self, segname):
            if len(self.segments) == 1 and self.segments[0].segname == '':
                return self.segments[0]
            for segment in self.segments:
                if segment.segname == segname:
                    return segment
            return None

        def get_first_load_command(self, lc_enum_value):
            for lc in self.commands:
                if lc.command.value == lc_enum_value:
                    return lc
            return None

        def get_symtab(self):
            if self.data and not self.symbols:
                lc_symtab = self.get_first_load_command (LC_SYMTAB)
                if lc_symtab:
                    symtab_offset = self.file_off
                    if self.data.is_in_memory():
                        linkedit_segment = self.get_segment('__LINKEDIT')
                        if linkedit_segment:
                            linkedit_vmaddr = linkedit_segment.vmaddr
                            linkedit_fileoff = linkedit_segment.fileoff
                            symtab_offset = linkedit_vmaddr + lc_symtab.symoff - linkedit_fileoff
                            symtab_offset = linkedit_vmaddr + lc_symtab.stroff - linkedit_fileoff
                    else:
                        symtab_offset += lc_symtab.symoff

                    self.data.seek (symtab_offset)
                    is_64 = self.is_64_bit()
                    for i in range(lc_symtab.nsyms):
                        nlist = Mach.NList()
                        nlist.unpack (self, self.data, lc_symtab)
                        self.symbols.append(nlist)
                else:
                    print "no LC_SYMTAB"
            return self.symbols

        def dump_symtab(self, dump_description = True, options = None):
            symbols = self.get_symtab()
            if dump_description:
                print self.description()
            for i, symbol in enumerate(symbols):
                print '[%5u] %s' % (i, symbol)

        def dump_symbol_names_matching_regex(self, regex, file=None):
            symbols = self.get_symtab()
            for symbol in symbols:
                if symbol.name and regex.search (symbol.name):
                    print symbol.name
                    if file:
                        file.write('%s\n' % (symbol.name))

        def is_64_bit(self):
            return self.magic.is_64_bit()

    class LoadCommand:
        class Command(dict_utils.Enum):
            enum = {
                'LC_SEGMENT'                : LC_SEGMENT,
                'LC_SYMTAB'                 : LC_SYMTAB,
                'LC_SYMSEG'                 : LC_SYMSEG,
                'LC_THREAD'                 : LC_THREAD,
                'LC_UNIXTHREAD'             : LC_UNIXTHREAD,
                'LC_LOADFVMLIB'             : LC_LOADFVMLIB,
                'LC_IDFVMLIB'               : LC_IDFVMLIB,
                'LC_IDENT'                  : LC_IDENT,
                'LC_FVMFILE'                : LC_FVMFILE,
                'LC_PREPAGE'                : LC_PREPAGE,
                'LC_DYSYMTAB'               : LC_DYSYMTAB,
                'LC_LOAD_DYLIB'             : LC_LOAD_DYLIB,
                'LC_ID_DYLIB'               : LC_ID_DYLIB,
                'LC_LOAD_DYLINKER'          : LC_LOAD_DYLINKER,
                'LC_ID_DYLINKER'            : LC_ID_DYLINKER,
                'LC_PREBOUND_DYLIB'         : LC_PREBOUND_DYLIB,
                'LC_ROUTINES'               : LC_ROUTINES,
                'LC_SUB_FRAMEWORK'          : LC_SUB_FRAMEWORK,
                'LC_SUB_UMBRELLA'           : LC_SUB_UMBRELLA,
                'LC_SUB_CLIENT'             : LC_SUB_CLIENT,
                'LC_SUB_LIBRARY'            : LC_SUB_LIBRARY,
                'LC_TWOLEVEL_HINTS'         : LC_TWOLEVEL_HINTS,
                'LC_PREBIND_CKSUM'          : LC_PREBIND_CKSUM,
                'LC_LOAD_WEAK_DYLIB'        : LC_LOAD_WEAK_DYLIB,
                'LC_SEGMENT_64'             : LC_SEGMENT_64,
                'LC_ROUTINES_64'            : LC_ROUTINES_64,
                'LC_UUID'                   : LC_UUID,
                'LC_RPATH'                  : LC_RPATH,
                'LC_CODE_SIGNATURE'         : LC_CODE_SIGNATURE,
                'LC_SEGMENT_SPLIT_INFO'     : LC_SEGMENT_SPLIT_INFO,
                'LC_REEXPORT_DYLIB'         : LC_REEXPORT_DYLIB,
                'LC_LAZY_LOAD_DYLIB'        : LC_LAZY_LOAD_DYLIB,
                'LC_ENCRYPTION_INFO'        : LC_ENCRYPTION_INFO,
                'LC_DYLD_INFO'              : LC_DYLD_INFO,
                'LC_DYLD_INFO_ONLY'         : LC_DYLD_INFO_ONLY,
                'LC_LOAD_UPWARD_DYLIB'      : LC_LOAD_UPWARD_DYLIB,
                'LC_VERSION_MIN_MACOSX'     : LC_VERSION_MIN_MACOSX,
                'LC_VERSION_MIN_IPHONEOS'   : LC_VERSION_MIN_IPHONEOS,
                'LC_FUNCTION_STARTS'        : LC_FUNCTION_STARTS,
                'LC_DYLD_ENVIRONMENT'       : LC_DYLD_ENVIRONMENT,
                'LC_MAIN'                    : LC_MAIN,
                'LC_DATA_IN_CODE'            : LC_DATA_IN_CODE,
                'LC_SOURCE_VERSION'          : LC_SOURCE_VERSION,
                'LC_DYLIB_CODE_SIGN_DRS'     : LC_DYLIB_CODE_SIGN_DRS,
                'LC_ENCRYPTION_INFO_64'      : LC_ENCRYPTION_INFO_64,
                'LC_LINKER_OPTION'           : LC_LINKER_OPTION,
                'LC_LINKER_OPTIMIZATION_HINT': LC_LINKER_OPTIMIZATION_HINT,
                'LC_VERSION_MIN_TVOS'        : LC_VERSION_MIN_TVOS,
                'LC_VERSION_MIN_WATCHOS'     : LC_VERSION_MIN_WATCHOS
            }

            def __init__(self, initial_value = 0):
                dict_utils.Enum.__init__(self, initial_value, self.enum)


        def __init__(self, c=None, l=0,o=0):
            if c != None:
                self.command = c
            else:
                self.command = Mach.LoadCommand.Command(0)
            self.length = l
            self.file_off = o

        def get_item_dictionary(self):
            return { '#0' : str(self.command),
                     'children' : callable(getattr(self, "get_child_item_dictionaries", None)),
                     'tree-item-delegate' : self }

        def unpack(self, mach_file, data):
            self.file_off = data.tell()
            self.command.value, self.length = data.get_n_uint32(2)

        def skip(self, data):
            data.seek (self.file_off + self.length, 0)

        def __str__(self):
            lc_name = self.command.get_enum_name()
            return '%#8.8x: <%#4.4x> %-24s' % (self.file_off, self.length, lc_name)

    class Section:

        class Type(dict_utils.Enum):
            enum = {
                'S_REGULAR'                             : S_REGULAR                             ,
                'S_ZEROFILL'		                    : S_ZEROFILL		                    ,
                'S_CSTRING_LITERALS'	                : S_CSTRING_LITERALS	                ,
                'S_4BYTE_LITERALS'	                    : S_4BYTE_LITERALS	                    ,
                'S_8BYTE_LITERALS'	                    : S_8BYTE_LITERALS	                    ,
                'S_LITERAL_POINTERS'	                : S_LITERAL_POINTERS	                ,
                'S_NON_LAZY_SYMBOL_POINTERS'            : S_NON_LAZY_SYMBOL_POINTERS            ,
                'S_LAZY_SYMBOL_POINTERS'		        : S_LAZY_SYMBOL_POINTERS		        ,
                'S_SYMBOL_STUBS'			            : S_SYMBOL_STUBS			            ,
                'S_MOD_INIT_FUNC_POINTERS'	            : S_MOD_INIT_FUNC_POINTERS	            ,
                'S_MOD_TERM_FUNC_POINTERS'	            : S_MOD_TERM_FUNC_POINTERS	            ,
                'S_COALESCED'			                : S_COALESCED			                ,
                'S_GB_ZEROFILL'			                : S_GB_ZEROFILL			                ,
                'S_INTERPOSING'			                : S_INTERPOSING			                ,
                'S_16BYTE_LITERALS'		                : S_16BYTE_LITERALS		                ,
                'S_DTRACE_DOF'			                : S_DTRACE_DOF			                ,
                'S_LAZY_DYLIB_SYMBOL_POINTERS'	        : S_LAZY_DYLIB_SYMBOL_POINTERS	        ,
                'S_THREAD_LOCAL_REGULAR'                : S_THREAD_LOCAL_REGULAR                ,
                'S_THREAD_LOCAL_ZEROFILL'               : S_THREAD_LOCAL_ZEROFILL               ,
                'S_THREAD_LOCAL_VARIABLES'              : S_THREAD_LOCAL_VARIABLES              ,
                'S_THREAD_LOCAL_VARIABLE_POINTERS'      : S_THREAD_LOCAL_VARIABLE_POINTERS      ,
                'S_THREAD_LOCAL_INIT_FUNCTION_POINTERS' : S_THREAD_LOCAL_INIT_FUNCTION_POINTERS
            }

            def __init__(self, t = 0):
                dict_utils.Enum.__init__(self, t, self.enum)

        def __init__(self):
            self.file_offset = 0
            self.index = 0
            self.is_64 = False
            self.sectname = None
            self.segname = None
            self.addr = 0
            self.size = 0
            self.offset = 0
            self.align = 0
            self.reloff = 0
            self.nreloc = 0
            self.flags = 0
            self.reserved1 = 0
            self.reserved2 = 0
            self.reserved3 = 0

        def get_item_dictionary(self):
            summary = None
            if self.size:
                summary = address_range_to_str(self.addr, self.addr + self.size, self.is_64)

            if summary:
                summary = summary + ' ' + self.get_type_as_string()
            else:
                summary = self.get_type_as_string()

            return { '#0' : str(self.index),
                     'value': self.sectname,
                     'summary' : summary,
                     'children' : True,
                     'tree-item-delegate' : self }

        def get_type_as_string(self):
            return str(Mach.Section.Type(self.flags & SECTION_TYPE))

        def get_attributes_as_string(self):
            attrs = list()
            if self.flags & S_ATTR_PURE_INSTRUCTIONS:
                attrs.append('S_ATTR_PURE_INSTRUCTIONS')
            if self.flags & S_ATTR_NO_TOC:
                attrs.append('S_ATTR_NO_TOC')
            if self.flags & S_ATTR_STRIP_STATIC_SYMS:
                attrs.append('S_ATTR_STRIP_STATIC_SYMS')
            if self.flags & S_ATTR_NO_DEAD_STRIP:
                attrs.append('S_ATTR_NO_DEAD_STRIP')
            if self.flags & S_ATTR_LIVE_SUPPORT:
                attrs.append('S_ATTR_LIVE_SUPPORT')
            if self.flags & S_ATTR_SELF_MODIFYING_CODE:
                attrs.append('S_ATTR_SELF_MODIFYING_CODE')
            if self.flags & S_ATTR_DEBUG:
                attrs.append('S_ATTR_DEBUG')
            if self.flags & S_ATTR_SOME_INSTRUCTIONS:
                attrs.append('S_ATTR_SOME_INSTRUCTIONS')
            if self.flags & S_ATTR_EXT_RELOC:
                attrs.append('S_ATTR_EXT_RELOC')
            if self.flags & S_ATTR_LOC_RELOC:
                attrs.append('S_ATTR_LOC_RELOC')
            return ' | '.join(attrs)

        def get_flags_as_string(self):
            type_str = self.get_type_as_string()
            attr_str = self.get_attributes_as_string()
            if len(attr_str):
                return 'type = ' + type_str + ', attrs = ' + attr_str
            else:
                return 'type = ' + type_str

        def get_child_item_dictionaries(self):
            item_dicts = list()
            item_dicts.append({ '#0' : 'sectname'   , 'value': self.sectname})
            item_dicts.append({ '#0' : 'segname'    , 'value': self.segname})
            item_dicts.append({ '#0' : 'addr'       , 'value': address_to_str(self.addr, self.is_64)})
            item_dicts.append({ '#0' : 'size'       , 'value': address_to_str(self.size, self.is_64), 'summary' : str(self.size)})
            item_dicts.append({ '#0' : 'offset'     , 'value': int_to_hex32(self.offset)})
            item_dicts.append({ '#0' : 'align'      , 'value': int_to_hex32(self.align), 'summary' : str(self.align)})
            item_dicts.append({ '#0' : 'reloff'     , 'value': int_to_hex32(self.reloff)})
            item_dicts.append({ '#0' : 'nreloc'     , 'value': int_to_hex32(self.nreloc), 'summary' : str(self.nreloc)})
            item_dicts.append({ '#0' : 'flags'      , 'value': int_to_hex32(self.flags), 'summary' : self.get_flags_as_string() })
            item_dicts.append({ '#0' : 'reserved1'  , 'value': int_to_hex32(self.reserved1), 'summary' : str(self.reserved1)})
            item_dicts.append({ '#0' : 'reserved2'  , 'value': int_to_hex32(self.reserved2), 'summary' : str(self.reserved2)})
            if self.is_64:
                item_dicts.append({ '#0' : 'reserved3'  , 'value': int_to_hex32(self.reserved3), 'summary' : str(self.reserved3)})
            return item_dicts

        def unpack(self, is_64, data):
            self.file_offset = data.tell()
            self.is_64 = is_64
            self.sectname = data.get_fixed_length_c_string (16, '', True)
            self.segname = data.get_fixed_length_c_string (16, '', True)
            if self.is_64:
                self.addr, self.size = data.get_n_uint64(2)
                self.offset, self.align, self.reloff, self.nreloc, self.flags, self.reserved1, self.reserved2, self.reserved3 = data.get_n_uint32(8)
            else:
                self.addr, self.size = data.get_n_uint32(2)
                self.offset, self.align, self.reloff, self.nreloc, self.flags, self.reserved1, self.reserved2 = data.get_n_uint32(7)

        def dump_header(self):
            if self.is_64:
                print "FILE OFF    INDEX ADDRESS            SIZE               OFFSET     ALIGN      RELOFF     NRELOC     FLAGS      RESERVED1  RESERVED2  RESERVED3  NAME"
                print "=========== ===== ------------------ ------------------ ---------- ---------- ---------- ---------- ---------- ---------- ---------- ---------- ----------------------"
            else:
                print "FILE OFF    INDEX ADDRESS    SIZE       OFFSET     ALIGN      RELOFF     NRELOC     FLAGS      RESERVED1  RESERVED2  NAME"
                print "=========== ===== ---------- ---------- ---------- ---------- ---------- ---------- ---------- ---------- ---------- ----------------------"

        def __str__(self):
            if self.is_64:
                return "0x%8.8x: [%3u] %#16.16x %#16.16x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %s.%s" % (self.file_offset, self.index, self.addr, self.size, self.offset, self.align, self.reloff, self.nreloc, self.flags, self.reserved1, self.reserved2, self.reserved3, self.segname, self.sectname)
            else:
                return "0x%8.8x: [%3u] %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %s.%s" % (self.file_offset, self.index, self.addr, self.size, self.offset, self.align, self.reloff, self.nreloc, self.flags, self.reserved1, self.reserved2, self.segname, self.sectname)

        def get_contents(self, mach_file):
            '''Get the section contents as a python string'''
            if self.size > 0 and mach_file.get_segment(self.segname).filesize > 0:
                data = mach_file.get_data()
                if data:
                    section_data_offset = mach_file.file_off + self.offset
                    #print '%s.%s is at offset 0x%x with size 0x%x' % (self.segname, self.sectname, section_data_offset, self.size)
                    data.push_offset_and_seek (section_data_offset)
                    bytes = data.read_size(self.size)
                    data.pop_offset_and_seek()
                    return bytes
            return None

        def get_contents_as_extractor(self, mach_file):
            bytes = self.get_contents(mach_file)
            return file_extract.FileExtract(StringIO.StringIO(bytes),
                                            mach_file.data.get_byte_order(),
                                            mach_file.data.get_addr_size())

    class DylibLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.name = None
            self.timestamp = 0
            self.current_version = 0
            self.compatibility_version = 0

        def unpack(self, mach_file, data):
            byte_order_char = mach_file.magic.get_byte_order()
            name_offset, self.timestamp, self.current_version, self.compatibility_version = data.get_n_uint32(4)
            data.seek(self.file_off + name_offset, 0)
            self.name = data.get_fixed_length_c_string(self.length - 24)

        def get_item_dictionary(self):
            item_dict = Mach.LoadCommand.get_item_dictionary(self)
            item_dict['summary'] = self.name
            return item_dict

        def get_child_item_dictionaries(self):
            item_dicts = list()
            item_dicts.append({ '#0' : 'name'                   , 'value': self.name })
            item_dicts.append({ '#0' : 'timestamp'              , 'value': int_to_hex32(self.timestamp) })
            item_dicts.append({ '#0' : 'current_version'        , 'value': get_version32_as_string(self.current_version) })
            item_dicts.append({ '#0' : 'compatibility_version'  , 'value': get_version32_as_string(self.compatibility_version) })
            return item_dicts

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "timestamp = %#8.8x, current_version = %10s, compatibility_version = %10s, name = '" % (self.timestamp, get_version32_as_string(self.current_version), get_version32_as_string(self.compatibility_version))
            s += self.name + "'"
            return s

    class LoadDYLDLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.name = None

        def unpack(self, mach_file, data):
            data.get_uint32()
            self.name = data.get_fixed_length_c_string(self.length - 12)

        def get_item_dictionary(self):
            item_dict = Mach.LoadCommand.get_item_dictionary(self)
            item_dict['summary'] = self.name
            return item_dict

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "%s" % self.name
            return s

    class UnixThreadLoadCommand(LoadCommand):
        class ThreadState:
            def __init__(self):
                self.flavor = 0
                self.count = 0
                self.register_values = list()

            def unpack(self, data):
                self.flavor, self.count = data.get_n_uint32(2)
                self.register_values = data.get_n_uint32(self.count)

            def __str__(self):
                s = "flavor = %u, count = %u, regs =" % (self.flavor, self.count)
                i = 0
                for register_value in self.register_values:
                    if i % 8 == 0:
                        s += "\n                                            "
                    s += " %#8.8x" % register_value
                    i += 1
                return s

        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.reg_sets = list()

        def unpack(self, mach_file, data):
            reg_set = Mach.UnixThreadLoadCommand.ThreadState()
            reg_set.unpack (data)
            self.reg_sets.append(reg_set)

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            for reg_set in self.reg_sets:
                s += "%s" % reg_set
            return s

    class DYLDInfoOnlyLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.rebase_off = 0
            self.rebase_size = 0
            self.bind_off = 0
            self.bind_size = 0
            self.weak_bind_off = 0
            self.weak_bind_size = 0
            self.lazy_bind_off = 0
            self.lazy_bind_size = 0
            self.export_off = 0
            self.export_size = 0

        def unpack(self, mach_file, data):
            byte_order_char = mach_file.magic.get_byte_order()
            self.rebase_off, self.rebase_size, self.bind_off, self.bind_size, self.weak_bind_off, self.weak_bind_size, self.lazy_bind_off, self.lazy_bind_size, self.export_off, self.export_size = data.get_n_uint32(10)

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "rebase_off     = %#8.8x, rebase_size    = %u\n" % (self.rebase_off, self.rebase_size)
            s += "                                             bind_off       = %#8.8x, bind_size      = %u\n" % (self.bind_off, self.bind_size)
            s += "                                             weak_bind_off  = %#8.8x, weak_bind_size = %u\n" % (self.weak_bind_off, self.weak_bind_size)
            s += "                                             lazy_bind_off  = %#8.8x, lazy_bind_size = %u\n" % (self.lazy_bind_off, self.lazy_bind_size)
            s += "                                             export_off     = %#8.8x, export_size    = %u" % (self.export_off, self.export_size)
            return s

    class DYLDSymtabLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.ilocalsym      = 0
            self.nlocalsym      = 0
            self.iextdefsym     = 0
            self.nextdefsym     = 0
            self.iundefsym      = 0
            self.nundefsym      = 0
            self.tocoff         = 0
            self.ntoc           = 0
            self.modtaboff      = 0
            self.nmodtab        = 0
            self.extrefsymoff   = 0
            self.nextrefsyms    = 0
            self.indirectsymoff = 0
            self.nindirectsyms  = 0
            self.extreloff      = 0
            self.nextrel        = 0
            self.locreloff      = 0
            self.nlocrel        = 0

        def unpack(self, mach_file, data):
            byte_order_char = mach_file.magic.get_byte_order()
            self.ilocalsym, self.nlocalsym, self.iextdefsym, self.nextdefsym, self.iundefsym, self.nundefsym, self.tocoff, self.ntoc, self.modtaboff, self.nmodtab, self.extrefsymoff, self.nextrefsyms, self.indirectsymoff, self.nindirectsyms, self.extreloff, self.nextrel, self.locreloff, self.nlocrel = data.get_n_uint32(18)

        def get_child_item_dictionaries(self):
            item_dicts = list()
            item_dicts.append({ '#0' : 'ilocalsym'      , 'value': str(self.ilocalsym) })
            item_dicts.append({ '#0' : 'nlocalsym'      , 'value': str(self.nlocalsym) })
            item_dicts.append({ '#0' : 'iextdefsym'     , 'value': str(self.iextdefsym) })
            item_dicts.append({ '#0' : 'nextdefsym'     , 'value': str(self.nextdefsym) })
            item_dicts.append({ '#0' : 'iundefsym'      , 'value': str(self.iundefsym) })
            item_dicts.append({ '#0' : 'nundefsym'      , 'value': str(self.nundefsym) })
            item_dicts.append({ '#0' : 'tocoff'         , 'value': str(self.tocoff) })
            item_dicts.append({ '#0' : 'ntoc'           , 'value': str(self.ntoc) })
            item_dicts.append({ '#0' : 'modtaboff'      , 'value': int_to_hex32(self.modtaboff) })
            item_dicts.append({ '#0' : 'nmodtab'        , 'value': str(self.nmodtab) })
            item_dicts.append({ '#0' : 'extrefsymoff'   , 'value': int_to_hex32(self.extrefsymoff) })
            item_dicts.append({ '#0' : 'nextrefsyms'    , 'value': str(self.nextrefsyms) })
            item_dicts.append({ '#0' : 'indirectsymoff' , 'value': int_to_hex32(self.indirectsymoff) })
            item_dicts.append({ '#0' : 'nindirectsyms'  , 'value': str(self.nindirectsyms) })
            item_dicts.append({ '#0' : 'extreloff'      , 'value': int_to_hex32(self.extreloff) })
            item_dicts.append({ '#0' : 'nextrel'        , 'value': str(self.nextrel) })
            item_dicts.append({ '#0' : 'locreloff'      , 'value': int_to_hex32(self.locreloff) })
            item_dicts.append({ '#0' : 'nlocrel'        , 'value': str(self.nlocrel) })
            return item_dicts

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            # s += "ilocalsym = %u, nlocalsym = %u, " % (self.ilocalsym, self.nlocalsym)
            # s += "iextdefsym = %u, nextdefsym = %u, " % (self.iextdefsym, self.nextdefsym)
            # s += "iundefsym %u, nundefsym = %u, " % (self.iundefsym, self.nundefsym)
            # s += "tocoff = %#8.8x, ntoc = %u, " % (self.tocoff, self.ntoc)
            # s += "modtaboff = %#8.8x, nmodtab = %u, " % (self.modtaboff, self.nmodtab)
            # s += "extrefsymoff = %#8.8x, nextrefsyms = %u, " % (self.extrefsymoff, self.nextrefsyms)
            # s += "indirectsymoff = %#8.8x, nindirectsyms = %u, " % (self.indirectsymoff, self.nindirectsyms)
            # s += "extreloff = %#8.8x, nextrel = %u, " % (self.extreloff, self.nextrel)
            # s += "locreloff = %#8.8x, nlocrel = %u" % (self.locreloff, self.nlocrel)
            s += "ilocalsym      = %-10u, nlocalsym      = %u\n" % (self.ilocalsym, self.nlocalsym)
            s += "                                             iextdefsym     = %-10u, nextdefsym     = %u\n" % (self.iextdefsym, self.nextdefsym)
            s += "                                             iundefsym      = %-10u, nundefsym      = %u\n" % (self.iundefsym, self.nundefsym)
            s += "                                             tocoff         = %#8.8x, ntoc           = %u\n" % (self.tocoff, self.ntoc)
            s += "                                             modtaboff      = %#8.8x, nmodtab        = %u\n" % (self.modtaboff, self.nmodtab)
            s += "                                             extrefsymoff   = %#8.8x, nextrefsyms    = %u\n" % (self.extrefsymoff, self.nextrefsyms)
            s += "                                             indirectsymoff = %#8.8x, nindirectsyms  = %u\n" % (self.indirectsymoff, self.nindirectsyms)
            s += "                                             extreloff      = %#8.8x, nextrel        = %u\n" % (self.extreloff, self.nextrel)
            s += "                                             locreloff      = %#8.8x, nlocrel        = %u" % (self.locreloff, self.nlocrel)
            return s

    class SymtabLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.symoff  = 0
            self.nsyms   = 0
            self.stroff  = 0
            self.strsize = 0

        def get_item_dictionary(self):
            item_dict = Mach.LoadCommand.get_item_dictionary(self)
            item_dict['summary'] = "%u symbols" % (self.nsyms)
            return item_dict

        def get_child_item_dictionaries(self):
            item_dicts = list()
            item_dicts.append({ '#0' : 'symoff' , 'value': int_to_hex32(self.symoff)})
            item_dicts.append({ '#0' : 'nsyms'  , 'value': int_to_hex32(self.nsyms), 'summary' : str(self.nsyms)})
            item_dicts.append({ '#0' : 'stroff' , 'value': int_to_hex32(self.stroff)})
            item_dicts.append({ '#0' : 'strsize', 'value': int_to_hex32(self.strsize), 'summary' : str(self.strsize)})
            return item_dicts

        def unpack(self, mach_file, data):
            byte_order_char = mach_file.magic.get_byte_order()
            self.symoff, self.nsyms, self.stroff, self.strsize = data.get_n_uint32(4)

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "symoff         = %#8.8x, nsyms          = %u\n" % (self.symoff, self.nsyms)
            s += "                                             stroff         = %#8.8x, strsize        = %u" % (self.stroff, self.strsize)
            return s


    class UUIDLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.uuid = None

        def get_item_dictionary(self):
            item_dict = Mach.LoadCommand.get_item_dictionary(self)
            item_dict['summary'] = self.uuid.__str__().upper()
            return item_dict

        def unpack(self, mach_file, data):
            uuid_data = data.get_n_uint8(16)
            uuid_str = ''
            for byte in uuid_data:
                uuid_str += '%2.2x' % byte
            self.uuid = uuid.UUID(uuid_str)
            mach_file.uuid = self.uuid

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += self.uuid.__str__().upper()
            return s

    class DataBlobLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.dataoff = 0
            self.datasize = 0
            self.data = None

        def get_child_item_dictionaries(self):
            item_dicts = list()
            item_dicts.append({ '#0' : 'dataoff' , 'value': int_to_hex32(self.dataoff) })
            item_dicts.append({ '#0' : 'datasize', 'value': int_to_hex32(self.datasize), 'summary' : str(self.datasize)})
            return item_dicts

        def unpack(self, mach_file, data):
            byte_order_char = mach_file.magic.get_byte_order()
            self.dataoff, self.datasize = data.get_n_uint32(2)
            if self.datasize > 0:
                data.seek(self.dataoff, 0)
                self.data = data.read_size(self.datasize)

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "dataoff = %#8.8x, datasize = %#8.8x (%u)" % (self.dataoff, self.datasize, self.datasize)
            # if self.data:
            #     string_strm = StringIO.StringIO()
            #     dump_memory (0, self.data, 16, string_strm)
            #     s += "\n" + string_strm.getvalue()
            return s

    class EncryptionInfoLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.cryptoff = 0
            self.cryptsize = 0
            self.cryptid = 0

        def unpack(self, mach_file, data):
            byte_order_char = mach_file.magic.get_byte_order()
            self.cryptoff, self.cryptsize, self.cryptid = data.get_n_uint32(3)

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "file-range = [%#8.8x - %#8.8x), cryptsize = %u, cryptid = %u" % (self.cryptoff, self.cryptoff + self.cryptsize, self.cryptsize, self.cryptid)
            return s

    class SegmentLoadCommand(LoadCommand):

        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.segname  = None
            self.vmaddr   = 0
            self.vmsize   = 0
            self.fileoff  = 0
            self.filesize = 0
            self.maxprot  = 0
            self.initprot = 0
            self.nsects   = 0
            self.flags    = 0
            self.sections = list()
            self.section_delegate = None

        def get_item_dictionary(self):
            item_dict = Mach.LoadCommand.get_item_dictionary(self)
            item_dict['value'] = self.segname
            is_64 = self.command.get_enum_value() == LC_SEGMENT_64
            if is_64:
                item_dict['summary'] = "[0x%16.16x - 0x%16.16x) %s" % (self.vmaddr, self.vmaddr + self.vmsize, (vm_prot_names[self.initprot]))
            else:
                item_dict['summary'] = "[0x%8.8x - 0x%8.8x) %s" % (self.vmaddr, self.vmaddr + self.vmsize, (vm_prot_names[self.initprot]))
            return item_dict

        def get_child_item_dictionaries(self):
            is_64 = self.command.get_enum_value() == LC_SEGMENT_64

            item_dicts = list()
            if len(self.sections) > 0:
                if self.section_delegate is None:
                    self.section_delegate = SectionListTreeItemDelegate(self.sections, False)
                item_dicts.append(self.section_delegate.get_item_dictionary())
            item_dicts.append({ '#0' : 'segname'    ,    'value': self.segname })
            if is_64:
                item_dicts.append({ '#0' : 'vmaddr'     ,  'value': int_to_hex64(self.vmaddr) })
                item_dicts.append({ '#0' : 'vmsize'     ,  'value': int_to_hex64(self.vmsize), 'summary' : str(self.vmsize)})
                item_dicts.append({ '#0' : 'fileoff'    ,  'value': int_to_hex64(self.fileoff) })
                item_dicts.append({ '#0' : 'filesize'   ,  'value': int_to_hex64(self.filesize), 'summary' : str(self.filesize) })
            else:
                item_dicts.append({ '#0' : 'vmaddr'     ,  'value': int_to_hex32(self.vmaddr) })
                item_dicts.append({ '#0' : 'vmsize'     ,  'value': int_to_hex32(self.vmsize), 'summary' : str(self.vmsize)})
                item_dicts.append({ '#0' : 'fileoff'    ,  'value': int_to_hex32(self.fileoff)})
                item_dicts.append({ '#0' : 'filesize'   ,  'value': int_to_hex32(self.filesize), 'summary' : str(self.filesize)})
            item_dicts.append({ '#0' : 'maxprot'    ,  'value': int_to_hex32(self.maxprot), 'summary' : "%s" % (vm_prot_names[self.maxprot]) })
            item_dicts.append({ '#0' : 'initprot'   ,  'value':  int_to_hex32(self.initprot), 'summary' : "%s" % (vm_prot_names[self.initprot]) })
            item_dicts.append({ '#0' : 'nsects'     ,  'value': int_to_hex32(self.nsects), 'summary' : str(self.nsects) })
            item_dicts.append({ '#0' : 'flags'      ,  'value': int_to_hex32(self.flags), 'summary' : self.get_flags_as_string() })
            return item_dicts

        def unpack(self, mach_file, data):
            is_64 = self.command.get_enum_value() == LC_SEGMENT_64
            self.segname = data.get_fixed_length_c_string (16, '', True)
            if is_64:
                self.vmaddr, self.vmsize, self.fileoff, self.filesize = data.get_n_uint64(4)
            else:
                self.vmaddr, self.vmsize, self.fileoff, self.filesize = data.get_n_uint32(4)
            self.maxprot, self.initprot, self.nsects, self.flags = data.get_n_uint32(4)
            mach_file.segments.append(self)
            for i in range(self.nsects):
                section = Mach.Section()
                section.unpack(is_64, data)
                section.index = len (mach_file.sections)
                mach_file.sections.append(section)
                self.sections.append(section)

        def get_flags_as_string(self):
            flag_strings = list()
            if self.flags & SG_HIGHVM:
                flag_strings.append('SG_HIGHVM')
            if self.flags & SG_FVMLIB:
                flag_strings.append('SG_HIGHVM')
            if self.flags & SG_NORELOC:
                flag_strings.append('SG_HIGHVM')
            if self.flags & SG_PROTECTED_VERSION_1:
                flag_strings.append('SG_HIGHVM')
            if len(flag_strings):
                return ' | '.join(flag_strings)
            else:
                return ''

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            if self.command.get_enum_value() == LC_SEGMENT:
                s += "%#8.8x %#8.8x %#8.8x %#8.8x " % (self.vmaddr, self.vmsize, self.fileoff, self.filesize)
            else:
                s += "%#16.16x %#16.16x %#16.16x %#16.16x " % (self.vmaddr, self.vmsize, self.fileoff, self.filesize)
            s += "%s %s %3u %#8.8x" % (vm_prot_names[self.maxprot], vm_prot_names[self.initprot], self.nsects, self.flags)
            s += ' ' + self.segname
            return s

    class VersionMinLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.version = 0
            self.sdk = 0

        def get_item_dictionary(self):
            item_dict = Mach.LoadCommand.get_item_dictionary(self)
            item_dict['summary'] = "version = %s, sdk = %s" % (get_version32_as_string(self.version), get_version32_as_string(self.sdk))
            return item_dict

        def unpack(self, mach_file, data):
            self.version, self.sdk = data.get_n_uint32(2)

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "version = %s, sdk = %s" % (get_version32_as_string(self.version), get_version32_as_string(self.sdk))
            return s

    class SourceVersionLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.version = 0

        def get_item_dictionary(self):
            item_dict = Mach.LoadCommand.get_item_dictionary(self)
            v = self.version
            item_dict['summary'] = "version = %u.%u.%u.%u.%u" % ((v >> 40) & 0xFFFFFFFFFF, (v >> 30) & 0x3ff, (v >> 20) & 0x3ff, (v >> 10) & 0x3ff, v & 0x3ff)
            return item_dict

        def unpack(self, mach_file, data):
            self.version = data.get_uint64()

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            v = self.version
            s += "version = %u.%u.%u.%u.%u" % ((v >> 40) & 0xFFFFFFFFFF, (v >> 30) & 0x3ff, (v >> 20) & 0x3ff, (v >> 10) & 0x3ff, v & 0x3ff)
            return s

    class LinkerOptionLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.options = []

        def unpack(self, mach_file, data):
            num_options = data.get_uint32()
            for i in range(num_options):
                self.options.append(data.get_c_string())

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            for opt in self.options:
                s += '"%s" ' % (opt)
            return s

    class MainLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.entryoff = 0
            self.stacksize = 0

        def unpack(self, mach_file, data):
            self.entryoff, self.stacksize = data.get_n_uint64(2)

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "entryoff = %#8.8x, stacksize = %u" % (self.entryoff, self.stacksize)
            return s

    class NList:
        class Type:
            class Stab(dict_utils.Enum):
                enum = {
                    'N_GSYM'    : N_GSYM    ,
                    'N_FNAME'   : N_FNAME   ,
                    'N_FUN'     : N_FUN     ,
                    'N_STSYM'   : N_STSYM   ,
                    'N_LCSYM'   : N_LCSYM   ,
                    'N_BNSYM'   : N_BNSYM   ,
                    'N_OPT'     : N_OPT     ,
                    'N_RSYM'    : N_RSYM    ,
                    'N_SLINE'   : N_SLINE   ,
                    'N_ENSYM'   : N_ENSYM   ,
                    'N_SSYM'    : N_SSYM    ,
                    'N_SO'      : N_SO      ,
                    'N_OSO'     : N_OSO     ,
                    'N_LSYM'    : N_LSYM    ,
                    'N_BINCL'   : N_BINCL   ,
                    'N_SOL'     : N_SOL     ,
                    'N_PARAMS'  : N_PARAMS  ,
                    'N_VERSION' : N_VERSION ,
                    'N_OLEVEL'  : N_OLEVEL  ,
                    'N_PSYM'    : N_PSYM    ,
                    'N_EINCL'   : N_EINCL   ,
                    'N_ENTRY'   : N_ENTRY   ,
                    'N_LBRAC'   : N_LBRAC   ,
                    'N_EXCL'    : N_EXCL    ,
                    'N_RBRAC'   : N_RBRAC   ,
                    'N_BCOMM'   : N_BCOMM   ,
                    'N_ECOMM'   : N_ECOMM   ,
                    'N_ECOML'   : N_ECOML   ,
                    'N_LENG'    : N_LENG
                }

                def __init__(self, magic = 0):
                    dict_utils.Enum.__init__(self, magic, self.enum)

            def __init__(self, t = 0):
                self.value = t

            def sect_idx_is_section_index(self):
                if self.value & N_STAB:
                    return False
                return (self.value & N_TYPE) == N_SECT

            def get_type_as_string(self):
                n_type = self.value
                if n_type & N_STAB:
                    return str(Mach.NList.Type.Stab(self.value))
                else:
                    type = self.value & N_TYPE
                    if type == N_UNDF:
                        return 'N_UNDF'
                    elif type == N_ABS:
                        return 'N_ABS '
                    elif type == N_SECT:
                        return 'N_SECT'
                    elif type == N_PBUD:
                        return 'N_PBUD'
                    elif type == N_INDR:
                        return 'N_INDR'
                    else:
                        return "??? (%#2.2x)" % type

            def get_flags_as_string(self):
                n_type = self.value
                if n_type & N_STAB == 0:
                    if n_type & N_PEXT:
                        if n_type & N_EXT:
                            return 'N_PEXT | N_EXT'
                        else:
                            return 'N_PEXT'
                    elif n_type & N_EXT:
                        return 'N_EXT'
                return ''

            def __str__(self):
                n_type = self.value
                if n_type & N_STAB:
                    stab = Mach.NList.Type.Stab(self.value)
                    return '%s' % stab
                else:
                    type = self.value & N_TYPE
                    type_str = ''
                    if type == N_UNDF:
                        type_str = 'N_UNDF'
                    elif type == N_ABS:
                        type_str = 'N_ABS '
                    elif type == N_SECT:
                        type_str = 'N_SECT'
                    elif type == N_PBUD:
                        type_str = 'N_PBUD'
                    elif type == N_INDR:
                        type_str = 'N_INDR'
                    else:
                        type_str = "??? (%#2.2x)" % type
                    if n_type & N_PEXT:
                        type_str += ' | PEXT'
                    if n_type & N_EXT:
                        type_str += ' | EXT '
                    return type_str


        def __init__(self):
            self.index = 0
            self.name_offset = 0
            self.name = 0
            self.type = Mach.NList.Type()
            self.sect_idx = 0
            self.desc = 0
            self.value = 0

        def sect_idx_is_section_index(self):
            return self.type.sect_idx_is_section_index()

        def get_item_dictionary(self):
            name = "Load Commands"
            item_dict = { '#0' : str(self.index),
                          'name_offset': int_to_hex32(self.name_offset),
                          'type': self.type.get_type_as_string(),
                          'flags' : self.type.get_flags_as_string(),
                          'sect_idx': self.sect_idx,
                          'desc': int_to_hex16(self.desc),
                          'value': int_to_hex64(self.value),
                          'tree-item-delegate' : self }
            if self.name:
                item_dict['name'] = self.name
            return item_dict

        def unpack(self, mach_file, data, symtab_lc):
            self.index = len(mach_file.symbols)
            self.name_offset = data.get_uint32()
            self.type.value, self.sect_idx = data.get_n_uint8(2)
            self.desc = data.get_uint16()
            if mach_file.is_64_bit():
                self.value = data.get_uint64()
            else:
                self.value = data.get_uint32()
            data.push_offset_and_seek (mach_file.file_off + symtab_lc.stroff + self.name_offset)
            #print "get string for symbol[%u]" % self.index
            self.name = data.get_c_string()
            data.pop_offset_and_seek()

        def __str__(self):
            name_display = ''
            if len(self.name):
                name_display = ' "%s"' % self.name
            return '%#8.8x %#2.2x (%-20s) %#2.2x %#4.4x %16.16x%s' % (self.name_offset, self.type.value, self.type, self.sect_idx, self.desc, self.value, name_display)


    class Interactive(cmd.Cmd):
        '''Interactive command interpreter to mach-o files.'''

        def __init__(self, mach, options):
            cmd.Cmd.__init__(self)
            self.intro = 'Interactive mach-o command interpreter'
            self.prompt = 'mach-o: %s %% ' % mach.path
            self.mach = mach
            self.options = options

        def default(self, line):
            '''Catch all for unknown command, which will exit the interpreter.'''
            print "uknown command: %s" % line
            return True

        def do_q(self, line):
            '''Quit command'''
            return True

        def do_quit(self, line):
            '''Quit command'''
            return True

        def do_header(self, line):
            '''Dump mach-o file headers'''
            self.mach.dump_header(True, self.options)
            return False

        def do_load(self, line):
            '''Dump all mach-o load commands'''
            self.mach.dump_load_commands(True, self.options)
            return False

        def do_sections(self, line):
            '''Dump all mach-o sections'''
            self.mach.dump_sections(True, self.options)
            return False

        def do_symtab(self, line):
            '''Dump all mach-o symbols in the symbol table'''
            self.mach.dump_symtab(True, self.options)
            return False

        def do_section(self, line):
            '''A command that dumps sections contents'''
            args = shlex.split(line)
            old_names = self.options.section_names
            self.options.section_names = args
            self.mach.dump_section_contents(self.options)


import Tkinter
from Tkinter import *
from ttk import *

class ScrollText(Frame):
    def __init__(self, parent):
        Frame.__init__(self, parent)
        self.parent = parent
        self.createWidgets()

    def createWidgets(self):

        self.text = Text(self, wrap=NONE)

        # Create scroll bars and bind them to the text view
        self.v_scroll = Scrollbar(orient=VERTICAL, command=self.text.yview)
        self.h_scroll = Scrollbar(orient=HORIZONTAL, command= self.text.xview)
        self.text['yscroll'] = self.v_scroll.set
        self.text['xscroll'] = self.h_scroll.set

        # Place the text view and scroll bars into this frame
        self.columnconfigure(0, weight=1) # Make sure the text view always resizes horizontally to take up all space
        self.rowconfigure(0, weight=1) # Make sure the text view always resizes vertically to take up all space
        self.text.grid(in_=self, row=0, column=0, sticky=NSEW)
        self.v_scroll.grid(in_=self, row=0, column=1, rowspan=2, sticky=NS)
        self.h_scroll.grid(in_=self, row=1, column=0, sticky=EW)

    def setText(self, text):
        pass
        self.text.delete(1.0, END)
        self.text.insert(END, text)

class DelegateTree(Frame):

    def __init__(self, parent, column_dicts, delegate):
        Frame.__init__(self, parent)
        self.sort_column_id = None
        self.sort_type = 'string'
        self.sort_direction = 1 # 0 = None, 1 = Ascending, 2 = Descending
        self.pack(expand=Y, fill=BOTH)
        self.delegate = delegate
        self.column_dicts = column_dicts
        self.item_id_to_item_dict = dict()
        frame = Frame(self)
        frame.pack(side=TOP, fill=BOTH, expand=Y)
        self._create_treeview(frame)
        self._populate_root()

    def _heading_clicked(self, column_id):
        # Detect if we are clicking on the same column again?
        reclicked = self.sort_column_id == column_id
        self.sort_column_id = column_id
        if reclicked:
            self.sort_direction += 1
            if self.sort_direction > 2:
                self.sort_direction = 0
        else:
            self.sort_direction = 1

        matching_column_dict = None
        for column_dict in self.column_dicts:
            if column_dict['id'] == self.sort_column_id:
                matching_column_dict = column_dict
                break
        new_sort_type = None
        if matching_column_dict:
            new_heading_text = ' ' + column_dict['text']
            if self.sort_direction == 1:
                new_heading_text += ' ' + unichr(0x25BC).encode('utf8')
            elif self.sort_direction == 2:
                new_heading_text += ' ' + unichr(0x25B2).encode('utf8')
            self.tree.heading(column_id, text=new_heading_text)
            if 'sort_type' in matching_column_dict:
                new_sort_type = matching_column_dict['sort_type']

        if new_sort_type is None:
            new_sort_type = 'string'
        self.sort_type = new_sort_type
        self.reload()

    def _create_treeview(self, parent):
        frame = Frame(parent)
        frame.pack(side=TOP, fill=BOTH, expand=Y)

        column_ids = list()
        for i in range(1,len(self.column_dicts)):
            column_ids.append(self.column_dicts[i]['id'])
        # create the tree and scrollbars
        self.tree = Treeview(columns=column_ids)
        self.tree.tag_configure('monospace', font=('Menlo', '12'))
        scroll_bar_v = Scrollbar(orient=VERTICAL, command= self.tree.yview)
        scroll_bar_h = Scrollbar(orient=HORIZONTAL, command= self.tree.xview)
        self.tree['yscroll'] = scroll_bar_v.set
        self.tree['xscroll'] = scroll_bar_h.set

        # setup column headings and columns properties
        for column_dict in self.column_dicts:
            column_id = column_dict['id']
            self.tree.heading(column_id, text=' ' + column_dict['text'], anchor=column_dict['anchor'], command=lambda c=column_id: self._heading_clicked(c))
            if 'width' in column_dict:
                self.tree.column(column_id, stretch=column_dict['stretch'], width=column_dict['width'])
            else:
                self.tree.column(column_id, stretch=column_dict['stretch'])


        # add tree and scrollbars to frame
        self.tree.grid(in_=frame, row=0, column=0, sticky=NSEW)
        scroll_bar_v.grid(in_=frame, row=0, column=1, sticky=NS)
        scroll_bar_h.grid(in_=frame, row=1, column=0, sticky=EW)

        # set frame resizing priorities
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        # action to perform when a node is expanded
        self.tree.bind('<<TreeviewOpen>>', self._update_tree)

    def insert_items(self, parent_id, item_dicts):
        for item_dict in item_dicts:
            name = None
            values = list()
            first = True
            for column_dict in self.column_dicts:
                column_key = column_dict['id']
                if column_key in item_dict:
                    column_value = item_dict[column_key]
                else:
                    column_value = ''
                if first:
                    name = column_value
                    first = False
                else:
                    values.append(column_value)
            item_id = self.tree.insert (parent_id, # root item has an empty name
                                        END,
                                        text=name,
                                        values=values,
                                        tag='monospace')
            self.item_id_to_item_dict[item_id] = item_dict
            if 'children' in item_dict and item_dict['children']:
                self.tree.insert(item_id, END, text='dummy')

    def _sort_item_dicts(self, item_dicts):
        if self.sort_column_id is None or self.sort_direction == 0:
            return item_dicts # No sorting needs to happen
        if self.sort_type == 'number':
            return sorted(item_dicts, reverse=self.sort_direction==2, key=lambda k, c=self.sort_column_id: int(k.get(c, 0), 0))
        else:
            return sorted(item_dicts, reverse=self.sort_direction==2, key=lambda k, c=self.sort_column_id: k.get(c, ''))

    def _populate_root(self):
        # use current directory as root node
        item_dicts = self._sort_item_dicts(self.delegate.get_child_item_dictionaries())
        self.insert_items('', item_dicts)

    def _update_tree(self, event):
        # user expanded a node - build the related directory
        item_id = self.tree.focus()      # the id of the expanded node
        children = self.tree.get_children (item_id)
        if len(children):
            first_child = children[0]
            # if the node only has a 'dummy' child, remove it and
            # build new directory skip if the node is already
            # populated
            if self.tree.item(first_child, option='text') == 'dummy':
                self.tree.delete(first_child)
                item_dict = self.item_id_to_item_dict[item_id]
                item_dicts = self._sort_item_dicts(item_dict['tree-item-delegate'].get_child_item_dictionaries())
                self.insert_items(item_id, item_dicts)

    def reload(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._populate_root()

class LoadCommandTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_item_dictionary(self):
        name = "Load Commands"
        return { '#0' : name,
                 'value': '',
                 'summary': '',
                 'children' : True,
                 'tree-item-delegate' : self }

    def get_child_item_dictionaries(self):
        item_dicts = list()
        load_commands = self.mach_frame.selected_mach.commands
        for idx, lc in enumerate(load_commands):
            item_dicts.append(lc.get_item_dictionary())
        return item_dicts

class SectionListTreeItemDelegate(object):
    def __init__(self, sections, flat):
        self.sections = sections
        self.flat = flat

    def get_item_dictionary(self):
        return { '#0' : 'sections',
                 'value': '',
                 'summary': '%u sections' % (len(self.sections)),
                 'children' : True,
                 'tree-item-delegate' : self }

    def get_child_item_dictionaries(self):
        item_dicts = list()
        for section in self.sections:
            if self.flat:
                item_dict = { '#0'         : str(section.index),
                              'offset'     : int_to_hex32(section.offset),
                              'align'      : int_to_hex32(section.align),
                              'reloff'     : int_to_hex32(section.reloff),
                              'nreloc'     : int_to_hex32(section.nreloc),
                              'flags'      : section.get_flags_as_string(),
                              'type'       : section.get_type_as_string(),
                              'attrs'      : section.get_attributes_as_string(),
                              'reserved1'  : int_to_hex32(section.reserved1),
                              'reserved2'  : int_to_hex32(section.reserved2) }
                if section.sectname:
                    item_dict['sectname'] = section.sectname
                if section.segname:
                    item_dict['segname'] = section.segname
                item_dict['range'] = address_range_to_str(section.addr, section.addr + section.size, section.is_64)
                item_dict['addr'] = address_to_str(section.addr, section.is_64)
                item_dict['size'] = address_to_str(section.size, section.is_64)
                if section.is_64:
                    item_dict['reserved3'] = int_to_hex32(section.reserved3)
                item_dicts.append(item_dict)
            else:
                item_dicts.append(section.get_item_dictionary())
        return item_dicts

class SymbolsTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_item_dictionary(self):
        return { '#0' : 'symbols',
                 'value': '',
                 'summary': '%u symbols' % (len(self.symbols)),
                 'children' : True,
                 'tree-item-delegate' : self }

    def get_child_item_dictionaries(self):
        item_dicts = list()
        mach = self.mach_frame.selected_mach
        symbols = mach.get_symtab()
        for nlist in symbols:
            item_dict = nlist.get_item_dictionary()
            sect_idx = item_dict['sect_idx']
            if nlist.sect_idx_is_section_index():
                section = self.mach_frame.selected_mach.sections[sect_idx]
                item_dict['sect'] = section.segname + '.' + section.sectname
            else:
                item_dict['sect'] = str(sect_idx)
            item_dicts.append(item_dict)
        return item_dicts

class DWARFDebugInfoTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_child_item_dictionaries(self):
        item_dicts = list()
        mach = self.mach_frame.selected_mach
        dwarf = mach.get_dwarf()
        if dwarf:
            debug_info = dwarf.get_debug_info()
            cus = debug_info.get_compile_units()
            for cu in cus:
                item_dict = cu.get_die().get_item_dictionary()
                if item_dict:
                    item_dicts.append(item_dict)
        return item_dicts

class DWARFDebugLineTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_child_item_dictionaries(self):
        item_dicts = list()
        mach = self.mach_frame.selected_mach
        dwarf = mach.get_dwarf()
        if dwarf:
            debug_info = dwarf.get_debug_info()
            cus = debug_info.get_compile_units()
            for cu in cus:
                line_table = cu.get_line_table()
                item_dict = line_table.get_item_dictionary()
                if item_dict:
                    item_dicts.append(item_dict)
        return item_dicts

class StringTableTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_child_item_dictionaries(self):
        item_dicts = list()
        mach = self.mach_frame.selected_mach
        dwarf = mach.get_dwarf()
        if dwarf:
            data = dwarf.debug_str_data
            length = data.get_size()
            data.seek(0)
            while data.tell() < length:
                item_dicts.append({ '#0' : '0x%8.8x' % (data.tell()), 'string' :  '"%s"' % (data.get_c_string()) })
        return item_dicts

class MachFrame(Frame):

    def __init__(self, parent, options, mach_files):
        Frame.__init__(self, parent)
        self.parent = parent
        self.options = options
        self.mach = None
        self.mach_files = mach_files
        self.mach_index = 0
        self.selected_mach = None
        self.lc_tree = None
        self.sections_tree = None
        self.symbols_tree = None
        self.selected_filepath = StringVar()
        self.selected_arch = StringVar()
        self.selected_arch.trace("w", self.arch_changed_callback)
        self.selected_filepath.set(self.mach_files[0])
        self.load_mach_file(self.mach_files[0])
        self.createWidgets()
        self.update_arch_option_menu()

    def load_mach_file (self, path):
        self.mach = Mach()
        self.mach.parse(path)
        self.selected_filepath.set(path)
        first_arch_name = str(self.mach.get_architecture(0))
        self.selected_mach = self.mach.get_architecture_slice(first_arch_name)
        self.selected_arch.set(first_arch_name)

    def update_arch_option_menu(self):
        # Update the architecture menu
        menu = self.arch_mb['menu']
        menu.delete(0,END)
        if self.mach:
            num_archs = self.mach.get_num_archs()
            for i in range(num_archs):
                arch_name = str(self.mach.get_architecture(i))
                menu.add_command(label=arch_name, command=Tkinter._setit(self.selected_arch, arch_name))

    def refresh_frames(self):
        if self.lc_tree:
            self.lc_tree.reload()
        if self.sections_tree:
            self.sections_tree.delegate = SectionListTreeItemDelegate(self.selected_mach.sections[1:], True)
            self.sections_tree.reload()
        if self.symbols_tree:
            self.symbols_tree.reload()

    def file_changed_callback(self, *dummy):
        path = self.selected_filepath.get()
        if self.mach is None or self.mach.path != path:
            self.load_mach_file(path)
            self.refresh_frames()
        else:
            print 'file did not change'

    def arch_changed_callback(self, *dummy):
        arch = self.selected_arch.get()
        self.selected_mach = self.mach.get_architecture_slice(arch)
        self.refresh_frames()

    def createWidgets(self):
        self.parent.title("Source")
        self.style = Style()
        self.style.theme_use("default")
        self.pack(fill=BOTH, expand=1)

        self.columnconfigure(0, pad=5, weight=1)
        self.columnconfigure(1, pad=5)
        self.rowconfigure(1, weight=1)

        files = list()
        for i, mach_file in enumerate(self.mach_files):
            files.append(mach_file)
            if i==0:
                files.append(files[0])
        self.mach_mb = OptionMenu(self, self.selected_filepath, *files, command=self.file_changed_callback)
        self.mach_mb.grid(row=0, column=0, stick=NSEW)

        self.arch_mb = OptionMenu(self, self.selected_arch, command=self.arch_changed_callback)
        self.arch_mb.grid(row=0, column=1, stick=NSEW)

        note = Notebook(self)

        lc_column_dicts = [{ 'id' : '#0'     , 'text' : 'Name'   , 'anchor' : W , 'stretch' : 0 },
                           { 'id' : 'value'  , 'text' : 'Value'  , 'anchor' : W , 'stretch' : 0 },
                           { 'id' : 'summary', 'text' : 'Summary', 'anchor' : W , 'stretch' : 1 }]

        sect_column_dicts = [{ 'id' : '#0'       , 'text' : 'Index'      , 'width' : 40  , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number' },
                             { 'id' : 'segname'  , 'text' : 'Segment'    , 'width' : 80  , 'anchor' : W , 'stretch' : 0 },
                             { 'id' : 'sectname' , 'text' : 'Section'    , 'width' : 120 , 'anchor' : W , 'stretch' : 0 },
                             { 'id' : 'range'    , 'text' : 'Address Range', 'width' : 300 , 'anchor' : W , 'stretch' : 0 },
                             { 'id' : 'size'     , 'text' : 'Size'       , 'width' : 140 , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                             { 'id' : 'offset'   , 'text' : 'File Offset', 'width' : 80  , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number' },
                             { 'id' : 'align'    , 'text' : 'Align'      , 'width' : 80  , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                             { 'id' : 'reloff'   , 'text' : 'Rel Offset' , 'width' : 80  , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                             { 'id' : 'nreloc'   , 'text' : 'Num Relocs' , 'width' : 80  , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                             { 'id' : 'type'     , 'text' : 'Type'       , 'width' : 200 , 'anchor' : W , 'stretch' : 0 },
                             { 'id' : 'attrs'    , 'text' : 'Attributes' , 'width' : 200 , 'anchor' : W , 'stretch' : 1 },
                             { 'id' : 'reserved1', 'text' : 'reserved1'  , 'width' : 100 , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                             { 'id' : 'reserved2', 'text' : 'reserved2'  , 'width' : 100 , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                             { 'id' : 'reserved3', 'text' : 'reserved3'  , 'width' : 100 , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'}]

        symbol_column_dicts = [{ 'id' : '#0'    , 'text' : 'Index'     , 'width' : 50  , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                               { 'id' : 'type'  , 'text' : 'Type'      , 'width' : 60  , 'anchor' : W , 'stretch' : 0 },
                               { 'id' : 'flags' , 'text' : 'Flags'     , 'width' : 60  , 'anchor' : W , 'stretch' : 0 },
                               { 'id' : 'sect'  , 'text' : 'Section'   , 'width' : 200 , 'anchor' : W , 'stretch' : 0 },
                               { 'id' : 'desc'  , 'text' : 'Descriptor', 'width' : 60  , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                               { 'id' : 'value' , 'text' : 'Value'     , 'width' : 140 , 'anchor' : W , 'stretch' : 0 , 'sort_type' : 'number'},
                               { 'id' : 'name'  , 'text' : 'Name'      , 'width' : 80  , 'anchor' : W , 'stretch' : 1 }]

        debug_info_column_dicts = [{ 'id' : '#0'   , 'text' : 'Offset', 'anchor' : W , 'stretch' : 0 },
                              { 'id' : 'name' , 'text' : 'Name'  , 'anchor' : W , 'stretch' : 0 },
                              { 'id' : 'value', 'text' : 'Value' , 'anchor' : W , 'stretch' : 1 }]

        debug_line_column_dicts = [ { 'id' : '#0' , 'text' : 'Address', 'width' : 200, 'anchor' : W , 'stretch' : 0 },
                                    { 'id' : 'file' , 'text' : 'File'  , 'width' : 400, 'anchor' : W , 'stretch' : 0 },
                                    { 'id' : 'line' , 'text' : 'Line'  , 'width' : 40, 'anchor' : W , 'stretch' : 0 },
                                    { 'id' : 'column' , 'text' : 'Col', 'width' : 40, 'anchor' : W , 'stretch' : 0 },
                                    { 'id' : 'is_stmt' , 'text' : 'Stmt', 'width' : 40, 'anchor' : W , 'stretch' : 0 },
                                    { 'id' : 'end_sequence' , 'text' : 'End'  , 'width' : 10, 'anchor' : W , 'stretch' : 1 }]
        debug_str_column_dicts = [{ 'id' : '#0'   , 'width' : 100, 'text' : 'Offset', 'anchor' : W , 'stretch' : 0 },
                                  { 'id' : 'string', 'text' : 'String' , 'anchor' : W , 'stretch' : 1 }]

        self.lc_tree = DelegateTree(self, lc_column_dicts, LoadCommandTreeItemDelegate(self))
        self.sections_tree = DelegateTree(self, sect_column_dicts, SectionListTreeItemDelegate(self.selected_mach.sections[1:], True))
        self.symbols_tree = DelegateTree(self, symbol_column_dicts, SymbolsTreeItemDelegate(self))
        self.debug_info_tree = DelegateTree(self, debug_info_column_dicts, DWARFDebugInfoTreeItemDelegate(self))
        self.debug_line_tree = DelegateTree(self, debug_line_column_dicts, DWARFDebugLineTreeItemDelegate(self))
        self.debug_str_tree = DelegateTree(self, debug_str_column_dicts, StringTableTreeItemDelegate(self))
        note.add(self.lc_tree, text = "Load Commands", compound=TOP)
        note.add(self.sections_tree, text = "Sections")
        note.add(self.symbols_tree, text = "Symbols")
        note.add(self.debug_info_tree, text = ".debug_info")
        note.add(self.debug_line_tree, text = ".debug_line")
        note.add(self.debug_str_tree, text = ".debug_str")
        note.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky= NSEW)
        #
        # self.info_text = ScrollText(self)
        # self.info_text.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky= NSEW)





def tk_gui(options, mach_files):
    root = Tk()
    root.geometry("800x600+300+300")
    app = MachFrame(root, options, mach_files)
    root.mainloop()

def handle_mach(options, path):
    mach = Mach()
    mach.parse(path)
    if mach.is_valid():
        if options.interactive:
            interpreter = Mach.Interactive(mach, options)
            interpreter.cmdloop()
        else:
            mach.dump(options)
    else:
        print 'error: "%s" is not a valid mach-o file' % (path)

def user_specified_options(options):
    '''Return true if the user specified any options, false otherwise.'''
    if options.dump_header:
        return True
    if options.dump_symtab:
        return True
    if options.dump_load_commands:
        return True
    if options.dump_sections:
        return True
    if options.section_names:
        return True
    if options.interactive:
        return True
    if options.find_mangled:
        return True
    if options.compare:
        return True
    if options.tk:
        return True
    if options.outfile:
        return True
    if dwarf.have_dwarf_options(options):
        return True
    return False

if __name__ == '__main__':
    parser = optparse.OptionParser(description='A script that parses skinny and universal mach-o files.')
    parser.add_option('--arch', '-a', type='string', metavar='arch', dest='archs', action='append', help='specify one or more architectures by name')
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='display verbose debug info', default=False)
    parser.add_option('-H', '--header', action='store_true', dest='dump_header', help='dump the mach-o file header', default=False)
    parser.add_option('-l', '--load-commands', action='store_true', dest='dump_load_commands', help='dump the mach-o load commands', default=False)
    parser.add_option('-s', '--symtab', action='store_true', dest='dump_symtab', help='dump the mach-o symbol table', default=False)
    parser.add_option('-S', '--sections', action='store_true', dest='dump_sections', help='dump the mach-o sections', default=False)
    parser.add_option('--section', type='string', metavar='arch', dest='section_names', action='append', help='Specify one or more section names to dump')
    parser.add_option('-i', '--interactive', action='store_true', dest='interactive', help='enable interactive mode', default=False)
    parser.add_option('-m', '--mangled', action='store_true', dest='find_mangled', help='dump all mangled names in a mach file', default=False)
    parser.add_option('-c', '--compare', action='store_true', dest='compare', help='compare two mach files', default=False)
    parser.add_option('-t', '--tk', action='store_true', dest='tk', help='Use TK to display an interactive window', default=False)
    parser.add_option('-o', '--out', type='string', dest='outfile', help='Used in conjunction with the --section=NAME option to save a single section\'s data to disk.', default=None)
    dwarf.append_dwarf_options(parser)
    (options, mach_files) = parser.parse_args()
    dwarf.enable_colors = options.color
    if options.tk:
        tk_gui(options, mach_files)
    elif options.compare:
        if len(mach_files) == 2:
            mach_a = Mach()
            mach_b = Mach()
            mach_a.parse(mach_files[0])
            mach_b.parse(mach_files[1])
            mach_a.compare(mach_b)
        else:
            print 'error: --compare takes two mach files as arguments'
    else:
        if not user_specified_options(options):
            options.dump_header = True
            options.dump_load_commands = True
        for path in mach_files:
            if os.path.isdir(path):
                uuid_output = commands.getoutput('xcrun dwarfdump --uuid "%s"' % (path))
                uuid_output_regex = re.compile("UUID: [-0-9A-Fa-f]+ \([^\)]+\) (.*)")
                lines = uuid_output.split('\n')
                for line in lines:
                    match = uuid_output_regex.match(line)
                    if match:
                        handle_mach(options, match.group(1))
                    else:
                        print "error: didn't match '%s'" % (line)
            else:
                handle_mach(options, path)
