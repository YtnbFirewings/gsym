#!/usr/bin/python
import json
import optparse
import StringIO
import sys

# Local imports
import dict_utils
import dwarf
import file_extract

# e_ident size and indices.
EI_MAG0 = 0        # File identification index.
EI_MAG1 = 1        # File identification index.
EI_MAG2 = 2        # File identification index.
EI_MAG3 = 3        # File identification index.
EI_CLASS = 4       # File class.
EI_DATA = 5        # Data encoding.
EI_VERSION = 6     # File version.
EI_OSABI = 7       # OS/ABI identification.
EI_ABIVERSION = 8  # ABI version.
EI_PAD = 9         # Start of padding bytes.
EI_NIDENT = 16     # Number of bytes in e_ident.

# File types
ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4
ET_LOPROC = 0xff00
ET_HIPROC = 0xffff

# Versioning
EV_NONE = 0
EV_CURRENT = 1

# Machine architectures
EM_NONE = 0   # No machine
EM_M32 = 1   # AT&T WE 32100
EM_SPARC = 2   # SPARC
EM_386 = 3   # Intel 386
EM_68K = 4   # Motorola 68000
EM_88K = 5   # Motorola 88000
EM_IAMCU = 6   # Intel MCU
EM_860 = 7   # Intel 80860
EM_MIPS = 8   # MIPS R3000
EM_S370 = 9   # IBM System/370
EM_MIPS_RS3_LE = 10  # MIPS RS3000 Little-endian
EM_PARISC = 15  # Hewlett-Packard PA-RISC
EM_VPP500 = 17  # Fujitsu VPP500
EM_SPARC32PLUS = 18  # Enhanced instruction set SPARC
EM_960 = 19  # Intel 80960
EM_PPC = 20  # PowerPC
EM_PPC64 = 21  # PowerPC64
EM_S390 = 22  # IBM System/390
EM_SPU = 23  # IBM SPU/SPC
EM_V800 = 36  # NEC V800
EM_FR20 = 37  # Fujitsu FR20
EM_RH32 = 38  # TRW RH-32
EM_RCE = 39  # Motorola RCE
EM_ARM = 40  # ARM
EM_ALPHA = 41  # DEC Alpha
EM_SH = 42  # Hitachi SH
EM_SPARCV9 = 43  # SPARC V9
EM_TRICORE = 44  # Siemens TriCore
EM_ARC = 45  # Argonaut RISC Core
EM_H8_300 = 46  # Hitachi H8/300
EM_H8_300H = 47  # Hitachi H8/300H
EM_H8S = 48  # Hitachi H8S
EM_H8_500 = 49  # Hitachi H8/500
EM_IA_64 = 50  # Intel IA-64 processor architecture
EM_MIPS_X = 51  # Stanford MIPS-X
EM_COLDFIRE = 52  # Motorola ColdFire
EM_68HC12 = 53  # Motorola M68HC12
EM_MMA = 54  # Fujitsu MMA Multimedia Accelerator
EM_PCP = 55  # Siemens PCP
EM_NCPU = 56  # Sony nCPU embedded RISC processor
EM_NDR1 = 57  # Denso NDR1 microprocessor
EM_STARCORE = 58  # Motorola Star*Core processor
EM_ME16 = 59  # Toyota ME16 processor
EM_ST100 = 60  # STMicroelectronics ST100 processor
EM_TINYJ = 61  # Advanced Logic Corp. TinyJ embedded processor family
EM_X86_64 = 62  # AMD x86-64 architecture
EM_PDSP = 63  # Sony DSP Processor
EM_PDP10 = 64  # Digital Equipment Corp. PDP-10
EM_PDP11 = 65  # Digital Equipment Corp. PDP-11
EM_FX66 = 66  # Siemens FX66 microcontroller
EM_ST9PLUS = 67  # STMicroelectronics ST9+ 8/16 bit microcontroller
EM_ST7 = 68  # STMicroelectronics ST7 8-bit microcontroller
EM_68HC16 = 69  # Motorola MC68HC16 Microcontroller
EM_68HC11 = 70  # Motorola MC68HC11 Microcontroller
EM_68HC08 = 71  # Motorola MC68HC08 Microcontroller
EM_68HC05 = 72  # Motorola MC68HC05 Microcontroller
EM_SVX = 73  # Silicon Graphics SVx
EM_ST19 = 74  # STMicroelectronics ST19 8-bit microcontroller
EM_VAX = 75  # Digital VAX
EM_CRIS = 76  # Axis Communications 32-bit embedded processor
EM_JAVELIN = 77  # Infineon Technologies 32-bit embedded processor
EM_FIREPATH = 78  # Element 14 64-bit DSP Processor
EM_ZSP = 79  # LSI Logic 16-bit DSP Processor
EM_MMIX = 80  # Donald Knuth's educational 64-bit processor
EM_HUANY = 81  # Harvard University machine-independent object files
EM_PRISM = 82  # SiTera Prism
EM_AVR = 83  # Atmel AVR 8-bit microcontroller
EM_FR30 = 84  # Fujitsu FR30
EM_D10V = 85  # Mitsubishi D10V
EM_D30V = 86  # Mitsubishi D30V
EM_V850 = 87  # NEC v850
EM_M32R = 88  # Mitsubishi M32R
EM_MN10300 = 89  # Matsushita MN10300
EM_MN10200 = 90  # Matsushita MN10200
EM_PJ = 91  # picoJava
EM_OPENRISC = 92  # OpenRISC 32-bit embedded processor
EM_ARC_COMPACT = 93  # ARC International ARCompact processor
EM_XTENSA = 94  # Tensilica Xtensa Architecture
EM_VIDEOCORE = 95  # Alphamosaic VideoCore processor
EM_TMM_GPP = 96  # Thompson Multimedia General Purpose Processor
EM_NS32K = 97  # National Semiconductor 32000 series
EM_TPC = 98  # Tenor Network TPC processor
EM_SNP1K = 99  # Trebia SNP 1000 processor
EM_ST200 = 100  # STMicroelectronics (www.st.com) ST200
EM_IP2K = 101  # Ubicom IP2xxx microcontroller family
EM_MAX = 102  # MAX Processor
EM_CR = 103  # National Semiconductor CompactRISC microprocessor
EM_F2MC16 = 104  # Fujitsu F2MC16
EM_MSP430 = 105  # Texas Instruments embedded microcontroller msp430
EM_BLACKFIN = 106  # Analog Devices Blackfin (DSP) processor
EM_SE_C33 = 107  # S1C33 Family of Seiko Epson processors
EM_SEP = 108  # Sharp embedded microprocessor
EM_ARCA = 109  # Arca RISC Microprocessor
EM_UNICORE = 110  # Microprocessor series from PKU-Unity Ltd.
EM_EXCESS = 111  # eXcess: 16/32/64-bit configurable embedded CPU
EM_DXP = 112  # Icera Semiconductor Inc. Deep Execution Processor
EM_ALTERA_NIOS2 = 113  # Altera Nios II soft-core processor
EM_CRX = 114  # National Semiconductor CompactRISC CRX
EM_XGATE = 115  # Motorola XGATE embedded processor
EM_C166 = 116  # Infineon C16x/XC16x processor
EM_M16C = 117  # Renesas M16C series microprocessors
EM_DSPIC30F = 118  # Microchip Technology dsPIC30F Digital Signal Controller
EM_CE = 119  # Freescale Communication Engine RISC core
EM_M32C = 120  # Renesas M32C series microprocessors
EM_TSK3000 = 131  # Altium TSK3000 core
EM_RS08 = 132  # Freescale RS08 embedded processor
EM_SHARC = 133  # Analog Devices SHARC family of 32-bit DSP processors
EM_ECOG2 = 134  # Cyan Technology eCOG2 microprocessor
EM_SCORE7 = 135  # Sunplus S+core7 RISC processor
EM_DSP24 = 136  # New Japan Radio (NJR) 24-bit DSP Processor
EM_VIDEOCORE3 = 137  # Broadcom VideoCore III processor
EM_LATTICEMICO32 = 138  # RISC processor for Lattice FPGA architecture
EM_SE_C17 = 139  # Seiko Epson C17 family
EM_TI_C6000 = 140  # The Texas Instruments TMS320C6000 DSP family
EM_TI_C2000 = 141  # The Texas Instruments TMS320C2000 DSP family
EM_TI_C5500 = 142  # The Texas Instruments TMS320C55x DSP family
EM_MMDSP_PLUS = 160  # STMicroelectronics 64bit VLIW Data Signal Processor
EM_CYPRESS_M8C = 161  # Cypress M8C microprocessor
EM_R32C = 162  # Renesas R32C series microprocessors
EM_TRIMEDIA = 163  # NXP Semiconductors TriMedia architecture family
EM_HEXAGON = 164  # Qualcomm Hexagon processor
EM_8051 = 165  # Intel 8051 and variants
EM_STXP7X = 166  # STMicroelectronics STxP7x RISC processors
EM_NDS32 = 167  # Andes Technology compact code size embedded RISC
EM_ECOG1 = 168  # Cyan Technology eCOG1X family
EM_ECOG1X = 168  # Cyan Technology eCOG1X family
EM_MAXQ30 = 169  # Dallas Semiconductor MAXQ30 Core Micro-controllers
EM_XIMO16 = 170  # New Japan Radio (NJR) 16-bit DSP Processor
EM_MANIK = 171  # M2000 Reconfigurable RISC Microprocessor
EM_CRAYNV2 = 172  # Cray Inc. NV2 vector architecture
EM_RX = 173  # Renesas RX family
EM_METAG = 174  # Imagination Technologies META processor architecture
EM_MCST_ELBRUS = 175  # MCST Elbrus general purpose hardware architecture
EM_ECOG16 = 176  # Cyan Technology eCOG16 family
EM_CR16 = 177  # National Semiconductor CompactRISC CR16 16-bit microprocessor
EM_ETPU = 178  # Freescale Extended Time Processing Unit
EM_SLE9X = 179  # Infineon Technologies SLE9X core
EM_L10M = 180  # Intel L10M
EM_K10M = 181  # Intel K10M
EM_AARCH64 = 183  # ARM AArch64
EM_AVR32 = 185  # Atmel Corporation 32-bit microprocessor family
EM_STM8 = 186  # STMicroeletronics STM8 8-bit microcontroller
EM_TILE64 = 187  # Tilera TILE64 multicore architecture family
EM_TILEPRO = 188  # Tilera TILEPro multicore architecture family
EM_CUDA = 190  # NVIDIA CUDA architecture
EM_TILEGX = 191  # Tilera TILE-Gx multicore architecture family
EM_CLOUDSHIELD = 192  # CloudShield architecture family
EM_COREA_1ST = 193  # KIPO-KAIST Core-A 1st generation processor family
EM_COREA_2ND = 194  # KIPO-KAIST Core-A 2nd generation processor family
EM_ARC_COMPACT2 = 195  # Synopsys ARCompact V2
EM_OPEN8 = 196  # Open8 8-bit RISC soft processor core
EM_RL78 = 197  # Renesas RL78 family
EM_VIDEOCORE5 = 198  # Broadcom VideoCore V processor
EM_78KOR = 199  # Renesas 78KOR family
EM_56800EX = 200  # Freescale 56800EX Digital Signal Controller (DSC)
EM_BA1 = 201  # Beyond BA1 CPU architecture
EM_BA2 = 202  # Beyond BA2 CPU architecture
EM_XCORE = 203  # XMOS xCORE processor family
EM_MCHP_PIC = 204  # Microchip 8-bit PIC(r) family
EM_INTEL205 = 205  # Reserved by Intel
EM_INTEL206 = 206  # Reserved by Intel
EM_INTEL207 = 207  # Reserved by Intel
EM_INTEL208 = 208  # Reserved by Intel
EM_INTEL209 = 209  # Reserved by Intel
EM_KM32 = 210  # KM211 KM32 32-bit processor
EM_KMX32 = 211  # KM211 KMX32 32-bit processor
EM_KMX16 = 212  # KM211 KMX16 16-bit processor
EM_KMX8 = 213  # KM211 KMX8 8-bit processor
EM_KVARC = 214  # KM211 KVARC processor
EM_CDP = 215  # Paneve CDP architecture family
EM_COGE = 216  # Cognitive Smart Memory Processor
EM_COOL = 217  # iCelero CoolEngine
EM_NORC = 218  # Nanoradio Optimized RISC
EM_CSR_KALIMBA = 219  # CSR Kalimba architecture family
EM_AMDGPU = 224  # AMD GPU architecture

# EI_CLASS - Object file classes.
ELFCLASSNONE = 0
ELFCLASS32 = 1  # 32-bit object file
ELFCLASS64 = 2  # 64-bit object file

# EI_DATA - Object file byte orderings.
ELFDATANONE = 0  # Invalid data encoding.
ELFDATA2LSB = 1  # Little-endian object file
ELFDATA2MSB = 2  # Big-endian object file

# OS ABI identification.
ELFOSABI_NONE = 0           # UNIX System V ABI
ELFOSABI_HPUX = 1           # HP-UX operating system
ELFOSABI_NETBSD = 2         # NetBSD
ELFOSABI_GNU = 3            # GNU/Linux
ELFOSABI_LINUX = 3          # Historical alias for ELFOSABI_GNU.
ELFOSABI_HURD = 4           # GNU/Hurd
ELFOSABI_SOLARIS = 6        # Solaris
ELFOSABI_AIX = 7            # AIX
ELFOSABI_IRIX = 8           # IRIX
ELFOSABI_FREEBSD = 9        # FreeBSD
ELFOSABI_TRU64 = 10         # TRU64 UNIX
ELFOSABI_MODESTO = 11       # Novell Modesto
ELFOSABI_OPENBSD = 12       # OpenBSD
ELFOSABI_OPENVMS = 13       # OpenVMS
ELFOSABI_NSK = 14           # Hewlett-Packard Non-Stop Kernel
ELFOSABI_AROS = 15          # AROS
ELFOSABI_FENIXOS = 16       # FenixOS
ELFOSABI_CLOUDABI = 17      # Nuxi CloudABI
ELFOSABI_C6000_ELFABI = 64  # Bare-metal TMS320C6000
ELFOSABI_AMDGPU_HSA = 64    # AMD HSA runtime
ELFOSABI_C6000_LINUX = 65   # Linux TMS320C6000
ELFOSABI_ARM = 97           # ARM
ELFOSABI_STANDALONE = 255   # Standalone (embedded) application

# Section header types
SHT_NULL = 0            # No associated section (inactive entry).
SHT_PROGBITS = 1        # Program-defined contents.
SHT_SYMTAB = 2          # Symbol table.
SHT_STRTAB = 3          # String table.
SHT_RELA = 4            # Relocation entries; explicit addends.
SHT_HASH = 5            # Symbol hash table.
SHT_DYNAMIC = 6         # Information for dynamic linking.
SHT_NOTE = 7            # Information about the file.
SHT_NOBITS = 8          # Data occupies no space in the file.
SHT_REL = 9             # Relocation entries; no explicit addends.
SHT_SHLIB = 10          # Reserved.
SHT_DYNSYM = 11         # Symbol table.
SHT_INIT_ARRAY = 14     # Pointers to initialization functions.
SHT_FINI_ARRAY = 15     # Pointers to termination functions.
SHT_PREINIT_ARRAY = 16  # Pointers to pre-init functions.
SHT_GROUP = 17          # Section group.
SHT_SYMTAB_SHNDX = 18   # Indices for SHN_XINDEX entries.
SHT_LOOS = 0x60000000
SHT_HIOS = 0x6fffffff
SHT_LOPROC = 0x70000000
SHT_HIPROC = 0x7fffffff
SHT_LOUSER = 0x80000000
SHT_HIUSER = 0xffffffff
SHT_GNU_ATTRIBUTES = 0x6ffffff5
SHT_GNU_HASH = 0x6ffffff6
SHT_GNU_verdef = 0x6ffffffd
SHT_GNU_verneed = 0x6ffffffe
SHT_GNU_versym = 0x6fffffff
SHT_ARM_EXIDX = 0x70000001
SHT_ARM_PREEMPTMAP = 0x70000002
SHT_ARM_ATTRIBUTES = 0x70000003
SHT_ARM_DEBUGOVERLAY = 0x70000004
SHT_ARM_OVERLAYSECTION = 0x70000005
SHT_HEX_ORDERED = 0x70000000
SHT_X86_64_UNWIND = 0x70000001
SHT_MIPS_REGINFO = 0x70000006
SHT_MIPS_OPTIONS = 0x7000000d
SHT_MIPS_ABIFLAGS = 0x7000002a

# Special Section Indexes
SHN_UNDEF = 0
SHN_LORESERVE = 0xff00
SHN_LOPROC = 0xff00
SHN_HIPROC = 0xff1f
SHN_ABS = 0xfff1
SHN_COMMON = 0xfff2
SHN_HIRESERVE = 0xffff

# The size (in bytes) of symbol table entries.
SYMENTRY_SIZE32 = 16  # 32-bit symbol entry size
SYMENTRY_SIZE64 = 24  # 64-bit symbol entry size.

# Symbol bindings.
STB_LOCAL = 0    # Local symbol, not visible outside obj file containing def
STB_GLOBAL = 1   # Global symbol, visible to all object files being combined
STB_WEAK = 2     # Weak symbol, like global but lower-precedence
STB_GNU_UNIQUE = 10
STB_LOOS = 10    # Lowest operating system-specific binding type
STB_HIOS = 12    # Highest operating system-specific binding type
STB_LOPROC = 13  # Lowest processor-specific binding type
STB_HIPROC = 15  # Highest processor-specific binding type

# Symbol types.
STT_NOTYPE = 0      # Symbol's type is not specified
STT_OBJECT = 1      # Symbol is a data object (variable, array, etc.)
STT_FUNC = 2        # Symbol is executable code (function, etc.)
STT_SECTION = 3     # Symbol refers to a section
STT_FILE = 4        # Local, absolute symbol that refers to a file
STT_COMMON = 5      # An uninitialized common block
STT_TLS = 6         # Thread local data object
STT_GNU_IFUNC = 10  # GNU indirect function
STT_LOOS = 10       # Lowest operating system-specific symbol type
STT_HIOS = 12       # Highest operating system-specific symbol type
STT_LOPROC = 13     # Lowest processor-specific symbol type
STT_HIPROC = 15     # Highest processor-specific symbol type

STV_DEFAULT = 0     # Visibility is specified by binding type
STV_INTERNAL = 1    # Defined by processor supplements
STV_HIDDEN = 2      # Not visible to other components
STV_PROTECTED = 3   # Visible in other components but not preemptable

# Symbol number.
STN_UNDEF = 0

PT_NULL = 0             # Unused segment.
PT_LOAD = 1             # Loadable segment.
PT_DYNAMIC = 2          # Dynamic linking information.
PT_INTERP = 3           # Interpreter pathname.
PT_NOTE = 4             # Auxiliary information.
PT_SHLIB = 5            # Reserved.
PT_PHDR = 6             # The program header table itself.
PT_TLS = 7              # The thread-local storage template.
PT_LOOS = 0x60000000    # Lowest operating system-specific pt entry type.
PT_HIOS = 0x6fffffff    # Highest operating system-specific pt entry type.
PT_LOPROC = 0x70000000  # Lowest processor-specific program hdr entry type.
PT_HIPROC = 0x7fffffff  # Highest processor-specific program hdr entry type.
PT_GNU_EH_FRAME = 0x6474e550
PT_SUNW_EH_FRAME = 0x6474e550
PT_SUNW_UNWIND = 0x6464e550
PT_GNU_STACK = 0x6474e551
PT_GNU_RELRO = 0x6474e552

# Segment flag bits.
PF_X = 1             # Execute
PF_W = 2             # Write
PF_R = 4             # Read
PF_MASKOS = 0x0ff00000    # Bits for operating system-specific semantics.
PF_MASKPROC = 0xf0000000    # Bits for processor-specific semantics.

# Note types
NT_PRSTATUS = 1
NT_PRFPREG = 2
NT_PRPSINFO = 3
NT_TASKSTRUCT = 4
NT_AUXV = 6
NT_SIGINFO = 0x53494749
NT_FILE = 0x46494c45
NT_PRXFPREG = 0x46e62b7f
NT_PPC_VMX = 0x100
NT_PPC_SPE = 0x101
NT_PPC_VSX = 0x102
NT_386_TLS = 0x200
NT_386_IOPERM = 0x201
NT_X86_XSTATE = 0x202
NT_S390_HIGH_GPRS = 0x300
NT_S390_TIMER = 0x301
NT_S390_TODCMP = 0x302
NT_S390_TODPREG = 0x303
NT_S390_CTRS = 0x304
NT_S390_PREFIX = 0x305
NT_S390_LAST_BREAK = 0x306
NT_S390_SYSTEM_CALL = 0x307
NT_S390_TDB = 0x308
NT_S390_VXRS_LOW = 0x309
NT_S390_VXRS_HIGH = 0x30a
NT_ARM_VFP = 0x400
NT_ARM_TLS = 0x401
NT_ARM_HW_BREAK = 0x402
NT_ARM_HW_WATCH = 0x403
NT_ARM_SYSTEM_CALL = 0x404
NT_METAG_CBUF = 0x500
NT_METAG_RPIPE = 0x501
NT_METAG_TLS = 0x502

# NT_AUXV defines
AT_NULL = 0             # End of auxv.
AT_IGNORE = 1           # Ignore entry.
AT_EXECFD = 2           # File descriptor of program.
AT_PHDR = 3             # Program headers.
AT_PHENT = 4            # Size of program header.
AT_PHNUM = 5            # Number of program headers.
AT_PAGESZ = 6           # Page size.
AT_BASE = 7             # Interpreter base address.
AT_FLAGS = 8            # Flags.
AT_ENTRY = 9            # Program entry point.
AT_NOTELF = 10          # Set if program is not an ELF.
AT_UID = 11             # UID.
AT_EUID = 12            # Effective UID.
AT_GID = 13             # GID.
AT_EGID = 14            # Effective GID.
AT_CLKTCK = 17          # Clock frequency (e.g. times(2)).
AT_PLATFORM = 15        # String identifying platform.
AT_HWCAP = 16           # Machine dependent hints about processor capabilities.
AT_FPUCW = 18           # Used FPU control word.
AT_DCACHEBSIZE = 19     # Data cache block size.
AT_ICACHEBSIZE = 20     # Instruction cache block size.
AT_UCACHEBSIZE = 21     # Unified cache block size.
AT_IGNOREPPC = 22       # Entry should be ignored.
AT_SECURE = 23          # Boolean, was exec setuid-like?
AT_BASE_PLATFORM = 24   # String identifying real platforms.
AT_RANDOM = 25          # Address of 16 random bytes.
AT_EXECFN = 31          # Filename of executable.
AT_SYSINFO = 32         # Pointer to the global system page used for sys calls
AT_SYSINFO_EHDR = 33
AT_L1I_CACHESHAPE = 34  # Shapes of the caches.
AT_L1D_CACHESHAPE = 35
AT_L2_CACHESHAPE = 36
AT_L3_CACHESHAPE = 37

DT_NULL = 0  # Marks end of dynamic array.
DT_NEEDED = 1  # String table offset of needed library.
DT_PLTRELSZ = 2  # Size of relocation entries in PLT.
DT_PLTGOT = 3  # Address associated with linkage table.
DT_HASH = 4  # Address of symbolic hash table.
DT_STRTAB = 5  # Address of dynamic string table.
DT_SYMTAB = 6  # Address of dynamic symbol table.
DT_RELA = 7  # Address of relocation table (Rela entries).
DT_RELASZ = 8  # Size of Rela relocation table.
DT_RELAENT = 9  # Size of a Rela relocation entry.
DT_STRSZ = 10  # Total size of the string table.
DT_SYMENT = 11  # Size of a symbol table entry.
DT_INIT = 12  # Address of initialization function.
DT_FINI = 13  # Address of termination function.
DT_SONAME = 14  # String table offset of a shared objects name.
DT_RPATH = 15  # String table offset of library search path.
DT_SYMBOLIC = 16  # Changes symbol resolution algorithm.
DT_REL = 17  # Address of relocation table (Rel entries).
DT_RELSZ = 18  # Size of Rel relocation table.
DT_RELENT = 19  # Size of a Rel relocation entry.
DT_PLTREL = 20  # Type of relocation entry used for linking.
DT_DEBUG = 21  # Reserved for debugger.
DT_TEXTREL = 22  # Relocations exist for non-writable segments.
DT_JMPREL = 23  # Address of relocations associated with PLT.
DT_BIND_NOW = 24  # Process all relocations before execution.
DT_INIT_ARRAY = 25  # Pointer to array of initialization functions.
DT_FINI_ARRAY = 26  # Pointer to array of termination functions.
DT_INIT_ARRAYSZ = 27  # Size of DT_INIT_ARRAY.
DT_FINI_ARRAYSZ = 28  # Size of DT_FINI_ARRAY.
DT_RUNPATH = 29  # String table offset of lib search path.
DT_FLAGS = 30  # Flags.
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33
DT_MAXPOSTAGS = 34
DT_GNU_HASH = 0x6FFFFEF5
DT_TLSDESC_PLT = 0x6FFFFEF6  # Location of PLT entry for TLS resolver calls.
DT_TLSDESC_GOT = 0x6FFFFEF7  # Location of GOT entry.
DT_RELACOUNT = 0x6FFFFFF9  # ELF32_Rela count.
DT_RELCOUNT = 0x6FFFFFFA  # ELF32_Rel count.
DT_FLAGS_1 = 0X6FFFFFFB  # Flags_1.
DT_VERSYM = 0x6FFFFFF0  # The address of .gnu.version section.
DT_VERDEF = 0X6FFFFFFC  # The address of the version definition table.
DT_VERDEFNUM = 0X6FFFFFFD  # The number of entries in DT_VERDEF.
DT_VERNEED = 0X6FFFFFFE  # The address of the version Dependency table.
DT_VERNEEDNUM = 0X6FFFFFFF  # The number of entries in DT_VERNEED.


class DynamicTags(dict_utils.Enum):
    enum = {
        'DT_NULL': DT_NULL,
        'DT_NEEDED': DT_NEEDED,
        'DT_PLTRELSZ': DT_PLTRELSZ,
        'DT_PLTGOT': DT_PLTGOT,
        'DT_HASH': DT_HASH,
        'DT_STRTAB': DT_STRTAB,
        'DT_SYMTAB': DT_SYMTAB,
        'DT_RELA': DT_RELA,
        'DT_RELASZ': DT_RELASZ,
        'DT_RELAENT': DT_RELAENT,
        'DT_STRSZ': DT_STRSZ,
        'DT_SYMENT': DT_SYMENT,
        'DT_INIT': DT_INIT,
        'DT_FINI': DT_FINI,
        'DT_SONAME': DT_SONAME,
        'DT_RPATH': DT_RPATH,
        'DT_SYMBOLIC': DT_SYMBOLIC,
        'DT_REL': DT_REL,
        'DT_RELSZ': DT_RELSZ,
        'DT_RELENT': DT_RELENT,
        'DT_PLTREL': DT_PLTREL,
        'DT_DEBUG': DT_DEBUG,
        'DT_TEXTREL': DT_TEXTREL,
        'DT_JMPREL': DT_JMPREL,
        'DT_BIND_NOW': DT_BIND_NOW,
        'DT_INIT_ARRAY': DT_INIT_ARRAY,
        'DT_FINI_ARRAY': DT_FINI_ARRAY,
        'DT_INIT_ARRAYSZ': DT_INIT_ARRAYSZ,
        'DT_FINI_ARRAYSZ': DT_FINI_ARRAYSZ,
        'DT_RUNPATH': DT_RUNPATH,
        'DT_FLAGS': DT_FLAGS,
        'DT_PREINIT_ARRAY': DT_PREINIT_ARRAY,
        'DT_PREINIT_ARRAYSZ': DT_PREINIT_ARRAYSZ,
        'DT_GNU_HASH': DT_GNU_HASH,
        'DT_TLSDESC_PLT': DT_TLSDESC_PLT,
        'DT_TLSDESC_GOT': DT_TLSDESC_GOT,
        'DT_RELACOUNT': DT_RELACOUNT,
        'DT_RELCOUNT': DT_RELCOUNT,
        'DT_FLAGS_1': DT_FLAGS_1,
        'DT_VERSYM': DT_VERSYM,
        'DT_VERDEF': DT_VERDEF,
        'DT_VERDEFNUM': DT_VERDEFNUM,
        'DT_VERNEED': DT_VERNEED,
        'DT_VERNEEDNUM': DT_VERNEEDNUM,
    }

    def __init__(self, t=0):
        dict_utils.Enum.__init__(self, t, self.enum)


# DT_FLAGS bits
DW_FLAGS_BITS = [
    ('DF_ORIGIN', 0x1),
    ('DF_SYMBOLIC', 0x2),
    ('DF_TEXTREL', 0x4),
    ('DF_BIND', 0x8),
    ('DF_STATIC', 0x10)]

# DT_FLAGS_1 bits
DW_FLAGS_1_BITS = [
    ('DF_1_NOW', 0x1),
    ('DF_1_GLOBAL', 0x2),
    ('DF_1_GROUP', 0x4),
    ('DF_1_NODELETE', 0x8),
    ('DF_1_LOADFLTR', 0x10),
    ('DF_1_INITFIRST', 0x20),
    ('DF_1_NOOPEN', 0x40),
    ('DF_1_ORIGIN', 0x80),
    ('DF_1_DIRECT', 0x100),
    ('DF_1_INTERPOSE', 0x400),
    ('DF_1_NODEFLIB', 0x800),
    ('DF_1_NODUMP', 0x1000),
    ('DF_1_CONFALT', 0x2000),
    ('DF_1_ENDFILTEE', 0x4000),
    ('DF_1_DISPRELDNE', 0x8000),
    ('DF_1_DISPRELPND', 0x10000),
    ('DF_1_NODIRECT', 0x20000),
    ('DF_1_IGNMULDEF', 0x40000),
    ('DF_1_NOKSYMS', 0x80000),
    ('DF_1_NOHDR', 0x100000),
    ('DF_1_EDITED', 0x200000),
    ('DF_1_NORELOC', 0x400000),
    ('DF_1_SYMINTPOSE', 0x800000),
    ('DF_1_GLOBAUDIT', 0x1000000),
    ('DF_1_SINGLETON', 0x2000000)]


class AuxvType(dict_utils.Enum):
    enum = {
        'AT_NULL':  AT_NULL,
        'AT_IGNORE':  AT_IGNORE,
        'AT_EXECFD':  AT_EXECFD,
        'AT_PHDR':  AT_PHDR,
        'AT_PHENT':  AT_PHENT,
        'AT_PHNUM':  AT_PHNUM,
        'AT_PAGESZ':  AT_PAGESZ,
        'AT_BASE':  AT_BASE,
        'AT_FLAGS':  AT_FLAGS,
        'AT_ENTRY':  AT_ENTRY,
        'AT_NOTELF':  AT_NOTELF,
        'AT_UID':  AT_UID,
        'AT_EUID':  AT_EUID,
        'AT_GID':  AT_GID,
        'AT_EGID':  AT_EGID,
        'AT_CLKTCK':  AT_CLKTCK,
        'AT_PLATFORM':  AT_PLATFORM,
        'AT_HWCAP':  AT_HWCAP,
        'AT_FPUCW':  AT_FPUCW,
        'AT_DCACHEBSIZE':  AT_DCACHEBSIZE,
        'AT_ICACHEBSIZE':  AT_ICACHEBSIZE,
        'AT_UCACHEBSIZE':  AT_UCACHEBSIZE,
        'AT_IGNOREPPC':  AT_IGNOREPPC,
        'AT_SECURE':  AT_SECURE,
        'AT_BASE_PLATFORM':  AT_BASE_PLATFORM,
        'AT_RANDOM':  AT_RANDOM,
        'AT_EXECFN':  AT_EXECFN,
        'AT_SYSINFO':  AT_SYSINFO,
        'AT_SYSINFO_EHDR':  AT_SYSINFO_EHDR,
        'AT_L1I_CACHESHAPE':  AT_L1I_CACHESHAPE,
        'AT_L1D_CACHESHAPE':  AT_L1D_CACHESHAPE,
        'AT_L2_CACHESHAPE':  AT_L2_CACHESHAPE,
        'AT_L3_CACHESHAPE':  AT_L3_CACHESHAPE
    }

    def __init__(self, t=0):
        dict_utils.Enum.__init__(self, t, self.enum)


class CoreNoteType(dict_utils.Enum):
    enum = {
        'NT_PRSTATUS': NT_PRSTATUS,
        'NT_PRFPREG': NT_PRFPREG,
        'NT_PRPSINFO': NT_PRPSINFO,
        'NT_TASKSTRUCT': NT_TASKSTRUCT,
        'NT_AUXV': NT_AUXV,
        'NT_SIGINFO': NT_SIGINFO,
        'NT_FILE': NT_FILE,
        'NT_PRXFPREG': NT_PRXFPREG,
        'NT_PPC_VMX': NT_PPC_VMX,
        'NT_PPC_SPE': NT_PPC_SPE,
        'NT_PPC_VSX': NT_PPC_VSX,
        'NT_386_TLS': NT_386_TLS,
        'NT_386_IOPERM': NT_386_IOPERM,
        'NT_X86_XSTATE': NT_X86_XSTATE,
        'NT_S390_HIGH_GPRS': NT_S390_HIGH_GPRS,
        'NT_S390_TIMER': NT_S390_TIMER,
        'NT_S390_TODCMP': NT_S390_TODCMP,
        'NT_S390_TODPREG': NT_S390_TODPREG,
        'NT_S390_CTRS': NT_S390_CTRS,
        'NT_S390_PREFIX': NT_S390_PREFIX,
        'NT_S390_LAST_BREAK': NT_S390_LAST_BREAK,
        'NT_S390_SYSTEM_CALL': NT_S390_SYSTEM_CALL,
        'NT_S390_TDB': NT_S390_TDB,
        'NT_S390_VXRS_LOW': NT_S390_VXRS_LOW,
        'NT_S390_VXRS_HIGH': NT_S390_VXRS_HIGH,
        'NT_ARM_VFP': NT_ARM_VFP,
        'NT_ARM_TLS': NT_ARM_TLS,
        'NT_ARM_HW_BREAK': NT_ARM_HW_BREAK,
        'NT_ARM_HW_WATCH': NT_ARM_HW_WATCH,
        'NT_ARM_SYSTEM_CALL': NT_ARM_SYSTEM_CALL,
        'NT_METAG_CBUF': NT_METAG_CBUF,
        'NT_METAG_RPIPE': NT_METAG_RPIPE,
        'NT_METAG_TLS': NT_METAG_TLS
    }

    def __init__(self, t=0):
        dict_utils.Enum.__init__(self, t, self.enum)


class ProgramHeaderType(dict_utils.Enum):
    enum = {
        'PT_NULL': PT_NULL,
        'PT_LOAD': PT_LOAD,
        'PT_DYNAMIC': PT_DYNAMIC,
        'PT_INTERP': PT_INTERP,
        'PT_NOTE': PT_NOTE,
        'PT_SHLIB': PT_SHLIB,
        'PT_PHDR': PT_PHDR,
        'PT_TLS': PT_TLS,
        'PT_LOOS': PT_LOOS,
        'PT_HIOS': PT_HIOS,
        'PT_LOPROC': PT_LOPROC,
        'PT_HIPROC': PT_HIPROC,
        'PT_GNU_EH_FRAME': PT_GNU_EH_FRAME,
        'PT_SUNW_EH_FRAME': PT_SUNW_EH_FRAME,
        'PT_SUNW_UNWIND': PT_SUNW_UNWIND,
        'PT_GNU_STACK': PT_GNU_STACK,
        'PT_GNU_RELRO': PT_GNU_RELRO
    }

    def __init__(self, t=0):
        dict_utils.Enum.__init__(self, t, self.enum)


class Identification(dict_utils.Enum):
    enum = {
        'EI_MAG0': EI_MAG0,
        'EI_MAG1': EI_MAG1,
        'EI_MAG2': EI_MAG2,
        'EI_MAG3': EI_MAG3,
        'EI_CLASS': EI_CLASS,
        'EI_DATA': EI_DATA,
        'EI_VERSION': EI_VERSION,
        'EI_OSABI': EI_OSABI,
        'EI_ABIVERSION': EI_ABIVERSION,
        'EI_PAD': EI_PAD
    }

    def __init__(self, t=0):
        dict_utils.Enum.__init__(self, t, self.enum)


class ElfClass(dict_utils.Enum):
    enum = {
        'ELFCLASSNONE': ELFCLASSNONE,
        'ELFCLASS32': ELFCLASS32,
        'ELFCLASS64': ELFCLASS64
    }

    def __init__(self, t=0):
        dict_utils.Enum.__init__(self, t, self.enum)


class ElfData(dict_utils.Enum):
    enum = {
        'ELFDATANONE': ELFDATANONE,
        'ELFDATA2LSB': ELFDATA2LSB,
        'ELFDATA2MSB': ELFDATA2MSB
    }

    def __init__(self, t=0):
        dict_utils.Enum.__init__(self, t, self.enum)


class FileType(dict_utils.Enum):
    enum = {
        'ET_NONE': ET_NONE,
        'ET_REL': ET_REL,
        'ET_EXEC': ET_EXEC,
        'ET_DYN': ET_DYN,
        'ET_CORE': ET_CORE
    }

    def __init__(self, t=0):
        dict_utils.Enum.__init__(self, t, self.enum)


class ElfOSABI(dict_utils.Enum):
    enum = {
        'ELFOSABI_NONE': ELFOSABI_NONE,
        'ELFOSABI_HPUX': ELFOSABI_HPUX,
        'ELFOSABI_NETBSD': ELFOSABI_NETBSD,
        'ELFOSABI_GNU': ELFOSABI_GNU,
        'ELFOSABI_LINUX': ELFOSABI_LINUX,
        'ELFOSABI_HURD': ELFOSABI_HURD,
        'ELFOSABI_SOLARIS': ELFOSABI_SOLARIS,
        'ELFOSABI_AIX': ELFOSABI_AIX,
        'ELFOSABI_IRIX': ELFOSABI_IRIX,
        'ELFOSABI_FREEBSD': ELFOSABI_FREEBSD,
        'ELFOSABI_TRU64': ELFOSABI_TRU64,
        'ELFOSABI_MODESTO': ELFOSABI_MODESTO,
        'ELFOSABI_OPENBSD': ELFOSABI_OPENBSD,
        'ELFOSABI_OPENVMS': ELFOSABI_OPENVMS,
        'ELFOSABI_NSK': ELFOSABI_NSK,
        'ELFOSABI_AROS': ELFOSABI_AROS,
        'ELFOSABI_FENIXOS': ELFOSABI_FENIXOS,
        'ELFOSABI_CLOUDABI': ELFOSABI_CLOUDABI,
        'ELFOSABI_C6000_ELFABI': ELFOSABI_C6000_ELFABI,
        'ELFOSABI_AMDGPU_HSA': ELFOSABI_AMDGPU_HSA,
        'ELFOSABI_C6000_LINUX': ELFOSABI_C6000_LINUX,
        'ELFOSABI_ARM': ELFOSABI_ARM,
        'ELFOSABI_STANDALONE': ELFOSABI_STANDALONE
    }

    def __init__(self, t=0):
        dict_utils.Enum.__init__(self, t, self.enum)


class Machine(dict_utils.Enum):
    enum = {
        'EM_NONE': EM_NONE,
        'EM_M32': EM_M32,
        'EM_SPARC': EM_SPARC,
        'EM_386': EM_386,
        'EM_68K': EM_68K,
        'EM_88K': EM_88K,
        'EM_IAMCU': EM_IAMCU,
        'EM_860': EM_860,
        'EM_MIPS': EM_MIPS,
        'EM_S370': EM_S370,
        'EM_MIPS_RS3_LE': EM_MIPS_RS3_LE,
        'EM_PARISC': EM_PARISC,
        'EM_VPP500': EM_VPP500,
        'EM_SPARC32PLUS': EM_SPARC32PLUS,
        'EM_960': EM_960,
        'EM_PPC': EM_PPC,
        'EM_PPC64': EM_PPC64,
        'EM_S390': EM_S390,
        'EM_SPU': EM_SPU,
        'EM_V800': EM_V800,
        'EM_FR20': EM_FR20,
        'EM_RH32': EM_RH32,
        'EM_RCE': EM_RCE,
        'EM_ARM': EM_ARM,
        'EM_ALPHA': EM_ALPHA,
        'EM_SH': EM_SH,
        'EM_SPARCV9': EM_SPARCV9,
        'EM_TRICORE': EM_TRICORE,
        'EM_ARC': EM_ARC,
        'EM_H8_300': EM_H8_300,
        'EM_H8_300H': EM_H8_300H,
        'EM_H8S': EM_H8S,
        'EM_H8_500': EM_H8_500,
        'EM_IA_64': EM_IA_64,
        'EM_MIPS_X': EM_MIPS_X,
        'EM_COLDFIRE': EM_COLDFIRE,
        'EM_68HC12': EM_68HC12,
        'EM_MMA': EM_MMA,
        'EM_PCP': EM_PCP,
        'EM_NCPU': EM_NCPU,
        'EM_NDR1': EM_NDR1,
        'EM_STARCORE': EM_STARCORE,
        'EM_ME16': EM_ME16,
        'EM_ST100': EM_ST100,
        'EM_TINYJ': EM_TINYJ,
        'EM_X86_64': EM_X86_64,
        'EM_PDSP': EM_PDSP,
        'EM_PDP10': EM_PDP10,
        'EM_PDP11': EM_PDP11,
        'EM_FX66': EM_FX66,
        'EM_ST9PLUS': EM_ST9PLUS,
        'EM_ST7': EM_ST7,
        'EM_68HC16': EM_68HC16,
        'EM_68HC11': EM_68HC11,
        'EM_68HC08': EM_68HC08,
        'EM_68HC05': EM_68HC05,
        'EM_SVX': EM_SVX,
        'EM_ST19': EM_ST19,
        'EM_VAX': EM_VAX,
        'EM_CRIS': EM_CRIS,
        'EM_JAVELIN': EM_JAVELIN,
        'EM_FIREPATH': EM_FIREPATH,
        'EM_ZSP': EM_ZSP,
        'EM_MMIX': EM_MMIX,
        'EM_HUANY': EM_HUANY,
        'EM_PRISM': EM_PRISM,
        'EM_AVR': EM_AVR,
        'EM_FR30': EM_FR30,
        'EM_D10V': EM_D10V,
        'EM_D30V': EM_D30V,
        'EM_V850': EM_V850,
        'EM_M32R': EM_M32R,
        'EM_MN10300': EM_MN10300,
        'EM_MN10200': EM_MN10200,
        'EM_PJ': EM_PJ,
        'EM_OPENRISC': EM_OPENRISC,
        'EM_ARC_COMPACT': EM_ARC_COMPACT,
        'EM_XTENSA': EM_XTENSA,
        'EM_VIDEOCORE': EM_VIDEOCORE,
        'EM_TMM_GPP': EM_TMM_GPP,
        'EM_NS32K': EM_NS32K,
        'EM_TPC': EM_TPC,
        'EM_SNP1K': EM_SNP1K,
        'EM_ST200': EM_ST200,
        'EM_IP2K': EM_IP2K,
        'EM_MAX': EM_MAX,
        'EM_CR': EM_CR,
        'EM_F2MC16': EM_F2MC16,
        'EM_MSP430': EM_MSP430,
        'EM_BLACKFIN': EM_BLACKFIN,
        'EM_SE_C33': EM_SE_C33,
        'EM_SEP': EM_SEP,
        'EM_ARCA': EM_ARCA,
        'EM_UNICORE': EM_UNICORE,
        'EM_EXCESS': EM_EXCESS,
        'EM_DXP': EM_DXP,
        'EM_ALTERA_NIOS2': EM_ALTERA_NIOS2,
        'EM_CRX': EM_CRX,
        'EM_XGATE': EM_XGATE,
        'EM_C166': EM_C166,
        'EM_M16C': EM_M16C,
        'EM_DSPIC30F': EM_DSPIC30F,
        'EM_CE': EM_CE,
        'EM_M32C': EM_M32C,
        'EM_TSK3000': EM_TSK3000,
        'EM_RS08': EM_RS08,
        'EM_SHARC': EM_SHARC,
        'EM_ECOG2': EM_ECOG2,
        'EM_SCORE7': EM_SCORE7,
        'EM_DSP24': EM_DSP24,
        'EM_VIDEOCORE3': EM_VIDEOCORE3,
        'EM_LATTICEMICO32': EM_LATTICEMICO32,
        'EM_SE_C17': EM_SE_C17,
        'EM_TI_C6000': EM_TI_C6000,
        'EM_TI_C2000': EM_TI_C2000,
        'EM_TI_C5500': EM_TI_C5500,
        'EM_MMDSP_PLUS': EM_MMDSP_PLUS,
        'EM_CYPRESS_M8C': EM_CYPRESS_M8C,
        'EM_R32C': EM_R32C,
        'EM_TRIMEDIA': EM_TRIMEDIA,
        'EM_HEXAGON': EM_HEXAGON,
        'EM_8051': EM_8051,
        'EM_STXP7X': EM_STXP7X,
        'EM_NDS32': EM_NDS32,
        'EM_ECOG1': EM_ECOG1,
        'EM_ECOG1X': EM_ECOG1X,
        'EM_MAXQ30': EM_MAXQ30,
        'EM_XIMO16': EM_XIMO16,
        'EM_MANIK': EM_MANIK,
        'EM_CRAYNV2': EM_CRAYNV2,
        'EM_RX': EM_RX,
        'EM_METAG': EM_METAG,
        'EM_MCST_ELBRUS': EM_MCST_ELBRUS,
        'EM_ECOG16': EM_ECOG16,
        'EM_CR16': EM_CR16,
        'EM_ETPU': EM_ETPU,
        'EM_SLE9X': EM_SLE9X,
        'EM_L10M': EM_L10M,
        'EM_K10M': EM_K10M,
        'EM_AARCH64': EM_AARCH64,
        'EM_AVR32': EM_AVR32,
        'EM_STM8': EM_STM8,
        'EM_TILE64': EM_TILE64,
        'EM_TILEPRO': EM_TILEPRO,
        'EM_CUDA': EM_CUDA,
        'EM_TILEGX': EM_TILEGX,
        'EM_CLOUDSHIELD': EM_CLOUDSHIELD,
        'EM_COREA_1ST': EM_COREA_1ST,
        'EM_COREA_2ND': EM_COREA_2ND,
        'EM_ARC_COMPACT2': EM_ARC_COMPACT2,
        'EM_OPEN8': EM_OPEN8,
        'EM_RL78': EM_RL78,
        'EM_VIDEOCORE5': EM_VIDEOCORE5,
        'EM_78KOR': EM_78KOR,
        'EM_56800EX': EM_56800EX,
        'EM_BA1': EM_BA1,
        'EM_BA2': EM_BA2,
        'EM_XCORE': EM_XCORE,
        'EM_MCHP_PIC': EM_MCHP_PIC,
        'EM_INTEL205': EM_INTEL205,
        'EM_INTEL206': EM_INTEL206,
        'EM_INTEL207': EM_INTEL207,
        'EM_INTEL208': EM_INTEL208,
        'EM_INTEL209': EM_INTEL209,
        'EM_KM32': EM_KM32,
        'EM_KMX32': EM_KMX32,
        'EM_KMX16': EM_KMX16,
        'EM_KMX8': EM_KMX8,
        'EM_KVARC': EM_KVARC,
        'EM_CDP': EM_CDP,
        'EM_COGE': EM_COGE,
        'EM_COOL': EM_COOL,
        'EM_NORC': EM_NORC,
        'EM_CSR_KALIMBA': EM_CSR_KALIMBA,
        'EM_AMDGPU': EM_AMDGPU
    }

    def __init__(self, t=0):
        dict_utils.Enum.__init__(self, t, self.enum)


class SectionType(dict_utils.Enum):
    enum = {
        'SHT_NULL': SHT_NULL,
        'SHT_PROGBITS': SHT_PROGBITS,
        'SHT_SYMTAB': SHT_SYMTAB,
        'SHT_STRTAB': SHT_STRTAB,
        'SHT_RELA': SHT_RELA,
        'SHT_HASH': SHT_HASH,
        'SHT_DYNAMIC': SHT_DYNAMIC,
        'SHT_NOTE': SHT_NOTE,
        'SHT_NOBITS': SHT_NOBITS,
        'SHT_REL': SHT_REL,
        'SHT_SHLIB': SHT_SHLIB,
        'SHT_DYNSYM': SHT_DYNSYM,
        'SHT_INIT_ARRAY': SHT_INIT_ARRAY,
        'SHT_FINI_ARRAY': SHT_FINI_ARRAY,
        'SHT_PREINIT_ARRAY': SHT_PREINIT_ARRAY,
        'SHT_GROUP': SHT_GROUP,
        'SHT_SYMTAB_SHNDX': SHT_SYMTAB_SHNDX,
        'SHT_GNU_ATTRIBUTES': SHT_GNU_ATTRIBUTES,
        'SHT_GNU_HASH': SHT_GNU_HASH,
        'SHT_GNU_verdef': SHT_GNU_verdef,
        'SHT_GNU_verneed': SHT_GNU_verneed,
        'SHT_GNU_versym': SHT_GNU_versym,
        'SHT_ARM_EXIDX': SHT_ARM_EXIDX,
        'SHT_ARM_PREEMPTMAP': SHT_ARM_PREEMPTMAP,
        'SHT_ARM_ATTRIBUTES': SHT_ARM_ATTRIBUTES,
        'SHT_ARM_DEBUGOVERLAY': SHT_ARM_DEBUGOVERLAY,
        'SHT_ARM_OVERLAYSECTION': SHT_ARM_OVERLAYSECTION,
        'SHT_HEX_ORDERED': SHT_HEX_ORDERED,
        'SHT_X86_64_UNWIND': SHT_X86_64_UNWIND,
        'SHT_MIPS_REGINFO': SHT_MIPS_REGINFO,
        'SHT_MIPS_OPTIONS': SHT_MIPS_OPTIONS,
        'SHT_MIPS_ABIFLAGS': SHT_MIPS_ABIFLAGS
    }

    def __init__(self, t=0):
        dict_utils.Enum.__init__(self, t, self.enum)


class SymbolBinding(dict_utils.Enum):
    enum = {
        'STB_LOCAL': STB_LOCAL,
        'STB_GLOBAL': STB_GLOBAL,
        'STB_WEAK': STB_WEAK,
        'STB_GNU_UNIQUE': STB_GNU_UNIQUE
    }

    def __init__(self, t=0):
        dict_utils.Enum.__init__(self, t, self.enum)


class SymbolType(dict_utils.Enum):
    enum = {
        'STT_NOTYPE': STT_NOTYPE,
        'STT_OBJECT': STT_OBJECT,
        'STT_FUNC': STT_FUNC,
        'STT_SECTION': STT_SECTION,
        'STT_FILE': STT_FILE,
        'STT_COMMON': STT_COMMON,
        'STT_TLS': STT_TLS,
        'STT_GNU_IFUNC': STT_GNU_IFUNC
    }

    def __init__(self, t=0):
        dict_utils.Enum.__init__(self, t, self.enum)


class Header(object):
    '''Represents the ELF header for an ELF file'''
    def __init__(self, elf):
        self.elf = elf
        data = elf.data
        data.seek(0)
        self.e_ident = data.get_n_uint8(EI_NIDENT)
        if len(self.e_ident) == EI_NIDENT and self.is_valid():
            # ELF magic bytes match, so this is an ELF file
            data.set_byte_order(self.get_byte_order())
            data.set_addr_size(self.get_address_byte_size())
            self.e_type = data.get_uint16()
            self.e_machine = data.get_uint16()
            self.e_version = data.get_uint32()
            self.e_entry = data.get_address()
            self.e_phoff = data.get_address()
            self.e_shoff = data.get_address()
            self.e_flags = data.get_uint32()
            self.e_ehsize = data.get_uint16()
            self.e_phentsize = data.get_uint16()
            self.e_phnum = data.get_uint16()
            self.e_shentsize = data.get_uint16()
            self.e_shnum = data.get_uint16()
            self.e_shstrndx = data.get_uint16()
        else:
            # This isn't an ELF file, clear our header
            self.clear()

    def dump(self, f=sys.stdout):
        print >>f, 'ELF Header:'
        for i in range(EI_PAD):
            if i == EI_OSABI:
                print >>f, 'e_ident[%-13s] = 0x%2.2x %s' % (
                        str(Identification(i)), self.e_ident[i],
                        str(ElfOSABI(self.e_ident[i])))
            elif i == EI_MAG1 or i == EI_MAG2 or i == EI_MAG3:
                print >>f, "e_ident[%-13s] = 0x%2.2x '%c'" % (
                        str(Identification(i)), self.e_ident[i],
                        self.e_ident[i])
            elif i == EI_CLASS:
                print >>f, 'e_ident[%-13s] = 0x%2.2x %s' % (
                        str(Identification(i)), self.e_ident[i],
                        str(ElfClass(self.e_ident[i])))
            elif i == EI_DATA:
                print >>f, 'e_ident[%-13s] = 0x%2.2x %s' % (
                        str(Identification(i)), self.e_ident[i],
                        str(ElfData(self.e_ident[i])))
            else:
                print >>f, 'e_ident[%-13s] = 0x%2.2x' % (
                        str(Identification(i)), self.e_ident[i])
        print >>f, 'e_type      = 0x%4.4x %s' % (self.e_type,
                                                 str(FileType(self.e_type)))
        print >>f, 'e_machine   = 0x%4.4x %s' % (self.e_machine,
                                                 str(Machine(self.e_machine)))
        print >>f, 'e_version   = 0x%8.8x' % (self.e_version)
        addr_size = self.get_address_byte_size()
        if addr_size == 4:
            print >>f, 'e_entry     = 0x%8.8x' % (self.e_entry)
            print >>f, 'e_phoff     = 0x%8.8x' % (self.e_phoff)
            print >>f, 'e_shoff     = 0x%8.8x' % (self.e_shoff)
        elif addr_size == 8:
            print >>f, 'e_entry     = 0x%16.16x' % (self.e_entry)
            print >>f, 'e_phoff     = 0x%16.16x' % (self.e_phoff)
            print >>f, 'e_shoff     = 0x%16.16x' % (self.e_shoff)
        print >>f, 'e_flags     = 0x%8.8x' % (self.e_flags)
        print >>f, 'e_ehsize    = 0x%4.4x' % (self.e_ehsize)
        print >>f, 'e_phentsize = 0x%4.4x' % (self.e_phentsize)
        print >>f, 'e_phnum     = 0x%4.4x' % (self.e_phnum)
        print >>f, 'e_shentsize = 0x%4.4x' % (self.e_shentsize)
        print >>f, 'e_shnum     = 0x%4.4x' % (self.e_shnum)
        print >>f, 'e_shstrndx  = 0x%4.4x' % (self.e_shstrndx)

    def is_valid(self):
        e = self.e_ident
        return (e and
                e[EI_MAG0] == 0x7f and
                e[EI_MAG1] == ord('E') and
                e[EI_MAG2] == ord('L') and
                e[EI_MAG3] == ord('F'))

    def clear(self):
        self.e_ident = None
        self.e_type = 0
        self.e_machine = 0
        self.e_version = 0
        self.e_entry = 0
        self.e_phoff = 0
        self.e_shoff = 0
        self.e_flags = 0
        self.e_ehsize = 0
        self.e_phentsize = 0
        self.e_phnum = 0
        self.e_shentsize = 0
        self.e_shnum = 0
        self.e_shstrndx = 0

    def get_address_byte_size(self):
        if self.e_ident:
            if self.e_ident[EI_CLASS] == ELFCLASS32:
                return 4
            elif self.e_ident[EI_CLASS] == ELFCLASS64:
                return 8
        return 0

    def get_byte_order(self):
        if self.e_ident:
            if self.e_ident[EI_DATA] == ELFDATA2LSB:
                return 'little'
            elif self.e_ident[EI_DATA] == ELFDATA2MSB:
                return 'big'
        return 0


class SectionHeader(object):
    '''
    struct Elf32_Shdr {
      Elf32_Word sh_name;      // Section name (index into string table)
      Elf32_Word sh_type;      // Section type (SHT_*)
      Elf32_Word sh_flags;     // Section flags (SHF_*)
      Elf32_Addr sh_addr;      // Address where section is to be loaded
      Elf32_Off  sh_offset;    // File offset of section data, in bytes
      Elf32_Word sh_size;      // Size of section, in bytes
      Elf32_Word sh_link;      // Section type-specific header table index link
      Elf32_Word sh_info;      // Section type-specific extra information
      Elf32_Word sh_addralign; // Section address alignment
      Elf32_Word sh_entsize;   // Size of records contained within the section
    };

    // Section header for ELF64 - same fields as ELF32, different types.
    struct Elf64_Shdr {
      Elf64_Word  sh_name;
      Elf64_Word  sh_type;
      Elf64_Xword sh_flags;
      Elf64_Addr  sh_addr;
      Elf64_Off   sh_offset;
      Elf64_Xword sh_size;
      Elf64_Word  sh_link;
      Elf64_Word  sh_info;
      Elf64_Xword sh_addralign;
      Elf64_Xword sh_entsize;
    };
    '''
    def __init__(self, elf, index):
        self.index = index
        self.elf = elf
        self.name = ''
        data = elf.data
        self.sh_name = data.get_uint32()
        self.sh_type = data.get_uint32()
        self.sh_flags = data.get_address()
        self.sh_addr = data.get_address()
        self.sh_offset = data.get_address()
        self.sh_size = data.get_address()
        self.sh_link = data.get_uint32()
        self.sh_info = data.get_uint32()
        self.sh_addralign = data.get_address()
        self.sh_entsize = data.get_address()

    @classmethod
    def encode(cls, data, shstrtab, name = '', type = SHT_NULL, flags = 0, addr = 0, offset = 0, size = 0, link = 0, info = 0, addr_align = 0, entsize = 0):
        data.put_uint32(shstrtab.get(name))
        data.put_uint32(type)
        data.put_address(flags)
        data.put_address(addr)
        data.put_address(offset)
        data.put_address(size)
        data.put_uint32(link)
        data.put_uint32(info)
        data.put_address(addr_align)
        data.put_address(entsize)

    def contains(self, addr):
        return self.sh_addr <= addr and addr < (self.sh_addr + self.sh_size)

    def dump(self, flat, f=sys.stdout):
        if flat:
            addr_size = self.elf.get_address_byte_size()
            if self.index == 0:
                print >>f, 'Section Headers:'
                if addr_size == 4:
                    f.write(('Index   sh_name    sh_type           sh_flags   '
                             'sh_addr    sh_offset  sh_size    sh_link    '
                             'sh_info    sh_addrali sh_entsize\n'))
                    f.write(('======= ---------- ----------------- ---------- '
                             '---------- ---------- ---------- ---------- '
                             '---------- ---------- ----------\n'))
                else:
                    f.write(('Index   sh_name    sh_type           '
                             'sh_flags           sh_addr            '
                             'sh_offset          sh_size            '
                             'sh_link    sh_info    sh_addr_a          '
                             'sh_entsize\n'))
                    f.write(('======= ---------- ----------------- '
                             '------------------ ------------------ '
                             '------------------ ------------------ '
                             '---------- ---------- ------------------ '
                             '------------------\n'))

            f.write('[%5u] ' % (self.index))
            f.write('0x%8.8x %-18s' % (self.sh_name,
                                       str(SectionType(self.sh_type))))
            if addr_size == 4:
                f.write('0x%8.8x 0x%8.8x 0x%8.8x 0x%8.8x ' % (self.sh_flags,
                                                              self.sh_addr,
                                                              self.sh_offset,
                                                              self.sh_size))
            else:
                f.write('0x%16.16x 0x%16.16x 0x%16.16x 0x%16.16x ' % (
                        self.sh_flags, self.sh_addr, self.sh_offset,
                        self.sh_size))
            f.write('0x%8.8x 0x%8.8x ' % (self.sh_link, self.sh_info))
            if addr_size == 4:
                f.write('0x%8.8x 0x%8.8x ' % (self.sh_addralign, self.sh_entsize))
            else:
                f.write('0x%16.16x 0x%16.16x ' % (self.sh_addralign,
                                                  self.sh_entsize))
            f.write(self.name)
        else:
            print >>f, 'Section[%u]:' % (self.index)
            if self.name:
                print >>f, 'sh_name      = 0x%8.8x "%s"' % (self.sh_name,
                                                            self.name)
            else:
                print >>f, 'sh_name      = 0x%8.8x' % (self.sh_name)
            print >>f, 'sh_type      = 0x%8.8x %s' % (self.sh_type,
                                                      str(SectionType(
                                                                self.sh_type)))
            addr_size = self.elf.get_address_byte_size()
            if addr_size == 4:
                print >>f, 'sh_flags     = 0x%8.8x' % (self.sh_flags)
                print >>f, 'sh_addr      = 0x%8.8x' % (self.sh_addr)
                print >>f, 'sh_offset    = 0x%8.8x' % (self.sh_offset)
                print >>f, 'sh_size      = 0x%8.8x' % (self.sh_size)
            elif addr_size == 8:
                print >>f, 'sh_flags     = 0x%16.16x' % (self.sh_flags)
                print >>f, 'sh_addr      = 0x%16.16x' % (self.sh_addr)
                print >>f, 'sh_offset    = 0x%16.16x' % (self.sh_offset)
                print >>f, 'sh_size      = 0x%16.16x' % (self.sh_size)
            print >>f, 'sh_link      = 0x%8.8x' % (self.sh_link)
            print >>f, 'sh_info      = 0x%8.8x' % (self.sh_info)
            if addr_size == 4:
                print >>f, 'sh_addralign = 0x%8.8x' % (self.sh_size)
                print >>f, 'sh_entsize   = 0x%8.8x' % (self.sh_entsize)
            elif addr_size == 8:
                print >>f, 'sh_addralign = 0x%16.16x' % (self.sh_size)
                print >>f, 'sh_entsize   = 0x%16.16x' % (self.sh_entsize)

    def get_contents(self):
        '''Get the section contents as a python string'''
        if self.sh_size > 0 and self.sh_type != SHT_NOBITS:
            data = self.elf.data
            if data:
                data.push_offset_and_seek(self.sh_offset)
                bytes = data.read_size(self.sh_size)
                data.pop_offset_and_seek()
                return bytes
        return None

    def get_contents_as_extractor(self):
        bytes = self.get_contents()
        return file_extract.FileExtract(StringIO.StringIO(bytes),
                                        self.elf.data.byte_order,
                                        self.elf.data.addr_size)


class ProgramHeader(object):
    '''
        struct Elf32_Phdr {
          Elf32_Word p_type;   // Type of segment
          Elf32_Off  p_offset; // File offset where segment is located
          Elf32_Addr p_vaddr;  // Virtual address of beginning of segment
          Elf32_Addr p_paddr;  // Physical address of beginning of segment
          Elf32_Word p_filesz; // Number of bytes in file image of segment
          Elf32_Word p_memsz;  // Number of bytes in mem image of segment
          Elf32_Word p_flags;  // Segment flags
          Elf32_Word p_align;  // Segment alignment constraint
        };

        // Program header for ELF64.
        struct Elf64_Phdr {
          Elf64_Word   p_type;   // Type of segment
          Elf64_Word   p_flags;  // Segment flags
          Elf64_Off    p_offset; // File offset where segment is located
          Elf64_Addr   p_vaddr;  // Virtual address of beginning of segment
          Elf64_Addr   p_paddr;  // Physical addr of beginning of segment
          Elf64_Xword  p_filesz; // Num. of bytes in file image of segment
          Elf64_Xword  p_memsz;  // Num. of bytes in mem image of segment
          Elf64_Xword  p_align;  // Segment alignment constraint
        };
    '''
    def __init__(self, elf, index):
        self.index = index
        self.elf = elf
        self.name = ''
        data = elf.data
        addr_size = self.elf.get_address_byte_size()
        if addr_size == 4:
            self.p_type = data.get_uint32()
            self.p_offset = data.get_uint32()
            self.p_vaddr = data.get_uint32()
            self.p_paddr = data.get_uint32()
            self.p_filesz = data.get_uint32()
            self.p_memsz = data.get_uint32()
            self.p_flags = data.get_uint32()
            self.p_align = data.get_uint32()
        elif addr_size == 8:
            self.p_type = data.get_uint32()
            self.p_flags = data.get_uint32()
            self.p_offset = data.get_uint64()
            self.p_vaddr = data.get_uint64()
            self.p_paddr = data.get_uint64()
            self.p_filesz = data.get_uint64()
            self.p_memsz = data.get_uint64()
            self.p_align = data.get_uint64()

    def get_contents(self):
        '''Get the program header contents as a python string'''
        if self.p_filesz > 0 and self.p_offset > 0:
            data = self.elf.data
            if data:
                data.push_offset_and_seek(self.p_offset)
                bytes = data.read_size(self.p_filesz)
                data.pop_offset_and_seek()
                return bytes
        return None

    def get_contents_as_extractor(self):
        bytes = self.get_contents()
        return file_extract.FileExtract(StringIO.StringIO(bytes),
                                        self.elf.data.byte_order,
                                        self.elf.data.addr_size)

    def dump(self, flat, f=sys.stdout):
        if flat:
            if self.index == 0:
                f.write('Program Headers:\n')
                f.write(('Index   p_type           p_flags    '
                         'p_offset           p_vaddr            '
                         'p_paddr            p_filesz           '
                         'p_memsz            p_align\n'))
                f.write(('======= ---------------- ---------- '
                         '------------------ ------------------ '
                         '------------------ ------------------ '
                         '------------------ ------------------\n'))

            f.write(('[%5u] %-*s 0x%8.8x 0x%16.16x 0x%16.16x 0x%16.16x '
                     '0x%16.16x 0x%16.16x 0x%16.16x') % (
                            self.index, ProgramHeaderType.max_width(),
                            str(ProgramHeaderType(self.p_type)), self.p_flags,
                            self.p_offset, self.p_vaddr, self.p_paddr,
                            self.p_filesz, self.p_memsz, self.p_align))
        else:
            print >>f, 'Program Header[%u]:' % (self.index)
            print >>f, 'p_type   = 0x%8.8x %s' % (self.p_type,
                                                  str(ProgramHeaderType(
                                                        self.p_type)))
            print >>f, 'p_flags  = 0x%8.8x' % (self.p_flags)
            print >>f, 'p_offset = 0x%16.16x' % (self.p_offset)
            print >>f, 'p_vaddr  = 0x%16.16x' % (self.p_vaddr)
            print >>f, 'p_paddr  = 0x%16.16x' % (self.p_paddr)
            print >>f, 'p_filesz = 0x%16.16x' % (self.p_filesz)
            print >>f, 'p_memsz  = 0x%16.16x' % (self.p_memsz)
            print >>f, 'p_align  = 0x%16.16x' % (self.p_align)


class Symbol(object):
    '''
    struct Elf32_Sym {
      Elf32_Word    st_name;  // Symbol name (index into string table)
      Elf32_Addr    st_value; // Value or address associated with the symbol
      Elf32_Word    st_size;  // Size of the symbol
      unsigned char st_info;  // Symbol's type and binding attributes
      unsigned char st_other; // Must be zero; reserved
      Elf32_Half    st_shndx; // Section index symbol is defined in
    };

    // Symbol table entries for ELF64.
    struct Elf64_Sym {
      Elf64_Word      st_name;  // Symbol name (index into string table)
      unsigned char   st_info;  // Symbol's type and binding attributes
      unsigned char   st_other; // Must be zero; reserved
      Elf64_Half      st_shndx; // Section index symbol is defined in
      Elf64_Addr      st_value; // Value or address associated with the symbol
      Elf64_Xword     st_size;  // Size of the symbol
    };
    '''
    def __init__(self, index, addr_size, data, strtab, elf):
        self.index = index
        if addr_size == 4:
            self.st_name = data.get_uint32()
            self.st_value = data.get_uint32()
            self.st_size = data.get_uint32()
            self.st_info = data.get_uint8()
            self.st_other = data.get_uint8()
            self.st_shndx = data.get_uint16()
        elif addr_size == 8:
            self.st_name = data.get_uint32()
            self.st_info = data.get_uint8()
            self.st_other = data.get_uint8()
            self.st_shndx = data.get_uint16()
            self.st_value = data.get_uint64()
            self.st_size = data.get_uint64()
        self.name = strtab.get_string(self.st_name)

    def get_binding(self):
        return self.st_info >> 4

    def get_type(self):
        return self.st_info & 0x0f

    def contains(self, addr):
        if self.st_shndx == 0:
            return False
        return self.st_value <= addr and addr < (self.st_value + self.st_size)

    @classmethod
    def dump_header(cls, f=sys.stdout):
        print >>f, 'Symbols:'
        f.write(('Index   st_name    st_value           st_size            '
                 'st_info                             st_other st_shndx '
                 'Name\n'))
        f.write(('======= ---------- ------------------ ------------------ '
                 '----------------------------------- -------- -------- '
                 '===========================\n'))

    def dump(self, flat, f=sys.stdout):
        if flat:
            if self.name:
                f.write(('[%5u] 0x%8.8x 0x%16.16x 0x%16.16x 0x%2.2x '
                         '(%-*s %-*s) 0x%2.2x     %8u %s') % (
                                self.index, self.st_name, self.st_value,
                                self.st_size, self.st_info,
                                SymbolBinding.max_width(),
                                SymbolBinding(self.get_binding()),
                                SymbolType.max_width(),
                                SymbolType(self.get_type()), self.st_other,
                                self.st_shndx, self.name))
            else:
                f.write(('[%5u] 0x%8.8x 0x%16.16x 0x%16.16x 0x%2.2x '
                         '(%-*s %-*s) 0x%2.2x     %8u') % (
                                self.index, self.st_name, self.st_value,
                                self.st_size, self.st_info,
                                SymbolBinding.max_width(),
                                SymbolBinding(self.get_binding()),
                                SymbolType.max_width(),
                                SymbolType(self.get_type()), self.st_other,
                                self.st_shndx))
        else:
            print >>f, 'Symbol[%u]:' % (self.index)
            if self.name:
                print >>f, 'st_name  = 0x%8.8x "%s"' % (self.st_name,
                                                        self.name)
            else:
                print >>f, 'st_name  = 0x%8.8x' % (self.st_name)
            print >>f, 'st_value = 0x%16.16x' % (self.st_value)
            print >>f, 'st_size  = 0x%16.16x' % (self.st_size)
            print >>f, 'st_info  = 0x%2.2x (%s %s)' % (
                    self.st_info, SymbolBinding(self.get_binding()),
                    SymbolType(self.get_type()))
            print >>f, 'st_other = 0x%2.2x' % (self.st_other)
            print >>f, 'st_shndx = 0x%4.4x (%u)' % (self.st_shndx,
                                                    self.st_shndx)


class Note(object):
    '''Respresents an ELF note'''
    def __init__(self, data):
        namesz = data.get_uint32()
        descsz = data.get_uint32()
        self.type = data.get_uint32()
        name_pos = data.tell()
        self.name = data.read_size(namesz)
        data.seek((name_pos + namesz + 3) & ~3)
        self.desc = data.read_size(descsz)
        self.data = file_extract.FileExtract(StringIO.StringIO(self.desc),
                                             data.byte_order, data.addr_size)

    def dump(self, f=sys.stdout):
        print >>f, 'name = "%s"' % (self.name)
        if self.name is 'CORE' or self.name is 'LINUX':
            note_enum = CoreNoteType(self.type)
            print >>f, 'type = 0x%8.8x (%s)' % (self.type, note_enum)
        else:
            print >>f, 'type = 0x%8.8x (%u)' % (self.type, self.type)
        self.data.seek(0)
        if self.type == NT_FILE:
            # Format of NT_FILE note:
            #
            # long count     -- how many files are mapped
            # long page_size -- units for file_ofs
            # array of [COUNT] elements of
            #   long start
            #   long end
            #   long file_ofs
            # followed by COUNT filenames in ASCII: "FILE1" NUL "FILE2" NUL...
            count = self.data.get_address()
            page_size = self.data.get_address()
            print >>f, '    count     = 0x%16.16x (%u)' % (count, count)
            print >>f, '    page_size = 0x%16.16x (%u)' % (page_size,
                                                           page_size)
            elements = list()
            for i in range(count):
                start = self.data.get_address()
                end = self.data.get_address()
                file_ofs = self.data.get_address()
                elements.append([start, end, file_ofs])
            print >>f, ('    Index start              end                '
                        'file_ofs           path')
            print >>f, ('    ===== ------------------ ------------------ '
                        '------------------ '
                        '-------------------------------------')
            for i in range(count):
                path = self.data.get_c_string()
                print >>f, '    [%3u] 0x%16.16x 0x%16.16x 0x%16.16x %s' % (
                        i, elements[i][0], elements[i][1], elements[i][2],
                        path)
            print >>f, ''
        elif self.type == NT_AUXV:
            while True:
                auxv_entry_type = self.data.get_address(-1)
                if auxv_entry_type == -1:
                    break
                auxv_entry_value = self.data.get_address(0)
                print >>f, '    %-*s = %#x' % (AuxvType.max_width(),
                                               AuxvType(auxv_entry_type),
                                               auxv_entry_value)
        else:
            file_extract.dump_memory(0, self.desc, options.num_per_line, f)

    @classmethod
    def extract_notes(cls, data):
        notes = list()
        while 1:
            note = Note(data)
            if len(note.name) == 0:
                break
            else:
                notes.append(note)
        return notes


class ELFDynamic(object):
    '''Represents and dynamic entry in the SHT_DYNAMIC section.'''
    def __init__(self, index, data):
        self.index = index
        self.d_tag = DynamicTags(data.get_address())
        self.d_val = data.get_address()

    def dump(self, elf, f=sys.stdout):
        s = "[%3u] %-*s %#8.8x" % (self.index, DynamicTags.max_width(),
                                   self.d_tag, self.d_val)
        print >>f, s,
        str = None
        bits = None
        val = self.d_tag.get_enum_value()
        d_val_is_str = [DT_NEEDED, DT_RPATH, DT_SONAME, DT_RUNPATH]
        if val in d_val_is_str:
            if elf.dynstr:
                str = elf.dynstr.get_string(self.d_val)
        elif val == DT_FLAGS:
            bits = DW_FLAGS_BITS
        elif val == DT_FLAGS_1:
            bits = DW_FLAGS_1_BITS

        if str is not None:
            print >>f, '"%s"' % (str)
        elif bits is not None:
            for (name, bit) in bits:
                if self.d_val & bit:
                    f.write(' %s' % (name))
            print >>f
        else:
            print >>f


class StringTable(object):
    '''Represents and SHT_STRTAB string table'''
    def __init__(self, data):
        self.data = data

    def get_string(self, offset):
        if self.data:
            self.data.seek(offset)
            return self.data.get_c_string()
        return None


def elf_hash(s):
    """A python implementation of elf_hash(3)."""
    h = 0L
    for c in s:
        h = (h << 4) + ord(c)
        t = (h & 0xF0000000L)
        if t != 0:
            h = h ^ (t >> 24)
        h = h & ~t
    return h


def djb_hash(s):
    """A python implementation of the DJB hash."""
    h = 5381
    for c in s:
        h = h * 33 + ord(c)
    return h & 0xffffffff


class GNUHash(object):
    def __init__(self, elf):
        self.elf = elf
        self.section = elf.get_section_by_dynamic_tag(DT_GNU_HASH)
        if self.section is None:
            self.nbucket = 0
            self.symndx = 0
            self.maskwords = 0
            self.shift2 = 0
            self.addr_size = 0
        else:
            data = self.section.get_contents_as_extractor()
            self.nbucket = data.get_uint32()
            self.symndx = data.get_uint32()
            self.maskwords = data.get_uint32()
            self.shift2 = data.get_uint32()
            self.addr_size = data.get_addr_size()
        self.bloom = list()
        self.buckets = list()
        self.hashes = list()
        for i in range(self.maskwords):
            self.bloom.append(data.get_address())
        for i in range(self.nbucket):
            self.buckets.append(data.get_uint32())
        symtab = self.elf.get_dynsym()
        nhashes = len(symtab) - self.symndx
        for i in range(nhashes):
            self.hashes.append(data.get_uint32())

    def is_valid(self):
        return self.nbucket > 0

    def lookup(self, name):
        if not self.is_valid():
            return None
        symtab = self.elf.get_dynsym()
        h1 = djb_hash(name)
        h2 = h1 >> self.shift2
        # Test against the Bloom filter
        c = self.addr_size * 8
        n = (h1 / c) & self.maskwords
        bitmask = (1 << (h1 % c)) | (1 << (h2 % c))
        if (self.bloom[n] & bitmask) != bitmask:
            return None
        # Locate the hash chain, and corresponding hash value element
        n = self.buckets[h1 % self.nbucket]
        if n == 0:  # Empty hash chain, symbol not present
            return None
        # Walk the chain until the symbol is found or the chain is exhausted.
        sym_idx = n
        h1 &= ~1
        while True:
            symbol = symtab[sym_idx]
            hash_idx = sym_idx - self.symndx
            h2 = self.hashes[hash_idx]
            if h1 == (h2 & ~1) and symbol.name == name:
                return symbol
            # Done if at end of chain */
            if h2 & 1:
                break
            sym_idx += 1
        return None


class Hash(object):
    def __init__(self, elf):
        self.elf = elf
        self.section = elf.get_section_by_dynamic_tag(DT_HASH)
        if self.section is None:
            self.nbucket = 0
            self.nchain = 0
        else:
            data = self.section.get_contents_as_extractor()
            self.nbucket = data.get_uint32()
            self.nchain = data.get_uint32()
        self.buckets = list()
        self.chain = list()
        for i in range(self.nbucket):
            self.buckets.append(data.get_uint32())
        for i in range(self.nchain):
            self.chain.append(data.get_uint32())

    def is_valid(self):
        return self.nbucket > 0

    def lookup(self, name):
        if not self.is_valid():
            return None
        x = elf_hash(name)
        y = self.buckets[x % self.nbucket]
        symtab = self.elf.get_dynsym()
        if len(symtab) != self.nchain:
            symtab = self.elf.get_symtab()
            if len(symtab) != self.nchain:
                return None
        while y != 0:
            symbol = symtab[y]
            if symbol.name == name:
                return symbol
            y = self.chain[y]
        return None


class File(object):
    '''Represents and ELF file'''
    def __init__(self, path):
        self.path = path
        self.data = file_extract.FileExtract(open(self.path), '=', 4)
        self.header = Header(self)
        if not self.header.is_valid():
            self.header = None
            self.data = None
        self.programs = None
        self.section_headers = None
        self.program_headers = None
        self.symtab = None
        self.dynsym = None
        self.symbols = None
        self.dynamic = None
        self.dynstr = None
        self.dwarf = -1
        self.hash = -1

    def get_file_type(self):
        return 'elf'

    def is_valid(self):
        return self.header is not None

    @classmethod
    def create_simple_elf(cls, orig_elf, out_path, sect_info_array):
        '''Create a simple ELF file with sections that contains the data found
        in the sect_info_array. It uses "orig_elf" as the template ELF file
        (for the machine type and byte order and more) when creating the output
        ELF file.'''
        out_file = open(out_path, 'w')
        data = file_extract.FileEncode(out_file,
                                       orig_elf.data.get_byte_order(),
                                       orig_elf.data.get_addr_size())
        # We need one section for each section data + the section header
        # string table + the first SHT_NULL section
        num_section_headers = len(sect_info_array) + 2
        # Section headers will start immediately after this header so the
        # section headers offset is the size in bytes of the ELF header.
        eh = orig_elf.header
        section_headers_offset = eh.e_ehsize
        # Write ELF header
        for e in eh.e_ident:
            data.put_uint8(e)
        data.put_uint16(eh.e_type)
        data.put_uint16(eh.e_machine)
        data.put_uint32(eh.e_version)
        data.put_address(0)  # e_entry
        data.put_address(0)  # e_phoff
        data.put_address(section_headers_offset)  # e_shoff
        data.put_uint32(eh.e_flags)
        data.put_uint16(eh.e_ehsize)
        data.put_uint16(eh.e_phentsize)
        data.put_uint16(0)  # e_phnum
        data.put_uint16(eh.e_shentsize)
        data.put_uint16(num_section_headers) # e_shnum
        data.put_uint16(1)  # e_shstrndx

        # Create the section header string table contents
        shstrtab = file_extract.StringTable()
        shstrtab.insert(".shstrtab")
        for sect_info in sect_info_array:
            shstrtab.insert(sect_info['name'])

        # Encode the shstrtab data so we know how big it is
        shstrtab_data = file_extract.FileEncode(StringIO.StringIO())
        shstrtab.encode(shstrtab_data)
        shstrtab_bytes = shstrtab_data.file.getvalue()
        #----------------------------------------------------------------------
        # Write out section headers
        #----------------------------------------------------------------------
        data_offset = num_section_headers * eh.e_shentsize + section_headers_offset
        shstrtab_size = len(shstrtab_bytes)
        SectionHeader.encode(data=data, shstrtab=shstrtab, type=SHT_NULL)
        SectionHeader.encode(data=data,
                             shstrtab=shstrtab,
                             name=".shstrtab",
                             type=SHT_STRTAB,
                             offset=data_offset,
                             size=shstrtab_size,
                             addr_align=1)
        data_offset += shstrtab_size
        for sect_info in sect_info_array:
            sect_name = sect_info['name']
            sect_bytes = sect_info['bytes']
            sect_type = SHT_PROGBITS
            if 'sh_type' in sect_info:
                sect_type = sect_info['sh_type']
            if 'align' in sect_info:
                align = sect_info['align']
                print 'data_offset before align %u: 0x%8.8x' % (align, data_offset)
                data_offset = file_extract.align_to(data_offset, align)
                print 'data_offset after  align %u: 0x%8.8x' % (align, data_offset)
            sect_bytes_len = len(sect_bytes)
            SectionHeader.encode(data=data,
                                 shstrtab=shstrtab,
                                 name=sect_name,
                                 type=sect_type,
                                 offset=data_offset,
                                 size=sect_bytes_len,
                                 addr_align=1)
            data_offset += sect_bytes_len
        # Write out section header string table data
        data.file.write(shstrtab_bytes)
        for sect_info in sect_info_array:
            sect_bytes = sect_info['bytes']
            if 'align' in sect_info:
                align = sect_info['align']
                data.align_to(align)
            data.file.write(sect_bytes)

        #for sect_name
    def get_address_byte_size(self):
        if self.header is None:
            return 0
        else:
            return self.header.get_address_byte_size()

    def get_hash_table(self):
        if self.hash == -1:
            self.hash = Hash(self)
            if not self.hash.is_valid():
                self.hash = GNUHash(self)
                if not self.hash.is_valid():
                    self.hash = None
        return self.hash

    def get_dwarf(self):
        if self.dwarf is not -1:
            return self.dwarf
        self.dwarf = None
        debug_abbrev_data = self.get_section_contents_by_name('.debug_abbrev')
        debug_info_data = self.get_section_contents_by_name('.debug_info')
        if debug_abbrev_data or debug_info_data:
            debug_aranges_data = self.get_section_contents_by_name(
                    '.debug_aranges')
            debug_line_data = self.get_section_contents_by_name('.debug_line')
            debug_ranges_data = self.get_section_contents_by_name(
                    '.debug_ranges')
            debug_str_data = self.get_section_contents_by_name('.debug_str')
            debug_types_data = self.get_section_contents_by_name(
                    '.debug_types')
            apple_names_data = None
            apple_types_data = None
            self.dwarf = dwarf.DWARF(debug_abbrev_data,
                                     debug_aranges_data,
                                     debug_info_data,
                                     debug_line_data,
                                     debug_ranges_data,
                                     debug_str_data,
                                     apple_names_data,
                                     apple_types_data,
                                     debug_types_data)
        return self.dwarf

    def get_sections_by_name(self, section_name):
        matching_sections = list()
        sections = self.get_section_headers()
        for section in sections:
            if section.name and section.name == section_name:
                matching_sections.append(section)
        return matching_sections

    def get_section_by_addr(self, sh_addr):
        sections = self.get_section_headers()
        for section in sections:
            if section.sh_addr == sh_addr:
                return section
        return None

    def get_section_by_dynamic_tag(self, d_tag):
        '''Many ELF dymnamic tags have values that are file addresses. These
        addresses are often the value of the section's sh_addr and can be
        looked up accordingly.'''
        dyn = self.get_first_dymamic_entry(d_tag)
        if dyn is None:
            return None
        return self.get_section_by_addr(dyn.d_val)

    def get_section_contents_by_name(self, section_name):
        sections = self.get_sections_by_name(section_name)
        if len(sections) > 0:
            return sections[0].get_contents_as_extractor()
        else:
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

    def get_section_headers(self):
        if self.section_headers is None:
            if self.is_valid():
                self.section_headers = list()
                if self.header.e_shnum > 0:
                    self.data.seek(self.header.e_shoff)
                    for section_index in range(self.header.e_shnum):
                        self.section_headers.append(
                                SectionHeader(self, section_index))
                    sh = self.section_headers[self.header.e_shstrndx]
                    shstrtab = StringTable(sh.get_contents_as_extractor())
                    for section_index in range(self.header.e_shnum):
                        section = self.section_headers[section_index]
                        section.name = shstrtab.get_string(section.sh_name)
        return self.section_headers

    def get_section_containing_address(self, addr):
        sections = self.get_section_headers()
        for section in sections:
            if section.contains(addr):
                return section
        return None

    def get_program_headers(self):
        if self.program_headers is None:
            if self.is_valid():
                self.data.seek(self.header.e_phoff)
                self.program_headers = list()
                for idx in range(self.header.e_phnum):
                    self.program_headers.append(ProgramHeader(self, idx))
        return self.program_headers

    def get_symbols(self):
        if self.symbols is None and self.is_valid():
            self.symbols = list()
            self.dynsym = list()
            self.symtab = list()
            sections = self.get_section_headers()
            addr_size = self.get_address_byte_size()
            for section in sections:
                if (section.sh_type == SHT_DYNSYM or
                        section.sh_type == SHT_SYMTAB):
                    is_dynsym = section.sh_type == SHT_DYNSYM
                    symtab_data = section.get_contents_as_extractor()
                    sh = sections[section.sh_link]
                    strtab = StringTable(sh.get_contents_as_extractor())
                    symtab_data_size = symtab_data.get_size()
                    if addr_size == 4:
                        num_symbols = symtab_data_size / SYMENTRY_SIZE32
                    elif addr_size == 8:
                        num_symbols = symtab_data_size / SYMENTRY_SIZE64
                    for i in range(num_symbols):
                        symbol = Symbol(index=i, addr_size=addr_size,
                                        data=symtab_data, strtab=strtab,
                                        elf=self)
                        if is_dynsym:
                            self.dynsym.append(symbol)
                        else:
                            self.symtab.append(symbol)
                        self.symbols.append(symbol)
        return self.symbols

    def get_dynsym(self):
        '''Get only the dynamic symbol table. The dynamic symbol table is
           contained in the section whose type is SHT_DYNSYM.'''
        self.get_symbols()
        return self.dynsym

    def get_symtab(self):
        '''Get only the normal symbol table. The normal symbol table is
           contained in the section whose type is SHT_SYMTAB.'''
        self.get_symbols()
        return self.symtab

    def get_dynamic(self):
        '''Get the array of dynamic entries in this ELF file.'''
        if self.dynamic is None and self.is_valid():
            self.dynamic = list()
            sections = self.get_section_headers()
            for section in sections:
                if section.sh_type == SHT_DYNAMIC:
                    sh = sections[section.sh_link]
                    self.dynstr = StringTable(sh.get_contents_as_extractor())
                    data = section.get_contents_as_extractor()
                    index = 0
                    while 1:
                        dynamic = ELFDynamic(index, data)
                        if dynamic.d_tag == DynamicTags(DT_NULL):
                            break
                        self.dynamic.append(dynamic)
                        index += 1
        return self.dynamic

    def get_first_dymamic_entry(self, d_tag):
        '''Get the first dynamic entry whose tag is "d_tag"'''
        entries = self.get_dynamic()
        for dyn in entries:
            if dyn.d_tag.get_enum_value() == d_tag:
                return dyn
        return None

    def get_symbol_containing_address(self, addr):
        symbols = self.get_symbols()
        for symbol in symbols:
            if symbol.contains(addr):
                return symbol
        return None

    def lookup_address(self, addr, f=sys.stdout):
        print >>f,  'Looking up 0x%x in "%s":' % (addr, self.path)
        section = self.get_section_containing_address(addr)
        if section:
            section.dump(flat=False, f=f)
            print
        symbol = self.get_symbol_containing_address(addr)
        if symbol:
            symbol.dump(flat=False, f=f)
            print

    def dump_section_headers_with_type(self, section_type, f=sys.stdout):
        section_type_enum = SectionType(section_type)
        print >>f, 'Dumping section with type %s:' % (section_type_enum)
        sh_type = section_type_enum.get_enum_value()
        sections = self.get_section_headers()
        if sections:
            for section in sections:
                if section.sh_type == sh_type:
                    section.dump(flat=False, f=f)
                    print >>f, ''
                    contents = section.get_contents()
                    if contents:
                        if section_type == SHT_NOTE:
                            notes = Note.extract_notes(
                                    section.get_contents_as_extractor())
                            for note in notes:
                                note.dump(f=f)
                        else:
                            file_extract.dump_memory(section.sh_addr,
                                                     contents,
                                                     options.num_per_line, f)
        else:
            print >>f, 'error: no section with type %#x were found' % (
                    section_type)

    def dump_program_headers_with_type(self, type,
                                       f=sys.stdout):
        type_enum = ProgramHeaderType(type)
        print >>f, 'Dumping section with type %s:' % (type_enum)
        p_type = type_enum.get_enum_value()
        program_headers = self.get_program_headers()
        if program_headers:
            for ph in program_headers:
                if ph.p_type == p_type:
                    ph.dump(flat=False, f=f)
                    print >>f, ''
                    contents = ph.get_contents()
                    if contents:
                        if p_type == PT_NOTE:
                            notes = Note.extract_notes(
                                    ph.get_contents_as_extractor())
                            for note in notes:
                                note.dump(f=f)
                        else:
                            file_extract.dump_memory(ph.p_vaddr, contents,
                                                     options.num_per_line, f)
        else:
            print >>f, 'error: no program headers with type %#x were found' % (
                type)

    def dump(self, options, f=sys.stdout):
        if self.is_valid():
            if options.dump_header:
                self.header.dump(f)
                if options.dump_program_headers:
                    print >>f, ''
            if options.dump_program_headers:
                program_headers = self.get_program_headers()
                for program_header in program_headers:
                    program_header.dump(flat=True, f=f)
                    print >>f, ''
                print >>f, ''
            if options.dump_section_headers:
                sections = self.get_section_headers()
                for section in sections:
                    section.dump(flat=True, f=f)
                    print >>f, ''
                print >>f, ''
            if options.dump_symtab:
                symbols = self.get_symtab()
                if symbols:
                    f.write("Symbol table:\n")
                    Symbol.dump_header(f=f)
                    for (idx, symbol) in enumerate(symbols):
                        symbol.dump(flat=True, f=f)
                        print >>f, ''
                    print >>f, ''
                else:
                    f.write("error: ELF file doesn't contain a SHT_SYMTAB "
                            "section\n")
            if options.dump_dynsym:
                symbols = self.get_dynsym()
                if symbols:
                    f.write("Dynamic symbol table:\n")
                    Symbol.dump_header(f=f)
                    for (idx, symbol) in enumerate(symbols):
                        symbol.dump(flat=True, f=f)
                        print >>f, ''
                    print >>f, ''
                else:
                    f.write("error: ELF file doesn't contain a SHT_DYNSYM "
                            "section\n")
            if options.section_names:
                print >>f, ''
                for section_name in options.section_names:
                    sections = self.get_sections_by_name(section_name)
                    if sections:
                        for section in sections:
                            contents = section.get_contents()
                            if contents:
                                print >>f, 'Dumping "%s" section contents:' % (
                                        section_name)
                                file_extract.dump_memory(section.sh_addr,
                                                         contents,
                                                         options.num_per_line,
                                                         f)
                    else:
                        print >>f, 'error: no sections named %s were found' % (
                                section_name)
            if options.section_types:
                print >>f, ''
                for section_type in options.section_types:
                    self.dump_section_headers_with_type(section_type)
            if options.dump_notes:
                print >>f, ''
                if len(self.get_section_headers()):
                    self.dump_section_headers_with_type(SHT_NOTE)
                else:
                    self.dump_program_headers_with_type(PT_NOTE)
            if options.dump_dynamic:
                dynamic_entries = self.get_dynamic()
                for dynamic_entry in dynamic_entries:
                    dynamic_entry.dump(elf=self, f=f)
            if options.undefined:
                symbols = self.get_symbols()
                if symbols:
                    undefined_symbols = {}
                    f.write('Undefined symbols:\n')
                    if options.verbose:
                        Symbol.dump_header(f=f)
                    for (idx, symbol) in enumerate(symbols):
                        if (symbol.st_shndx == SHN_UNDEF and
                                symbol.get_binding() == STB_GLOBAL):
                            if options.verbose:
                                symbol.dump(flat=True, f=f)
                                print >>f, ''
                            else:
                                symbol_name = symbol.name
                                if symbol_name not in undefined_symbols:
                                    undefined_symbols[symbol_name] = symbol
                    symbol_names = undefined_symbols.keys()
                    if symbol_names:
                        symbol_names.sort()
                        for symbol_name in symbol_names:
                            f.write(symbol_name)
                            symbol = undefined_symbols[symbol_name]
                            if symbol.get_binding() == STB_WEAK:
                                f.write(' (weak)')
                            f.write('\n')
                        print >>f, ''
                    else:
                        print >>f, 'no undefined symbols'
            if options.api:
                api_dict = self.get_api_info()
                print json.dumps(api_dict, indent=2, ensure_ascii=False)
            dwarf.handle_dwarf_options(options, self, f)

    def get_api_info(self):
        symbols = self.get_symbols()
        api_info = dict()
        api_info['path'] = self.path
        api_info['dependencies'] = list()
        dynamic_entries = self.get_dynamic()
        for dyn in dynamic_entries:
            if dyn.d_tag.get_enum_value() == DT_NEEDED:
                api_info['dependencies'].append(
                        self.dynstr.get_string(dyn.d_val))

        if symbols:
            undef_map = {}
            export_map = {}
            for (idx, symbol) in enumerate(symbols):
                if symbol.get_binding() != STB_GLOBAL:
                    continue
                if symbol.st_shndx == SHN_UNDEF:
                    if symbol.name not in undef_map:
                        undef_map[symbol.name] = symbol
                if symbol.st_shndx > 0 and symbol.st_shndx < SHN_LORESERVE:
                    if symbol.name not in export_map:
                        export_map[symbol.name] = symbol
            undef_names = undef_map.keys()
            if undef_names:
                undef_names.sort()
            api_info['imports'] = undef_names
            export_names = export_map.keys()
            if export_names:
                export_names.sort()
            api_info['exports'] = export_names
        return api_info


def handle_elf(options, path):
    elf = File(path)
    if elf.is_valid():
        if options.links_against:
            dynamic_entries = elf.get_dynamic()
            for dyn in dynamic_entries:
                if dyn.d_tag.get_enum_value() == DT_NEEDED:
                    shlib__name = elf.dynstr.get_string(dyn.d_val)
                    if shlib__name in options.links_against:
                        print('ELF: %s links against %s ' % (path,
                                                             shlib__name))
                        break
        elif options.hash_lookups:
            print('ELF: %s' % (path))
            for name in options.hash_lookups:
                hash_table = elf.get_hash_table()
                if hash_table:
                    symbol = hash_table.lookup(name)
                    if symbol:
                        print('Found "%s" in hash table of "%s"...' % (name,
                              elf.path))
                        symbol.dump(False)
        else:
            if not options.api:
                print('ELF: %s' % (path))
            elf.dump(options=options)
    else:
        print 'error: %s is not a valid ELF file' % (path)


def user_specified_options(options):
    '''Return true if the user specified any options, false otherwise.'''
    if options.dump_symtab or options.dump_dynsym:
        return True
    if options.dump_program_headers:
        return True
    if options.dump_section_headers:
        return True
    if options.dump_dynamic:
        return True
    if options.dump_program_headers:
        return True
    if options.dump_header:
        return True
    if options.dump_notes:
        return True
    if options.section_names:
        return True
    if options.section_types:
        return True
    if options.undefined:
        return True
    if options.api:
        return True
    if len(options.links_against) > 0:
        return True
    if dwarf.have_dwarf_options(options):
        return True
    if len(options.hash_lookups) > 0:
        return True
    return False


if __name__ == '__main__':
    parser = optparse.OptionParser(
        description='A script that parses ELF files.')
    parser.add_option(
        '-v', '--verbose',
        action='store_true',
        dest='verbose',
        help='Display verbose debug info',
        default=False)
    parser.add_option(
        '-s', '--symtab',
        action='store_true',
        dest='dump_symtab',
        help='Dump the normal ELF symbol table',
        default=False)
    parser.add_option(
        '-d', '--dynsym',
        action='store_true',
        dest='dump_dynsym',
        help='Dump the dynamic ELF symbol table',
        default=False)
    parser.add_option(
        '-p', '--ph', '--program-headers',
        action='store_true',
        dest='dump_program_headers',
        help='Dump the ELF program headers',
        default=False)
    parser.add_option(
        '-S', '--sh', '--section-headers',
        action='store_true',
        dest='dump_section_headers',
        help='Dump the ELF section headers',
        default=False)
    parser.add_option(
        '-D', '--dynamic',
        action='store_true',
        dest='dump_dynamic',
        help='Dump the ELF Dynamic tags',
        default=False)
    parser.add_option(
        '-H', '--header',
        action='store_true',
        dest='dump_header',
        help='Dump the ELF file header',
        default=False)
    parser.add_option(
        '-n', '--notes',
        action='store_true',
        dest='dump_notes',
        help='Dump any notes in the ELF file program and section headers',
        default=False)
    parser.add_option(
        '-N', '--num-per-line',
        dest='num_per_line',
        metavar='COUNT',
        type='int',
        help='The number of bytes per line when dumping section contents',
        default=32)
    parser.add_option(
        '--undefined',
        action='store_true',
        help=('Display the external API (functions and data) that this ELF '
              'file links against.'),
        default=False)
    parser.add_option(
        '--section',
        type='string',
        metavar='NAME',
        dest='section_names',
        action='append',
        help='Specify one or more section names to dump')
    parser.add_option(
        '--section-type',
        type='string',
        metavar='SH_TYPE',
        dest='section_types',
        action='append',
        help='Specify one or more section types to dump')
    parser.add_option(
        '--api',
        action='store_true',
        dest='api',
        help='Dump the API details as JSON',
        default=False)
    parser.add_option(
        '--links-against',
        type='string',
        metavar='LIBNAME',
        action='append',
        dest='links_against',
        help='Print any ELF file that links against the specified library',
        default=list())
    parser.add_option(
        '--hash',
        type='string',
        action='append',
        metavar='STRING',
        dest='hash_lookups',
        help='Lookup names in the ELF hash tables',
        default=list())

    dwarf.append_dwarf_options(parser)

    (options, files) = parser.parse_args()
    dwarf.enable_colors = options.color
    if not user_specified_options(options):
        options.dump_header = True
        options.dump_program_headers = True
        options.dump_section_headers = True
    if options.verbose:
        print 'options', options
        print 'files', files
    for path in files:
        handle_elf(options, path)
