# gsym
Python code that can parse mach-o and ELF files, parse DWARF debug info and generate a new symbolication format.

# Introduction

The gsym.py file contains a class named gsym.Symbolicator that is a
class for a new symbolication format that uses sections within object
files (ELF, Mach-o or COFF) to contain the symbolication data. The gsym file
format efficiently stores information for addresses within an executable or
shared library.

The information is designed to efficiently lookup addresses and provide
function name, source file and source line information for a given address.
To save space many things have been done:
- binary file format
- store the address lookup table as a base address + address offsets where
  the address offsets can be smaller than a full sized 32 or 64 bit
  address. The address offsets will be dynamic stored as uint16_t,
  uint32_t, or uint64_t depending on the max address difference in the file.
  We can look into storing 24 bit offsets in the future if needed but I
  didn't want to have to do any processing to decode 24 bit integers as it
  might affect the address lookup speed.
- compress C++ strings that by removing default parameters for STL code
  and changing names into shorter forms (see shortencpp.py).
- use a string table for all strings that contains uniqued strings. The
  string table can be shared with the current executable or debug info which
  allows this information to be efficiently encoded in existing debug info
  files.
- store file paths by separating the directory and basename. These are
  stored as offsets into the string table. This allows file directories
  to share the same string in the string table. Unlike DWARF, all files are
  stored in one table for all line tables for all funcitons.
- store line tables efficiently using a technique similar to DWARF line
  tables.

## File Format Details
The file format is designed to be able to be memory mapped into memory and
used as is. Each lookup will only expand the expensive address info data on
demand.

The data is placed two sections in the object file. The main section contains
the header, address table, address info offsets, files and the actual address
info data. This section is named "__gsym" in mach-o and ".gsym" in all other
file formats. The symbolication information requires a string table. The string
table section name is specified in the header. This allows the string table to
share strings from an existing string table (like ".strtab" or ".debug_str")
or it can have its own stand alone string table.

### The format of the main section section is:
#### HEADER
Data layout on disk:
```
    uint32_t magic;
    uint16_t version;
    uint8_t  addr_off_size;   // Size of addr_off_t
    uint8_t  pad;
    uint64_t base_address;
    uint32_t num_addrs;
    char strtab_section_name[]; // Name of string table section
    // Addresses are stored as offsets from "base_address" and the
    // addr_off_t size will vary depending on the max address - min
    // address of all functions in this file. This allows us to store
    // address offsets as offsets from the base_address so we don't
    // need to store full sized addresses for each function address.
    // Usually these are uint16_t or uint32_t values.
    .align(addr_off_size)
    addr_off_t addr_offsets[num_addrs];
    // Each address in addr_offsets has a corresponding entry in
    // addr_info_offsets which points to the location of the
    // information for that address like the function name and size,
    // and the address to file and line mappings.
    .align(sizeof(uint32_t))
    uint32_t addr_info_offsets[num_addrs];
```

#### FILES TABLE
Definitions:
```
  typedef struct {
    uint32_t directory; // String table offset in the string table
    uint32_t basename;  // String table offset in the string table
  } file_t;
```
Data layout on disk:
```
  .align(sizeof(uint32_t))
  uint32_t num_files;
  file_t files[num_files];
```

#### ADDRESS INFOS
Each offset in the addr_info_offsets[] array points to one of these.
The data is designed to carry one or more types of information for
the address ranges in question. This type of the information block
is specified by the InfoType enumeration below. Each Information block
is preceded by the 32 bit InfoType enumeration and followed by a 32
bit size in bytes of the data for that type. This allows parsers to
quickly look for the data they care about and skip any data they don't
want to parse.

Definitions:
```
  enum class uint32_t {
    EndOfList = 0,
    LineTable = 1,
    InlineInfo = 2
  } InfoType;
  typedef struct {
    InfoType type;
    uint32_t length;
    uint8_t data[length];
  } InfoEntry;
```
Data layout on disk:
```
  .align(sizeof(uint32_t))
  uint32_t size;    // Size in bytes of this function or symbol
  uint32_t name;    // String table offset in the string table
  InfoEntry info[]; // Variable size chunks if formatted data
                    // associated with this address. Terminated by
                    // a InfoEntry struct with a type of
                    // InfoType::EndOfList and a length of zero.
                    // Each InfoEntry struct is aligned on a 32 bit
                    // boundary.
```                          

#### ADDRESS LOOKUPS

Address lookups involve taking the address passed in, subtracting the
base_address from the header, then looking up the address offset using a
binary search in addr_offsets to find the index of the matching address.
Using this index, grab the offset for the address information from the
addr_info_offsets[index], and then parse the address info for the address.
The address info contains the byte size, so we must ensure that the address
info contians the address before reporting the result. The address info
contains the function name, function size and the line tables entries for
all addresses in the function if there was debug info for the function. If
the function came from the symbol table, there might not be file and line
information available.

The address queries are very efficient as the address search is searching
an array of offsets and we will touch a minimal number of cache lines and
pages when doing address lookups. The address offset index that is found
is then used access the offset of the data and we go straight to the data
that contains the address info.

#### INFOTYPE SPECIFICATIONS

gsym can support an expandable amount of information types. This allows this
file format to be used to store more information in the future for a given
address range. The gsym.py script currently supports generating two types of
data blocks: InfoType::LineTable and InfoType::InlineInfo.

##### InfoType::LineTable

The line table is encoded using a modified version of DWARF line tables.
The line tables are trimmed down to only support address to source file and
source line number. The data is encoded using a header followed by opcodes that
describe a state machine that will create line table rows as it is being parsed.
As line table opcods are parsed, a state machine maintains a state that is
defined by the following structure:
```
typedef struct {
  uint64_t address;
  uint32_t file_idx;
  uint32_t file_line;
} LineTableRow;
```
As the line table opcodes are evaluated they fill in the current LineTableRow
and possibly push one of these structures into an array. The array that results
after parsing all opcodes forms the line table for the address range.

The line table is encoded as an array of LineTableRow objects where the address
is always increasing. The file_idx and file_line can increase or decrease, but
addresses only increase in value.

The following opcodes are defined:

Definitions:
```
DBG_END_SEQUENCE  = 0x00  # End of the line table
DBG_SET_FILE      = 0x01  # Set LineTableRow.file_idx, don't push a row
DBG_ADVANCE_PC    = 0x02  # Increment LineTableRow.address, and push a row
DBG_ADVANCE_LINE  = 0x03  # Set LineTableRow.file_line, don't push a row
DBG_FIRST_SPECIAL = 0x04  # All special opcodes push a row.
```

Some opcodes are followed by arguments and some opcodes will cause a row to be
pushed into the final line table array.

###### DBG_END_SEQUENCE

Argument: none
Pushes row: no
Description: This opcode terminates the current line sequence.

###### DBG_SET_FILE

Argument: uleb128
Pushes row: no
Description: This opcode sets LineTableRow.file_idx in the parse state setting
up the current state for a future opcode that will push a row.

###### DBG_ADVANCE_PC

Argument: uleb128
Pushes row: yes
Description: This opcode increments LineTableRow.address in the parse state by
the unsigned value in the argument. It then pushes the current state onto the
line table array. Clients should set the file and the line before using this
opcode since it does push a row.

###### DBG_ADVANCE_LINE

Argument: sleb128
Pushes row: yes
Description: This opcode increments LineTableRow.file_line in the parse state by
the unsigned value in the argument.

###### DBG_FIRST_SPECIAL - 255

Argument: none
Pushes row: yes
These special arguments contain both a address and line increment. The address
and line increment is calculated using the min and max line range from the line
table header information. This opcode will increment the address and line and
push a row onto the final line table. The LineTableHeader.min_delta and
LineTableHeader.max_delta are used to encode the address and line increment
exactly as DWARF does.

##### Header
The line table data starts with a line table header.

Data layout on disk:
```
typedef struct {
  sleb128 min_delta;
  sleb128 max_delta;
  uleb128 first_line;
} LineTableHeader;
```
##### Parsing

Parsing the line table involves parsing the header and initializing a
LineTableRow structure with appropriate values. The LineTableRow.address is
initialized with the start address of the address info. LineTableRow.file_idx
is initialized with LineTableHeader.first_line. LineTablerow.file_line is
initiazed with 1. After the initialization we are ready to parse the line table
opcodes. As each opcode is parsed current LineTableRow is updated and some
opcodes push a row to generate what becomes the final line table. Once all
opcodes are parsed, we will a complete line table.

##### InfoType::InlineInfo

Inline information encodes all inline function names and address ranges along
with the calling file and calling line information. Encoding this information
allows us to unwind inline call stacks given a single address. Symbolicating a
single address allows us to get N stack frames and allows us to trace the call
back to the original position of the concrete function in the source instead of
only seeing the deepest inline function call.

Inline info is encoded as follows:

```
typedef struct {
  uleb128 addr_offset;
  uleb128 size;
} OffsetRange;

typedef struct {
  uleb128 num_ranges;
  OffsetRange ranges[num_ranges];
  uint8_t has_children;
  uint32_t name; // String index of inline function name
  uleb128 call_file;
  uleb128 call_line;
  InlineInfo children[];
} InlineInfo;
```

###### Encoding

Each inline info struct contains one or more address ranges. All address ranges
are encoded as offsets from the parent. For the top level InlineInfo structs,
the offset is from the function start address. For children of a InlineInfo,
the offset is from the first address in the first range of the parent
InlineInfo. Encoding the address ranges for inline functions as offsets from
the parent base address allows efficient encoding of address ranges using
ULEB128 numbers by keeping these offsets as low as possible. If an InlineInfo
struct has children (InlineInfo.has_children != 0), then children are encoded immediately following the current InlineInfo. The sibling chain is terminated
by a InlineInfo with a "num_ranges" set to zero. This encoding mechanism is
very easy to implement recursively.

## Using gsym.py

The gsym.py script can be used to create, dump and do lookups on gsym files.

To create a gsym file, you specify the path to a mach-o or ELF file that
contains DWARF debug info:

```
% gsym.py -o a.out.gsym a.out
```

To dump the contents of a gsym file:

```
% gsym.py --dump a.out.gsym
```

To lookup an address withing a gsym file:

```
% gsym.py --address 0x1000 a.out.gsym
```
