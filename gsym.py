#!/usr/bin/env python

# Python imports
import bisect
import commands
import optparse
import os
import shortencpp
import StringIO
import sys

# Local imports
import dwarf
import elf
import file_extract
import mach_o

UINT8_MAX = 255
UINT16_MAX = 65535
UINT32_MAX = 4294967295

def is_string(value):
    return isinstance(value, basestring)


class File(object):
    def __init__(self, arg, strtab=None):
        self.dirname_stroff = None
        self.basename_stroff = None
        if is_string(arg):
            self.dirname = os.path.dirname(arg)
            self.basename = os.path.basename(arg)
        if isinstance(arg, file_extract.FileExtract):
            self.dirname = None
            self.basename = None
            self.decode(arg, strtab)

    def __lt__(self, rhs):
        if self.dirname != rhs.dirname:
            return self.dirname < rhs.dirname
        return self.basename < rhs.basename

    def __eq__(self, rhs):
        return self.dirname == rhs.dirname and self.basename == rhs.basename

    def encode(self, out, strtab):
        out.put_uint32(strtab.get(self.dirname))
        out.put_uint32(strtab.get(self.basename))

    def decode(self, data, strtab):
        self.dirname_stroff = data.get_uint32()
        self.basename_stroff = data.get_uint32()
        self.dirname = strtab.get(self.dirname_stroff)
        self.basename = strtab.get(self.basename_stroff)

    def get_fullpath(self):
        if self.dirname:
            return os.path.join(self.dirname, self.basename)
        return self.basename

    def dump(self, f=sys.stdout):
        if self.dirname_stroff is not None:
            f.write('%#8.8x %#8.8x ("%s", "%s")\n' % (self.dirname_stroff,
                    self.basename_stroff, self.dirname, self.basename))
        else:
            f.write('dirname = "%s", basename "%s"\n' % (self.dirname,
                                                         self.basename))


class Files(object):
    def __init__(self):
        self.files = list()

    def __getitem__(self, key):
        return self.files[key]

    def insert(self, file):
        index = -1
        try:
            index = self.files.index(file)
        except ValueError:
            pass
        if index == -1:
            index = len(self.files)
            self.files.append(file)
        return index

    def dump(self, f=sys.stdout):
        for (i, file) in enumerate(self.files):
            f.write('[%3u] ' % (i))
            file.dump(f=f)

    def encode(self, out, strtab):
        out.align_to(4)
        out.put_uint32(len(self.files))
        for file in self.files:
            file.encode(out, strtab)

    def decode(self, data, strtab):
        self.files = list()
        data.align_to(4)
        num_files = data.get_uint32()
        for i in range(num_files):
            file = File(data, strtab)
            self.files.append(file)


class LineEntry(object):
    def __init__(self, addr, fullpath, line):
        # If "line" is -1, then this is a termination entry
        self.addr = addr
        self.fullpath = fullpath
        self.line = line

    def dump(self, f=sys.stdout):
        f.write("%#16.16x: %s:%u\n" % (self.addr, self.fullpath, self.line))


DBG_END_SEQUENCE = 0x00
DBG_SET_FILE = 0x01  # Doesn't push a row
DBG_ADVANCE_PC = 0x02  # Pushes a row, so set file and line first
DBG_ADVANCE_LINE = 0x03  # Doesn't push a row
DBG_FIRST_SPECIAL = 0x04  # All special opcodes push a row

DBG_MIN_LINE = -4
DBG_MAX_LINE = 10
DBG_LINE_RANGE = DBG_MAX_LINE - DBG_MIN_LINE + 1
DBG_MAX_ADDR_OFFSET = 16


def decode_special_opcode(opcode):
    adjusted_opcode = opcode - DBG_FIRST_SPECIAL
    line_delta = DBG_MIN_LINE + (adjusted_opcode % DBG_LINE_RANGE)
    addr_delta = (adjusted_opcode / DBG_LINE_RANGE)
    return (line_delta, addr_delta)


def encode_special_opcode(line_delta, addr_delta):
    if line_delta < DBG_MIN_LINE:
        return -1
    if line_delta > DBG_MAX_LINE:
        return -1
    adjusted_opcode = (line_delta - DBG_MIN_LINE) + addr_delta * DBG_LINE_RANGE
    opcode = adjusted_opcode + DBG_FIRST_SPECIAL
    if opcode < 0:
        return -1
    if opcode > 255:
        return -1
    return opcode


class line_codec(object):
    def __init__(self, min=-4, max=10):
        self.min_delta = -4
        self.max_delta = 10
        if self.min_delta < min:
            self.min_delta = min
        if self.max_delta > max:
            self.max_delta = max
        if self.min_delta > 0:
            self.min_delta = 0
        self.line_range = self.max_delta - self.min_delta + 1

    def set_deltas(self, min, max):
        self.min_delta = min
        self.max_delta = max
        self.line_range = max - min + 1

    def decode_special(self, opcode):
        adjusted_opcode = opcode - DBG_FIRST_SPECIAL
        line_delta = self.min_delta + (adjusted_opcode % self.line_range)
        addr_delta = (adjusted_opcode / self.line_range)
        return (line_delta, addr_delta)

    def encode_special(self, line_delta, addr_delta):
        if line_delta < self.min_delta:
            return -1
        if line_delta > self.max_delta:
            return -1
        adjusted_opcode = ((line_delta - self.min_delta) +
                           addr_delta * self.line_range)
        opcode = adjusted_opcode + DBG_FIRST_SPECIAL
        if opcode < 0:
            return -1
        if opcode > 255:
            return -1
        return opcode

class InlineInfo(object):
    def __init__(self, die, depth):
        self.name = None
        self.call_file = None
        self.call_line = 0
        self.ranges = None
        self.children = list()
        self.die = die
        tag = die.get_tag()
        if tag == dwarf.DW_TAG_inlined_subroutine:
            call_file_idx = die.get_attribute_value_as_integer(dwarf.DW_AT_call_file)
            self.name = die.get_mangled_name()
            if self.name is None:
                self.name = die.get_name()
            self.call_file = die.cu.get_file(call_file_idx)
            self.call_line = die.get_attribute_value_as_integer(dwarf.DW_AT_call_line)
            self.ranges = die.get_die_ranges()
        elif tag == dwarf.DW_TAG_lexical_block:
            self.ranges = die.get_die_ranges()
        elif depth == 0 and tag == dwarf.DW_TAG_subprogram:
            self.name = die.get_mangled_name()
            if self.name is None:
                self.name = die.get_name()
            self.ranges = die.get_die_ranges()
        if self.ranges is not None:
            for child_die in die.get_children():
                child_inline_info = InlineInfo(child_die, depth+1)
                if child_inline_info.is_valid():
                    self.children.append(child_inline_info)

    def is_valid(self):
        return self.ranges is not None

    def contains_inline_info(self):
        if self.call_file and self.call_line > 0 and self.name:
            return True
        for child in self.children:
            if child.contains_inline_info():
                return True
        return False

    def dump(self, f=sys.stdout, depth=0):
        if depth > 0:
            f.write(' ' *  depth)
        if self.ranges:
            self.ranges.dump(f=f)
        f.write(' die=%#8.8x' % self.die.get_offset())
        if self.name:
            f.write(' name="%s"' % self.name)
        if self.call_file is not None:
            f.write(' call_file="%s"' % self.call_file)
        if self.call_line:
            f.write(' call_line="%s"' % self.call_line)
        f.write('\n')
        for child in self.children:
            child.dump(f=f, depth=depth+1)

class AddrInfo(object):
    EndOfList = 0
    LineTable = 1
    UnwindInfo = 2
    InlineInfo = 3

    def __init__(self, context=None):
        self.lines = list()
        if context is None:
            self.name = None
            self.range = dwarf.AddressRange(0, 0)
        elif isinstance(context, dwarf.DIERanges.Range):
            self.name = context.die.get_display_name()
            self.range = dwarf.AddressRange(context.lo, context.hi)
            cu = context.die.cu
            line_table = cu.get_line_table()
            rows = line_table.get_rows_for_range(self.range)
            prev = None
            for (i, row) in enumerate(rows):
                # Strip out multiple line table entries with the same file and
                # line. They differ by the column which we don't store so we
                # can remove these sequential entries.
                if prev and prev.file == row.file and prev.line == row.line:
                    continue
                self.lines.append(LineEntry(row.range.lo,
                                            cu.get_file(row.file), row.line))
                prev = row

            # Drop the last line entry if it matches the end of the function.
            if len(self.lines) > 1:
                if self.lines[-1].addr == context.hi:
                    self.lines.pop()
            prev = None
            for curr in self.lines:
                if (prev and curr.fullpath == prev.fullpath and
                        curr.line == prev.line):
                    print 'coalesce'
                    prev.dump()
                    curr.dump()
                prev = curr
            # ii = InlineInfo(context.die, 0)
            # if ii.contains_inline_info():
            #     ii.dump()

    def __cmp__(self, other):
        return cmp(self.range, other.range)

    def lookup_line_addr(self, addr):
        '''Very inefficient line entry lookup, just prototyping so performance
        isn't needed yet. A real implementation will do a binary search.'''
        match_line_entry = None
        for line_entry in self.lines:
            if line_entry.addr > addr:
                break
            match_line_entry = line_entry
        return match_line_entry

    def dump(self, f=sys.stdout, dump_lines=True):
        self.range.dump(f=f)
        f.write(' "%s"\n' % (self.name))
        if dump_lines:
            for (i, line_entry) in enumerate(self.lines):
                line_entry.dump(f=f)

    def encode_lines(self, fullpath_to_index, debug, data, min, max):
        all_special = True
        curr_file_num = 1
        prev_addr = self.range.lo
        prev_line = self.lines[0].line
        line_encoder = line_codec()
        line_encoder.set_deltas(min, max)
        # Write out the min and max line delta as signed LEB128
        data.put_sleb128(line_encoder.min_delta)
        data.put_sleb128(line_encoder.max_delta)

        # Write out the starting line number as a unsigned LEB128
        data.put_uleb128(self.lines[0].line)

        for line_entry in self.lines:
            addr_delta = line_entry.addr - prev_addr
            line_delta = line_entry.line - prev_line
            if addr_delta < 0:
                raise ValueError('addr_delta = %i must be positive' % (
                                 addr_delta))

            # Make a 1 based file index into the files array
            file_num = fullpath_to_index[line_entry.fullpath]+1

            # Set the file if it doesn't match the current one.
            if file_num != curr_file_num:
                data.put_uint8(DBG_SET_FILE)
                data.put_uleb128(file_num)
                curr_file_num = file_num
                if debug:
                    print('%#8.8x: DBG_SET_FILE(%u)' % (data.tell(), file_num))

            special_op = line_encoder.encode_special(line_delta, addr_delta)
            if special_op == -1:
                all_special = False
                # We can't encode the address delta and line delta into
                # a single special opcode, we must do them separately

                # Advance the line
                if line_delta != 0:
                    if debug:
                        print('%#8.8x: DBG_ADVANCE_LINE(%i)' % (
                              data.tell(), line_delta))
                    data.put_uint8(DBG_ADVANCE_LINE)
                    data.put_sleb128(line_delta)

                # Advance the PC and push a row
                if debug:
                    print('%#8.8x: DBG_ADVANCE_PC(%u)' % (data.tell(),
                                                          addr_delta))
                data.put_uint8(DBG_ADVANCE_PC)
                data.put_uleb128(addr_delta)
            else:
                # Advance the PC and line and push a row
                if debug:
                    print('%#8.8x: DBG_SPECIAL(%#2.2x) line += %i, '
                          'addr += %i' % (data.tell(), special_op, line_delta,
                                          addr_delta))
                data.put_uint8(special_op)

            prev_addr = line_entry.addr
            prev_line = line_entry.line
        if debug:
            print('%#8.8x: DBG_END_SEQUENCE\n' % (data.tell()))
        data.put_uint8(DBG_END_SEQUENCE)
        return all_special

    def encode(self, data, strtab, fullpath_to_index):
        # self.dump()
        debug = False
        num_lines = len(self.lines)
        # Write the 32 bit bytes size of this function or symbol.
        data.put_uint32(self.range.size())
        # Write the 32 bit string table offset for the name of the function
        data.put_uint32(strtab.get(self.name))
        # Write the number of line table entries that follow
        data.put_uint32(self.LineTable)
        data_size_offset = data.tell()
        data.put_uint32(0)  # We will fixup this value after writing line table
        if num_lines > 0:
            prev_addr = self.range.lo
            prev_line = 1
            min_line_delta = sys.maxint
            max_line_delta = -sys.maxint - 1
            min_addr_delta = sys.maxint
            max_addr_delta = -sys.maxint - 1
            for (i, line_entry) in enumerate(self.lines):
                addr_delta = line_entry.addr - prev_addr
                line_delta = line_entry.line - prev_line
                # Skip first entry
                if i > 0:
                    if min_line_delta > line_delta:
                        min_line_delta = line_delta
                    if max_line_delta < line_delta:
                        max_line_delta = line_delta
                    if min_addr_delta > addr_delta:
                        min_addr_delta = addr_delta
                    if max_addr_delta < addr_delta:
                        max_addr_delta = addr_delta
                prev_addr = line_entry.addr
                prev_line = line_entry.line
            if min_line_delta == sys.maxint:
                min_line_delta = 0
            if max_line_delta == -sys.maxint - 1:
                max_line_delta = 0

            # print('min_line_delta = %i' % (min_line_delta))
            # print('max_line_delta = %i' % (max_line_delta))
            # print('min_addr_delta = %i' % (min_addr_delta))
            # print('max_addr_delta = %i' % (max_addr_delta))

            curr_data = file_extract.FileEncode(StringIO.StringIO(),
                                                data.byte_order,
                                                data.addr_size)
            min = -4
            max = 10
            all_special = self.encode_lines(fullpath_to_index, debug,
                                            curr_data, min, max)
            best_encoding = (curr_data.file.getvalue(), min, max)
            # print('Initial encoding: %u bytes, min=%i, max=%i' % (
            #       len(best_encoding[0]), min, max))

            # if not all_special:
            #     max_max = 20
            #     min_min = -32
            #     if min_line_delta < min_min:
            #         min_line_delta = min_min
            #     if max_line_delta > max_max:
            #         max_line_delta = max_max
            #     print('adjusted min_line_delta = %i' % (min_line_delta))
            #     print('adjusted max_line_delta = %i' % (max_line_delta))
            #     for min in range(min_line_delta, max_line_delta):
            #         max_max = min + (255 - DBG_FIRST_SPECIAL)
            #         if max_max > max_line_delta:
            #             max_max = max_line_delta
            #         for max in range(max_max, min, -1):
            #             curr_data = file_extract.FileEncode(
            #                 StringIO.StringIO(), data.byte_order,
            #                 data.addr_size)
            #             all_special = self.encode_lines(fullpath_to_index,
            #                                             debug, curr_data, min,
            #                                             max)
            #             curr_bytes = curr_data.file.getvalue()
            #             curr_len = len(curr_bytes)
            #             # print('Encoding is %5u bytes, min=%3i, max=%3i %i' %
            #             #       (curr_len, min, max, all_special))
            #             if len(best_encoding[0]) > curr_len:
            #                 print('New best encoding: %u bytes, min=%i, max=%i'
            #                       % (curr_len, min, max))
            #                 best_encoding = (curr_bytes, min, max)
            #             if all_special:
            #                 break
            #         if all_special:
            #             break
            # print('Best encoding result: %u bytes, min=%i, max=%i' % (
            #     len(best_encoding[0]), best_encoding[1], best_encoding[2]))
            data.file.write(best_encoding[0])
        else:
            # No line entries, just emit an end sequence
            if debug:
                print('%#8.8x: DBG_END_SEQUENCE\n' % (data.tell()))
            data.put_uint8(DBG_END_SEQUENCE)
        line_table_size = data.tell() - data_size_offset
        data.fixup_uint_size(4, line_table_size, data_size_offset)
        data.put_uint32(self.EndOfList)
        data.put_uint32(0)

    def decode(self, addr, data, strtab, files):
        debug = False
        # Read the size in bytes of this function or symbol.
        size = data.get_uint32()
        # Read the name string table index and get the name.
        self.name = strtab.get(data.get_uint32())
        # Compute the lo and hi address from size and "addr" arg.
        self.range.lo = addr
        self.range.hi = addr + size

        while True:
            info_type = data.get_uint32()
            if info_type == self.EndOfList:
                break
            info_len = data.get_uint32()
            if info_type == self.LineTable:
                # Read the min and max line delta
                min_line_delta = data.get_sleb128()
                max_line_delta = data.get_sleb128()
                # Read the starting line number
                line = data.get_uleb128()

                if debug:
                    print('line_encoder.min_delta = %i' % (min_line_delta))
                    print('line_encoder.max_delta = %i' % (max_line_delta))
                    print('start_line = %i' % (line))

                # Create a line decoder from the min and max line delta
                line_decoder = line_codec(min_line_delta, max_line_delta)

                # Read the line entries
                addr = self.range.lo
                file_num = 1
                while True:
                    offset = data.tell()
                    op = data.get_uint8()
                    if op >= DBG_FIRST_SPECIAL:
                        (line_delta, addr_delta) = line_decoder.decode_special(op)
                        line += line_delta
                        addr += addr_delta
                        if debug:
                            print('%#8.8x: DBG_SPECIAL(%#2.2x) line += %i, addr += %i'
                                  % (offset, op, line_delta, addr_delta))
                        file_idx = file_num - 1
                        if file_idx < 0 or file_idx >= len(files.files):
                            raise ValueError('invalid file index %i' % (file_idx))
                        self.lines.append(LineEntry(addr,
                                                    files[file_idx].get_fullpath(),
                                                    line))
                    elif op == DBG_SET_FILE:
                        # Set the current source file with a 1 based file
                        file_num = data.get_uleb128()
                        if debug:
                            print('%#8.8x: DBG_SET_FILE(%u)' % (offset, file_num))
                    elif op == DBG_ADVANCE_PC:
                        # Advance the PC and push a row
                        addr_delta = data.get_uleb128()
                        if debug:
                            print('%#8.8x: DBG_ADVANCE_PC(%u)' % (offset, addr_delta))
                        addr += addr_delta
                        file_idx = file_num - 1
                        if file_idx < 0 or file_idx >= len(files.files):
                            raise ValueError('invalid file index %i' % (file_idx))
                        self.lines.append(LineEntry(addr,
                                                    files[file_num-1].get_fullpath(),
                                                    line))
                    elif op == DBG_ADVANCE_LINE:
                        line_delta = data.get_sleb128()
                        line += line_delta
                        if debug:
                            print('%#8.8x: DBG_ADVANCE_LINE(%u)' % (offset,
                                                                    line_delta))
                    elif op == DBG_END_SEQUENCE:
                        if debug:
                            print('%#8.8x: DBG_END_SEQUENCE\n' % (offset))
                        break


class Symbolicator(object):
    '''A class for a new symboliocation format that uses sections withing object
    files (ELF, Mach-o or COFF) to contain the symbolication data.

    The gsym file format efficiently stores information for addresses within an
    executable or shared library.

    For any questions or modification requests on this file format please
    contact: gclayton@fb.com

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

    The file format is designed to be able to be memory mapped into memory and
    used as is. Each lookup will only expand the expensive address info data on
    demand.

    The data is placed two sections in the object file:
    - main data: the header and addresses, address info offsets, files and
      the actual address info data are all contained in this section. This
      section is named "__gsym" in mach-o and ".gsym" in all other file formats.
      The format of the section is:
      HEADER
        Data layout on disk:
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
      FILES TABLE
        Definitions:
            typedef struct {
                uint32_t directory; // String table offset in the string table
                uint32_t basename;  // String table offset in the string table
            } file_t;
        Data layout on disk:
            .align(sizeof(uint32_t))
            uint32_t num_files;
            file_t files[num_files];
      ADDRESS INFOS
        Each offset in the addr_info_offsets[] array points to one of these.
        The data is designed to carry one or more types of information for
        the address ranges in question. This type of the information block
        is specified by the InfoType enumeration below. Each Information block
        is preceded by the 32 bit InfoType enumeration and followed by a 32
        bit size in bytes of the data for that type. This allows parsers to
        quickly look for the data they care about and skip any data they don't
        want to parse.

        Definitions:
            enum class uint32_t {
                EndOfList = 0,
                LineTable = 1,
                UnwindInfo = 2
            } InfoType;
            typedef struct {
                InfoType type;
                uint32_t length;
                uint8_t data[length];
            } InfoEntry;
        Data layout on disk:
            .align(sizeof(uint32_t))
            uint32_t size;    // Size in bytes of this function or symbol
            uint32_t name;    // String table offset in the string table
            InfoEntry info[]; // Variable size chunks if formatted data
                              // associated with this address. Terminated by
                              // a InfoEntry struct with a type of
                              // InfoType::EndOfList and a length of zero.
                              // Each InfoEntry struct is aligned on a 32 bit
                              // boundary.
    - string table: The symbolication information requires a string table.
      The string table section name is specified in the header. This allows
      the string table to share strings from an existing string table (like
      ".strtab" or ".debug_str") or it can have its own stand alone string
      table.

    ADDRESS LOOKUPS:

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
    '''
    magic_value_native = 0x4753594d   # 'GSYM'
    magic_value_swapped = 0x4d595347  # 'MYSG'
    current_version = 1

    def __init__(self, path, logfile=None):
        self.data = None
        self.strtab = None
        objfile = None
        mach = mach_o.Mach()
        mach.parse(path)
        data = None
        if mach.is_valid():
            arch = mach.get_architecture(0)
            objfile = mach.get_architecture_slice(str(arch))
            if objfile:
                data = objfile.get_section_contents_by_name("__gsym")
        else:
            objfile = elf.File(path)
            if objfile.is_valid():
                data = objfile.get_section_contents_by_name(".gsym")
        if data is None:
            print('error: unsupported file type "%s"', path)
            return
        self.data = data
        self.magic = 0
        self.version = 0
        self.addrs = list()
        self.addr_info_offsets = list()
        self.addr_infos = list()  # Populated on demand
        self.files = Files()
        self.strtab = file_extract.StringTable()
        self.magic = data.get_uint32()
        if self.magic == self.magic_value_swapped:
            data.set_byte_order('swap')
            self.magic = self.magic_value_native
        elif self.magic != self.magic_value_native:
            return
        self.version = data.get_uint16()
        self.addr_offset_size = data.get_uint8()
        data.get_uint8() # skip pad byte
        self.base_addr = data.get_uint64()
        num_addrs = data.get_uint32()
        self.strtab_section_name = data.get_c_string()
        if num_addrs > 0:
            data.align_to(self.addr_offset_size)
            # Get one more than the number of addresses to include the last
            # terminating address.
            for i in range(num_addrs):
                addr_offset = data.get_uint_size(self.addr_offset_size)
                self.addrs.append(self.base_addr + addr_offset)
            # Read the AddrInfo offsets, one for each address except the
            # terminating address.
            data.align_to(4)
            for i in range(num_addrs):
                self.addr_info_offsets.append(data.get_uint32())
                self.addr_infos.append(None)
        if logfile:
            logfile.write('strtab_offset = %#x\n' % (data.tell()))
        self.strtab.decode(objfile.get_section_contents_by_name(self.strtab_section_name))
        if logfile:
            self.strtab.dump(f=logfile)
            logfile.write('files_offset = %#x\n' % (data.tell()))
        self.files.decode(data, self.strtab)
        # If we are logging dump the files and all AddrInfo structs
        if logfile:
            self.files.dump(f=logfile)
            for i in range(num_addrs):
                addr_info = self.get_addr_info(i)
                logfile.write('addr_info[%u] ' % (i))
                addr_info.dump(f=logfile)

    def get_addr_info(self, addr_idx):
        '''Get the AddrInfo for a given address index.'''
        if addr_idx < 0 or addr_idx >= len(self.addr_infos):
            return None
        if self.addr_infos[addr_idx] is None:
            data = self.data
            data.seek(self.addr_info_offsets[addr_idx])
            addr_info = AddrInfo()
            addr_info.decode(self.addrs[addr_idx], data, self.strtab,
                             self.files)
            self.addr_infos[addr_idx] = addr_info
        return self.addr_infos[addr_idx]

    def lookup_addr_index(self, addr):
        '''Lookup the address index for a given address. Returns -1 as the
        address index if the address isn't contained in the addresses in this
        object.'''
        num = len(self.addrs)
        if num == 0:
            return -1
        i = bisect.bisect_left(self.addrs, addr)
        if i == num or self.addrs[i] > addr:
            i -= 1
        if i < num:
            if self.get_addr_info(i).range.contains(addr):
                return i
        return -1

    def lookup_addr_info(self, addr):
        '''Lookup the AddrInfo for a given address. Returns None if "addr" is
        not contined in this addressses in this object.'''
        return self.get_addr_info(self.lookup_addr_index(addr))

    @classmethod
    def save(cls, options, objfile, addr_infos, logfile=None):
        '''Save a symbolicator file to disk using the supplied address info
        structures.'''
        files = Files()
        strtab = file_extract.StringTable()
        fullpath_to_index = dict()

        addr_infos = sorted(addr_infos)

        # Get everything added to the string table in an order that will
        # keep common strings that are accessed close to each other. The
        # function name and its files are placed sequentially.
        for addr_info in addr_infos:
            # Add the function name into the string table
            strtab.insert(addr_info.name)
            for line_entry in addr_info.lines:
                if line_entry.fullpath not in fullpath_to_index:
                    file = File(line_entry.fullpath)
                    index = files.insert(file)
                    fullpath_to_index[line_entry.fullpath] = index
                    # Add the directory and basename to the string table
                    strtab.insert(file.dirname)
                    strtab.insert(file.basename)
        num_addresses = len(addr_infos)
        addr_size = 4
        addr_offset_size = 4
        min_addr = 0
        max_addr = 0
        if num_addresses > 0:
            min_addr = addr_infos[0].range.lo
            max_addr = addr_infos[-1].range.hi
            max_delta = max_addr - min_addr
            if max_delta <= UINT16_MAX:
                addr_offset_size = 2
            elif max_delta <= UINT32_MAX:
                addr_offset_size = 4
            else:
                addr_offset_size = 8
            if max_addr > UINT32_MAX:
                addr_size = 8
        if logfile:
            logfile.write('max range = %s\n' % (dwarf.AddressRange(min_addr, max_addr)))
            logfile.write('addr_size = %u\n' % (addr_size))
            logfile.write('addr_offset_size = %u\n' % (addr_offset_size))
        data_path = options.outfile + ".data"
        strtab_path = options.outfile + ".strtab"
        data_file = open(data_path, 'w')
        strtab_file = open(strtab_path, 'w')
        data = file_extract.FileEncode(data_file, 'native', addr_size)
        strtab_data = file_extract.FileEncode(strtab_file, 'native', addr_size)
        data.put_uint32(cls.magic_value_native)
        data.put_uint16(cls.current_version)
        data.put_uint8(addr_offset_size)
        data.put_uint8(0)  # padding
        end_header_offset = data.tell()
        if logfile:
            logfile.write('header_size = %u\n' % (end_header_offset))
        # ---------------------------------------------------------------------
        # Write out the min addresses first. We will then write out 16, 32 or
        # 64 bit offsets from this address.
        # ---------------------------------------------------------------------
        data.put_uint64(min_addr)

        # Write the number of address offsets that will follow this.
        data.put_uint32(num_addresses)
        # We will use our own string table for now
        file_format = objfile.get_file_type()
        if file_format == "mach-o":
            strtab_sect_name = "__gsym_strtab"
        else:
            strtab_sect_name = ".gsymstrtab"
        data.put_c_string(strtab_sect_name)
        # ---------------------------------------------------------------------
        # Write the addresses as a sorted array of full sized addresses with
        # one extra termination address at the end to terminate the last
        # address info class.
        # ---------------------------------------------------------------------
        if num_addresses:
            data.align_to(addr_offset_size)
            for addr_info in addr_infos:
                addr_offset = addr_info.range.lo - min_addr
                data.put_uint_size(addr_offset_size, addr_offset)
        # ---------------------------------------------------------------------
        # Write out address info offsets, one for each address. We start by
        # writing zero as the offset and we will fix up these offsets later
        # after when we emit the address infos.
        # ---------------------------------------------------------------------
        # Remember the offset of the addr info offsets so we can fixup the
        # offsets later
        data.align_to(4)
        addr_offsets_offset = data.tell()

        if logfile:
            logfile.write('addresses_size = %u\n' % (addr_offsets_offset - end_header_offset))
        # Write the zero offsets to each addr info offset
        for i in range(num_addresses):
            data.put_uint32(0)

        end_addr_offsets_offset = data.tell()
        if logfile:
            logfile.write('addr_info_offsets_size = %u\n' % (end_addr_offsets_offset - addr_offsets_offset))

        # ---------------------------------------------------------------------
        # Write out the string table
        # ---------------------------------------------------------------------
        strtab.encode(strtab_data)

        # ---------------------------------------------------------------------
        # Write out the files
        # ---------------------------------------------------------------------
        if logfile:
            logfile.write('files_offset = %#x\n' % (data.tell()))
        files.encode(data, strtab)

        end_files_offset = data.tell()
        if logfile:
            logfile.write('files_size = %u\n' % (end_files_offset - end_addr_offsets_offset))

        if logfile:
            files.dump(f=logfile)

        addr_offsets = list()
        for (i, addr_info) in enumerate(addr_infos):
            if logfile:
                logfile.write('addr_info[%u] ' % (i))
                addr_info.dump(f=logfile)
            data.align_to(4)
            addr_offsets.append(data.tell())
            addr_info.encode(data, strtab, fullpath_to_index)

        end_addr_infos_offset = data.tell()
        if logfile:
            logfile.write('addr_infos_size = %u\n' % (end_addr_infos_offset - end_files_offset))

        # ---------------------------------------------------------------------
        # Fixup the addr_info_offsets
        # ---------------------------------------------------------------------
        if len(addr_offsets) != num_addresses:
            raise ValueError('address_offsests has incorrect size')
        data.seek(addr_offsets_offset)
        for addr_offset in addr_offsets:
            data.put_uint32(addr_offset)

        data_file.close()
        strtab_file.close()
        if file_format == "mach-o":
            command = 'echo "" | clang -Wl,-r -x c -o "%s"' % (options.outfile)
            command += ' -Wl,-sectcreate,__GSYM,__gsym,%s' % (data_path)
            command += ' -Wl,-sectcreate,__GSYM,%s,%s' % (strtab_sect_name, strtab_path)
            command += ' -'
            (status, output) = commands.getstatusoutput(command)
            if status != 0:
                print '%s' % (command)
                if output:
                    print output
                print 'error: %u' % (status)
            else:
                print 'mach-o file created: "%s"' % (options.outfile)
        else:
            data_bytes = open(data_path, 'r').read()
            strtab_bytes = open(strtab_path, 'r').read()
            sect_bytes_dict = { '.gsym' : data_bytes, strtab_sect_name :  strtab_bytes }
            elf.File.create_simple_elf(objfile, options.outfile, sect_bytes_dict)
            print 'ELF file created: "%s"' % (options.outfile)
        os.remove(data_path)
        os.remove(strtab_path)

    def dump(self, f=sys.stdout):
        f.write("Header:\n")
        f.write('  magic            = 0x%8.8x\n' % (self.magic))
        f.write('  version          = 0x%4.4x\n' % (self.version))
        f.write('  addr_offset_size = 0x%2.2x\n' % (self.addr_offset_size))
        f.write('  pad              = 0x%2.2x\n' % (0))
        f.write('  base_address     = %#16.16x\n' % (self.base_addr))
        f.write('  num_addresses    = %#8.8x\n' % (len(self.addrs)))
        f.write('  strtab_sect_name = "%s"\n' % (self.strtab_section_name))
        if self.addr_offset_size == 2:
            addr_offset_format = '0x%4.4x'
        else:
            addr_offset_format = '0x%8.8x'
        f.write("Address offsets:\n")
        for i in range(len(self.addrs)):
            addr = self.addrs[i]
            format = '[%3u] ' + addr_offset_format + ' (%#x)\n'
            f.write(format % (i, addr - self.base_addr, addr))
        f.write("Address info offsets:\n")
        for i in range(len(self.addrs)):
            addr = self.addrs[i]
            f.write('[%3u] 0x%8.8x\n' % (i, self.addr_info_offsets[i]))
        f.write('Files:\n')
        self.files.dump()
        for i in range(len(self.addr_info_offsets)):
            f.write('0x%8.8x: ' % self.addr_info_offsets[i])
            addr_info = self.get_addr_info(i)
            addr_info.dump()


def create_gsym_from_dwarf(path, objfile, dwarf_file, options):
    addr_infos = list()
    for cu in dwarf_file.get_compile_units():
        die_ranges = cu.get_die_ranges()
        for die_range in die_ranges.ranges:
            addr_info = AddrInfo(die_range)
            addr_infos.append(addr_info)
    # Shorten C++ strings by removing default params and restoring typedefs.
    for addr_info in addr_infos:
        addr_info.name = shortencpp.shorten_string(addr_info.name)
    # logfile_a = open('/tmp/a', 'w')
    # logfile_b = open('/tmp/b', 'w')
    # Symbolicator.save(options, addr_infos, logfile_a)
    # Symbolicator(options.outfile, logfile_b)
    Symbolicator.save(options, objfile, addr_infos)


def main():
    parser = optparse.OptionParser(
        description='A script that creates and parsese GSYM files.')
    parser.add_option(
        '-v', '--verbose',
        action='store_true',
        dest='verbose',
        help='display verbose debug info',
        default=False)
    parser.add_option(
        '-d', '--dump',
        action='store_true',
        dest='dump',
        help='dump the GSYM file data',
        default=False)
    parser.add_option(
        '-o', '--out',
        dest='outfile',
        help='The output file to create',
        default="/tmp/gsym")
    parser.add_option(
        '-a', '--address',
        action='append',
        type='int',
        dest='lookup_addresses',
        help='Address to lookup',
        default=[])

    (options, files) = parser.parse_args()

    for path in files:
        if options.dump:
            symbolicator = Symbolicator(path)
            symbolicator.dump()
        elif len(options.lookup_addresses):
            for addr in options.lookup_addresses:
                print 'Looking up %#x...' % (addr)
                symbolicator = Symbolicator(path)
                addr_info = symbolicator.lookup_addr_info(addr)
                if addr_info:
                    addr_info.dump(dump_lines=False)
                    line_entry = addr_info.lookup_line_addr(addr)
                    if line_entry:
                        line_entry.dump()
                    else:
                        print 'no line info'
                else:
                    print 'no function or symbol matched'
        else:
            mach = mach_o.Mach()
            mach.parse(path)
            if mach.is_valid():
                for arch_idx in range(mach.get_num_archs()):
                    arch = mach.get_architecture(arch_idx)
                    skinny = mach.get_architecture_slice(str(arch))
                    if skinny is None:
                        continue
                    print("Parsing debug info in mach-o file: '%s'" % (path))
                    dwarf = skinny.get_dwarf()
                    if dwarf:
                        create_gsym_from_dwarf(path, skinny, dwarf, options)
            else:
                elf_file = elf.File(path)
                if elf_file.is_valid():
                    print("Parsing debug info in ELF file: '%s'" % (path))
                    dwarf = elf_file.get_dwarf()
                    if dwarf:
                        create_gsym_from_dwarf(path, elf_file, dwarf, options)
                else:
                    print('error: unsupported file type "%s"', path)


if __name__ == '__main__':
    main()
