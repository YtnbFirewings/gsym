//
//  main.cpp
//  bpadtogsym
//
//  Created by Gregory Clayton on 11/7/17.
//  Copyright © 2017 Gregory Clayton. All rights reserved.
//

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include <algorithm>
#include <string>
#include <vector>

#include "FileTableCreator.h"
#include "FunctionInfo.h"
#include "MemoryMappedFile.h"
#include "StringTableCreator.h"
#include "gsym.h"

using namespace gsym;

bool starts_with(const char *line, std::string s) {
  return strncmp(line, s.c_str(), s.size()) == 0;
}

enum BreakpadLineType {
  Invalid,
  Module,
  File,
  Function,
  SourceLine,
  Public,
  Stack
};

static std::string BPAD_MODULE("MODULE ");
static std::string BPAD_FILE("FILE ");
static std::string BPAD_FUNC("FUNC ");
static std::string BPAD_PUBLIC("PUBLIC ");
static std::string BPAD_STACK("STACK ");

class Line
{
  const char *m_start;
  const char *m_end;
  const char *m_pos;
public:
  Line(const char *s, const char *e) : m_start(s), m_end(e), m_pos(s) {}
  
  BreakpadLineType GetLineType() {
    if (m_pos < m_end) {
      switch (m_pos[0]) {
        case 'F':
          if (starts_with(m_pos, BPAD_FUNC)) {
            m_pos += BPAD_FUNC.size();
            return BreakpadLineType::Function;
          }
          if (starts_with(m_pos, BPAD_FILE)) {
            m_pos += BPAD_FILE.size();
            return BreakpadLineType::File;
          }
          break;
        case 'M':
          if (starts_with(m_pos, BPAD_MODULE)) {
            m_pos += BPAD_MODULE.size();
            return BreakpadLineType::Module;
          }
          break;
        case 'P':
          if (starts_with(m_pos, BPAD_PUBLIC)) {
            m_pos += BPAD_PUBLIC.size();
            return BreakpadLineType::Public;
          }
          break;
        case 'S':
          if (starts_with(m_pos, BPAD_STACK)) {
            m_pos += BPAD_STACK.size();
            return BreakpadLineType::Stack;
          }
          break;
        default:
          if (isxdigit(m_pos[0]))
            return BreakpadLineType::SourceLine;
          break;
      }
    }
    return BreakpadLineType::Invalid;
  }
  std::string GetRestOfLineAsString() {
    if (m_pos < m_end - 1)
      return std::string(m_pos, m_end - 1- m_pos);
    return std::string();
  }
  uint32_t GetHex32() {
    auto u = GetUnsigned(16);
    assert(u<UINT32_MAX);
    return (uint32_t)u;
  }
  uint64_t GetHex() {
    return GetUnsigned(16);
  }
  uint64_t GetDecimal() {
    return GetUnsigned(10);
  }
  uint32_t GetDecimal32() {
    auto u = GetUnsigned(10);
    assert(u<UINT32_MAX);
    return (uint32_t)u;
  }
  uint64_t GetUnsigned(int base) {
    if (m_pos < m_end) {
      char *end = (char *)m_pos;
      auto value = strtoull(m_pos, &end, base);
      if (value != ULLONG_MAX) {
        m_pos = end;
        while (m_pos < m_end && *m_pos == ' ')
          ++m_pos;
        return value;
      }
    }
    return UINT64_MAX;
  }
};

void usage()
{
  printf(R"(Usage: bpadtogsym <BREAKPAD_FILE> <GSYM_FILE>
         
Converts Google Breakpad files to GSYM files. The Breakpad file is specified
as a path to the Breakpad text file and the output GSYM file is specified as
the path to the output GSYM file.)");
}

int main(int argc, char * const *argv) {
  
  int verify = 0;
  /* options descriptor */
  static struct option longopts[] = {
    { "verify",     no_argument,            &verify,        1 },
  };
  
  int ch;
  while ((ch = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
    switch (ch) {
      case 0:
        break;
      default:
        usage();
        return 1;
    }
  }
  argc -= optind;
  argv += optind;

  if (argc != 2) {
    usage();
    return 1;
  }
  const char *bpad_path = argv[0];
  const char *gsym_path = argv[1];
  MemoryMappedFile bpad_mmap;
  StringTableCreator strtab;
  std::vector<FunctionInfo> func_infos;
  FileTableCreator filetab(strtab);
  FunctionInfo function_info;
  std::string error;
  if (!bpad_mmap.Open(bpad_path, error)) {
    fprintf(stderr, "error: %s\n", error.c_str());
    return 1;
  }
  DataRef bpad_data = bpad_mmap.GetData();
  const char *bpad_start = (const char*)bpad_data.GetStart();
  const char *bpad_end = (const char*)bpad_data.GetEnd();
  std::vector<const char *> line_ends;
  for (const char *p = bpad_start + 1; p < bpad_end; ++p) {
    if (*p == '\n') {
      line_ends.push_back(p + 1);
    }
  }
  if (line_ends.back() != bpad_end)
    line_ends.push_back(bpad_end);
  
  bool got_public = false;
  const char *line_start = bpad_start;
  for (auto line_end: line_ends) {
    Line line(line_start, line_end);
    
    switch (line.GetLineType()) {
      case BreakpadLineType::Invalid:
        break;
      case BreakpadLineType::Module:
        break;
      case BreakpadLineType::File:
        line.GetDecimal(); // Ignore the file index
        filetab.Insert(line.GetRestOfLineAsString());
        break;
      case BreakpadLineType::Function:
        if (function_info.IsValid())
          func_infos.push_back(function_info);
        function_info.addr = line.GetHex();
        function_info.size = line.GetHex32();
        line.GetHex(); // Skip parameter_size
        function_info.name = strtab.Insert(line.GetRestOfLineAsString());
        function_info.lines.clear();
        break;
      case BreakpadLineType::SourceLine: {
          uint64_t addr = line.GetHex();
          line.GetHex32(); // Skip 32 bit size
          uint32_t line_num = line.GetDecimal32();
          uint32_t file_idx = line.GetDecimal32() + 1;
          if (!function_info.lines.empty()) {
            auto &last = function_info.lines.back();
            // Skip multiple line entries in a row that have the same file and line
            if (last.file == file_idx && last.line == line_num)
              break;
          }
          function_info.lines.push_back(LineEntry(addr, file_idx, line_num));
        }
        break;
      case BreakpadLineType::Public: {
          got_public = true;
          uint64_t addr = line.GetHex();
          line.GetHex(); // Skip parameter_size
          uint32_t name = strtab.Insert(line.GetRestOfLineAsString());
          func_infos.push_back(FunctionInfo(addr, 0, name));
        }
        break;
      case BreakpadLineType::Stack:
        break;
    }
    line_start = line_end;
  }
  if (got_public) {
    // We appended public symbol FunctionInfo objects onto the end of our
    // sorted func_infos array and we need to sort it now.
    std::sort(func_infos.begin(), func_infos.end());
  }
  gsym::File::Save(strtab, filetab, func_infos, gsym_path);
  
  if (verify) {
    gsym::File gsym(gsym_path);
    for (const auto &func_info: func_infos) {
      FunctionInfo gsym_func_info;
      if (gsym.GetFunctionInfo(func_info.addr, gsym_func_info)) {
        if (func_info != gsym_func_info) {
          puts("stop here");
        }
      }
    }
  }
  return 0;
}
