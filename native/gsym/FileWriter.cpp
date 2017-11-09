//
//  FileWriter.cpp
//  gsym
//

#include "FileWriter.h"
#include "LEB128.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

using namespace gsym;

FileWriter::~FileWriter() {
  Close();
}

int FileWriter::Open(const char *path) {
  Close();
  mode_t mode = 0660;
  m_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (m_fd < 0)
    return errno;
  return 0;
}

void FileWriter::Close() {
  if (m_fd < 0)
    return;
  close(m_fd);
  m_fd = -1;
}

bool FileWriter::WriteSLEB(int64_t value) {
  uint8_t bytes[32];
  auto len = encodeSLEB128(value, bytes);
  assert(len < sizeof(bytes));
  return Write(bytes, len);
}

bool FileWriter::WriteULEB(uint64_t value) {
  uint8_t bytes[32];
  auto len = encodeULEB128(value, bytes);
  assert(len < sizeof(bytes));
  return Write(bytes, len);
}

bool FileWriter::WriteU8(uint8_t u) {
  return Write(&u, sizeof(u));
}

bool FileWriter::WriteU32(uint32_t u) {
  return Write(&u, sizeof(u));
}

bool FileWriter::Fixup32(uint32_t value, off_t offset) {
  const off_t pos = Tell();
  if (pos == -1)
    return false;
  if (Seek(offset) != offset)
    return false;
  if (!WriteU32(value))
    return false;
  return Seek(pos) == pos;
}


bool FileWriter::WriteUnsigned(uint64_t u, size_t n) {
  // NOTE: this only works on little endian machines
  return Write(&u, n);
}
bool FileWriter::Write(const void *src, size_t src_len) {
  if (m_fd < 0)
    return false;
  ssize_t n = 0;
  do {
    n = write(m_fd, src, src_len);
  } while (n == -1 && errno == EINTR);
  assert(n == src_len);
  return n == src_len;
}

off_t FileWriter::Tell() {
  if (m_fd < 0)
    return -1;
  return lseek(m_fd, 0, SEEK_CUR);
}

off_t FileWriter::Seek(off_t pos) {
  if (m_fd < 0)
    return -1;
  return lseek(m_fd, pos, SEEK_SET);
}

bool FileWriter::AlignTo(size_t align) {
  off_t pos = Tell();
  assert(pos != -1);
  if (pos == -1)
    return false;
  off_t aligned_pos = (pos + align - 1) / align * align;
  if (aligned_pos == pos)
    return true;
  const bool success = aligned_pos == Seek(aligned_pos);
  assert(success);
  return success;
}
