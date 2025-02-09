#pragma once

#include <charconv>
// #include <cstdio>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "types.h"

/*
inline void hexdump(const u8* buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    const bool is_last = i + 1 == len;
    const bool needs_newline = (i + 1) % 16 == 0;
    printf("%02x%c", buf[i], (is_last || needs_newline) ? '\n' : ' ');
  }
}
//*/

std::string buf2hex(const std::vector<u8>& buf) {
  std::string str;
  static const char lut[] = "0123456789ABCDEF";
  for (auto& b : buf) {
    char hi = lut[b >> 4];
    char lo = lut[b & 0xf];
    str.push_back(hi);
    str.push_back(lo);
  }
  return str;
}

bool hex2nibble(char c, u8* nibble) {
  if (c >= '0' && c <= '9') {
    *nibble = c - '0';
  } else if (c >= 'a' && c <= 'f') {
    *nibble = 10 + (c - 'a');
  } else if (c >= 'A' && c <= 'F') {
    *nibble = 10 + (c - 'A');
  } else {
    return false;
  }
  return true;
}

bool hex2buf(std::string_view str, std::vector<u8>* buf) {
  *buf = {};
  if (str.size() & 1) {
    return false;
  }
  for (size_t i = 0; i < str.size(); i += 2) {
    u8 h, l;
    if (!hex2nibble(str[i], &h)) {
      return false;
    }
    if (!hex2nibble(str[i + 1], &l)) {
      return false;
    }
    buf->push_back((h << 4) | l);
  }
  return true;
}

std::string string_from_hex(std::string_view hex) {
  std::vector<u8> buf;
  if (!hex2buf(hex, &buf)) {
    return {};
  }
  size_t len = 0;
  for (auto& b : buf) {
    if (!b) {
      break;
    }
    len++;
  }
  return std::string(reinterpret_cast<char*>(buf.data()), len);
}

template <typename T>
std::optional<T> int_from_hex(std::string_view str, size_t offset = 0) {
  T val;
  if (std::from_chars(&str[offset], &str[str.size()], val, 16).ec !=
      std::errc{}) {
    return {};
  }
  return val;
}

void strip_trailing_crlf(std::string* str) {
  while (str->back() == '\n' || str->back() == '\r') {
    str->pop_back();
  }
}

std::vector<std::string> split_string(const std::string& str, char delim) {
  std::istringstream istr(str);
  std::vector<std::string> rv;
  std::string s;
  while (std::getline(istr, s, delim)) {
    rv.push_back(s);
  }
  return rv;
}
