// Read-only KCOV return-PC mapping through the same libdw API used by MAccConc.
#include <elfutils/libdw.h>
#include <dwarf.h>
#include <fcntl.h>
#include <unistd.h>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

static std::string quoted(const std::string &value) {
  std::ostringstream out;
  out << '"';
  for (unsigned char ch : value) {
    if (ch == '"' || ch == '\\') out << '\\' << ch;
    else if (ch < 0x20) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << unsigned(ch);
    else out << ch;
  }
  out << '"';
  return out.str();
}

static std::string hex_address(uint64_t value) {
  std::ostringstream out;
  out << "0x" << std::hex << value;
  return out.str();
}

static bool lookup(Dwarf *debug, uint64_t ip, std::string &file, int &line,
                   std::string &symbol, std::string &symbol_kind, std::string &error) {
  Dwarf_Die unit;
  if (!dwarf_addrdie(debug, ip, &unit)) { error = "dwarf_addrdie: address has no compilation unit"; return false; }
  Dwarf_Line *location = dwarf_getsrc_die(&unit, ip);
  if (!location) { error = "dwarf_getsrc_die: address has no source location"; return false; }
  const char *path = dwarf_linesrc(location, nullptr, nullptr);
  if (!path || !*path || dwarf_lineno(location, &line) != 0 || line < 0) {
    error = "libdw: source file or line unavailable"; return false;
  }
  file = path;
  Dwarf_Die *scopes = nullptr;
  int count = dwarf_getscopes(&unit, ip, &scopes);
  if (count <= 0) { error = "dwarf_getscopes: function scope unavailable"; return false; }
  for (int i = 0; i < count; ++i) {
    int tag = dwarf_tag(&scopes[i]);
    if (tag != DW_TAG_subprogram && tag != DW_TAG_inlined_subroutine) continue;
    const char *name = dwarf_diename(&scopes[i]);
    if (!name) continue;
    // libdw orders scopes innermost first; do not confuse an inlined source
    // function with the containing ELF symbol printed by terminal tracers.
    if (symbol.empty()) {
      symbol = name;
      symbol_kind = tag == DW_TAG_inlined_subroutine ? "inline" : "subprogram";
    }
  }
  std::free(scopes);
  if (symbol.empty()) { error = "libdw: no named function scope"; return false; }
  return true;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: " << argv[0] << " VMLINUX < raw-kcov-hex-ips.txt\n";
    return 2;
  }
  int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
  if (fd < 0) { perror("open vmlinux"); return 1; }
  Dwarf *debug = dwarf_begin(fd, DWARF_C_READ);
  if (!debug) { std::cerr << "dwarf_begin: " << dwarf_errmsg(-1) << '\n'; close(fd); return 1; }
  size_t index = 0;
  bool failed = false;
  std::string input;
  while (std::getline(std::cin, input)) {
    ++index;
    const auto begin = input.find_first_not_of(" \t\r");
    const auto end = input.find_last_not_of(" \t\r");
    std::string number = begin == std::string::npos ? "" : input.substr(begin, end - begin + 1);
    if (number.starts_with("0x") || number.starts_with("0X")) number.erase(0, 2);
    uint64_t raw = 0;
    auto parsed = std::from_chars(number.data(), number.data() + number.size(), raw, 16);
    std::string file, symbol, symbol_kind, error;
    int line = 0;
    bool valid = !number.empty() && parsed.ec == std::errc() &&
                 parsed.ptr == number.data() + number.size() && raw != 0;
    bool found = valid && lookup(debug, raw - 1, file, line, symbol, symbol_kind, error);
    if (!valid) error = "input must be a nonzero unsigned 64-bit hexadecimal KCOV return PC";
    std::cout << "{\"input_index\":" << index << ",\"found\":" << (found ? "true" : "false")
              << ",\"input\":" << quoted(input)
              << ",\"raw_ip\":" << (valid ? quoted(hex_address(raw)) : "null")
              << ",\"lookup_ip\":" << (valid ? quoted(hex_address(raw - 1)) : "null");
    if (found) {
      std::cout << ",\"file\":" << quoted(file) << ",\"line\":" << line
                << ",\"symbol\":" << quoted(symbol)
                << ",\"symbol_kind\":" << quoted(symbol_kind)
                << ",\"exact_line\":" << (line > 0 ? "true" : "false")
                << ",\"mapping_kind\":" << quoted(line > 0 ? "exact_line" : "function_only");
      if (line == 0) {
        // The producer explicitly emitted a line-zero row. Keep the raw IP
        // and resolved file/scope; never substitute a neighbouring source line.
        std::cout << ",\"explanation\":" << quoted("DWARF line table explicitly specifies line 0; file and function are known, but no exact source line is available");
      }
    } else {
      std::cout << ",\"error\":" << quoted(error);
      std::cerr << "mapping input " << index << " failed: " << error << '\n';
      failed = true;
    }
    std::cout << "}\n";
  }
  if (!index) { std::cerr << "no KCOV IPs supplied\n"; failed = true; }
  if (std::cin.bad()) { std::cerr << "input stream read failed\n"; failed = true; }
  dwarf_end(debug);
  close(fd);
  return failed ? 1 : 0;
}
