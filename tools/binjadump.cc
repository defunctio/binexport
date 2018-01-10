#include <cstdio>
#include <memory>
#include <binaryninjaapi.h>
#include <iostream>
#include <binaryninja/binja_export.h>
#include <filesystem_util.h>

int main(int argc, char* argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s BNDB\n", Basename(argv[0]).c_str());
    return EXIT_FAILURE;
  }

  std::string filename(argv[1]);

  if (!FileExists(filename)) {
    perror("could not open file");
    return EXIT_FAILURE;
  }

  auto x = new BinjaExport(filename);
  if(!x->ExportProtobuf(filename + ".BinExport"))
    return EXIT_FAILURE;

  return EXIT_SUCCESS;
}

