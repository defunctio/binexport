//  MIT License
//
//  Copyright (c) <2018> <NOP Developments LLC> (https://keybase.io/defunct)
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//          of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//          to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//          copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//          The above copyright notice and this permission notice shall be included in all
//          copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//          AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.

#include "binja_export.h"

void export_database(BinaryNinja::BinaryView *view) {
  BinaryNinja::LogInfo("FILENAME: %s", view->GetFile()->GetFilename().c_str());
  auto x = BinjaExport(view);
  x.ExportProtobuf(view->GetFile()->GetFilename().append(".BinExport2"));
}

extern "C"
{
BINARYNINJAPLUGIN bool CorePluginInit() {
  BinaryNinja::PluginCommand::Register("BinjaExport", "Export database to BinExport2.", &export_database);
}
}