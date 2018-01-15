//  MIT License
//
//  Copyright (c) <2017> <NOP Developments LLC> (https://keybase.io/defunct)
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


#ifndef BINJADIFF_BINJAEXPORT_H
#define BINJADIFF_BINJAEXPORT_H

#include <binaryninjaapi.h>
#include <binaryninjacore.h>
#include <chain_writer.h>
#include <function.h>
#include <x86.h>
#include <capstone.h>
#include <map>
#include <vector>

#include <utility>
#include <expression.h>
#include <entry_point.h>
#include <types.h>
#include <operand.h>
#include <instruction.h>

typedef std::pair <BNStringReference, BinaryNinja::ReferenceSource> RefPair;

class BinjaExport {
 public:
  struct Name {
    Name(std::string name, Expression::Type type)
        : name(std::move(name)), type(type) {}

    bool empty() const {
      return name.empty() || type == Expression::TYPE_INVALID;
    }

    std::string name;
    Expression::Type type;
  };

  enum class MemOpType {
    MEM_TYPE_UNKNOWN,
    MEM_TYPE_DIRECT,
    MEM_TYPE_PHRASE,
    MEM_TYPE_DISP
  };

  BinaryNinja::Ref <BinaryNinja::BinaryView> m_view;
  BinaryNinja::Ref <BinaryNinja::Architecture> m_arch;

  explicit BinjaExport(BinaryNinja::Ref<BinaryNinja::BinaryView> view);

  explicit BinjaExport(const std::string &filename) : BinjaExport(viewFromFilename(filename)) {};

  bool ExportProtobuf(const std::string &filename);

  bool ExportPostgres(const std::string &filename, std::string connection_string);

  bool ExportDump(const std::string &filename);

  std::string GetArchitectureName();

  std::string GetModuleName();

  std::string GetFileName();

  int GetArchitectureBitness();

  void ExportDatabase(ChainWriter &writer);

  void AnalyzeFlowBN(EntryPoints *entryPoints, std::map <Address, std::string> *modules, ChainWriter *writer,
                     Instructions *instructions, FlowGraph *flowGraph, CallGraph *callGraph);

  int GetSegmentPermissions(const BinaryNinja::Segment &segment);

  Instruction ParseInstruction(Address address, BinaryNinja::Ref <BinaryNinja::BasicBlock> basicBlock,
                               CallGraph *callGraph, FlowGraph *flowGraph);

  const Operands ParseOperandsX86(Address address, const BinaryNinja::Ref <BinaryNinja::BasicBlock> block,
                                  const BinaryNinja::Ref <BinaryNinja::LowLevelILFunction> func, CallGraph *pCallGraph,
                                  FlowGraph *pFlowGraph);

  const std::string GetSizePrefix(size_t size);

  Name GetName(Address address, bool user_names_only);

  void HandleMemoryExpression(csh handle, cs_x86_op *op, Expressions &expressions, FlowGraph *flowGraph);

  void HandleDisplacementExpression(unsigned long handle, const cs_x86_op *op, Expressions &expressions);

  void HandlePhraseExpression(csh handle, cs_x86_op *op, Expressions expressions, FlowGraph *flowGraph);

  void HandleImmediateExpression(const cs_x86_op *op, Expressions &expressions);

 private:
  const std::map <BNSymbolType, Function::FunctionType> funcTypeMap = {
      {BNSymbolType::ImportedFunctionSymbol, Function::FunctionType::TYPE_THUNK},
      {BNSymbolType::ImportAddressSymbol, Function::FunctionType::TYPE_IMPORTED},
      {BNSymbolType::FunctionSymbol, Function::FunctionType::TYPE_STANDARD}
  };

  BinjaExport::MemOpType MemoryOperandType(cs_x86_op *op);

  std::vector <RefPair> m_strRefs;
  static std::string getPluginDirectory();
  static BinaryNinja::Ref<BinaryNinja::BinaryView> viewFromFilename(const string &filename);
};

#endif //BINJADIFF_BINJAEXPORT_H
