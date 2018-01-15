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

#include "binja_export.h"
#include "bntypes_container.h"
#include <call_graph.h>
#include <flow_graph.h>
#include <type_system.h>
#include <iostream>
#include <libgen.h>
#include <dlfcn.h>
#include <binexport2_writer.h>
#include <filesystem_util.h>
#include <dump_writer.h>
#include <flow_analyzer.h>
#include <timer.h>
#include <cinttypes>
#include <database_writer.h>
#include <hex_codec.h>
#include <stubs/base/logging.h>
#include <absl/strings/str_cat.h>
#include <absl/time/time.h>

BinjaExport::BinjaExport(BinaryNinja::Ref<BinaryNinja::BinaryView> view) : m_view(view) {

  m_view = view;
  m_arch = m_view->GetDefaultArchitecture();
  // Required for at least string refs, maybe others.
  m_view->UpdateAnalysisAndWait();

  for (auto &&str : m_view->GetStrings()) {
    for (auto &&ref : m_view->GetCodeReferences(str.start)) {
      m_strRefs.emplace_back(std::make_pair(str, ref));
    }
  }
}

BinaryNinja::Ref<BinaryNinja::BinaryView> BinjaExport::viewFromFilename(const std::string &filename) {
  // TODO: add support for creating BNDB not just existing

  // Initialize BinaryNinja
  BinaryNinja::SetBundledPluginDirectory(getPluginDirectory());
  BinaryNinja::InitCorePlugins();
  BinaryNinja::InitUserPlugins();

  BinaryNinja::Ref<BinaryNinja::BinaryView> v;

  if (GetFileExtension(filename) != std::string(".bndb"))
    LOG(QFATAL) << "Input file is not a BNDB";
  if (!FileExists(filename))
    LOG(QFATAL) << "File " << filename << " does not exist.";

  LOG(INFO) << "Input file: " << filename;
  auto meta = new BinaryNinja::FileMetadata(filename);
  BinaryNinja::Ref<BinaryNinja::BinaryView> bv = meta->OpenExistingDatabase(filename);

  for (auto &vt : BinaryNinja::BinaryViewType::GetViewTypesForData(bv)) {
    if (vt->GetName() != "Raw") {
      LOG(INFO) << "BinaryViewType<" << vt->GetName() << ">";
      v = bv->GetFile()->GetViewOfType(vt->GetName());
      break;
    }
  }
  v->UpdateAnalysisAndWait();
  return v;
}

/**
 * Get binaryninja plugin path
 * @return
 */
std::string BinjaExport::getPluginDirectory() {
  Dl_info info;
  if (!dladdr((void *) BNGetBundledPluginDirectory, &info))
    return std::__cxx11::string();

  std::stringstream ss;
  ss << dirname((char *) info.dli_fname) << "/plugins/";
  return ss.str();
}

/**
 * Export to PostgreSQL for BinNavi
 * @param filename
 * @param connection_string
 * @return
 */
bool BinjaExport::ExportPostgres(const std::string &filename, const std::string connection_string) {
  ChainWriter writer;
  auto database_writer(std::make_shared<DatabaseWriter>(
      GetModuleName() /* Database */, GetModuleName(), 0 /* Module id */,
      std::string(), std::string(), GetArchitectureName(),
      0, "BinExport" /* Version string */,
      connection_string));
  writer.AddWriter(database_writer);
  ExportDatabase(writer);
}

/**
 * Export to BinExport's DumpWriter (text)
 * @param filename
 * @return
 */
bool BinjaExport::ExportDump(const std::string &filename) {
  std::ofstream file(filename.c_str());
  ChainWriter writer;
  writer.AddWriter(std::make_shared<DumpWriter>(file));
  ExportDatabase(writer);
  return true;

}
/**
 * Export to BinExport's Protobuf format
 * @param filename
 * @return
 */
bool BinjaExport::ExportProtobuf(const std::string &filename) {
  ChainWriter writer;
  // TODO: proper hash calculation (I don't think this is actually enforced)
  std::string hash("FIXMELATER");
  writer.AddWriter(std::make_shared<BinExport2Writer>(
      filename,
      GetModuleName(),
      EncodeHex(hash),
      GetArchitectureName()
  ));
  ExportDatabase(writer);
  return true;
}

int BinjaExport::GetArchitectureBitness() {
  return static_cast<int>(m_view->GetDefaultArchitecture()->GetAddressSize() << 3);
}

std::string BinjaExport::GetArchitectureName() {
  return m_view->GetDefaultArchitecture()->GetName() + "-" + std::to_string(GetArchitectureBitness());
}

std::string BinjaExport::GetModuleName() {
  return Basename(m_view->GetFile()->GetFilename());
}

void BinjaExport::ExportDatabase(ChainWriter &writer) {

  Timer<> timer;
  //Add functions
  EntryPoints entry_points;
  {
    EntryPointAdder entry_point_adder(&entry_points, "function chunks");
    for (const auto &func : m_view->GetAnalysisFunctionList())
      entry_point_adder.Add(func->GetStart(), EntryPoint::Source::FUNCTION_PROLOGUE);
  }

  //TODO: check this later
  //Add imported functions
  std::map<Address, std::string> modules;
  {
    EntryPointAdder entry_point_addr(&entry_points, "calls");
    for (const auto &import : m_view->GetSymbolsOfType(ImportedFunctionSymbol)) {
      modules.insert(std::pair<Address, std::string>(import->GetAddress(), ""));
      entry_point_addr.Add(import->GetAddress(), EntryPoint::Source::CALL_TARGET);
    }
  }

  //TODO: implement module map, this is used for windows imports

  Instructions instructions;
  FlowGraph flowGraph;
  CallGraph callGraph;

  AnalyzeFlowBN(&entry_points, &modules, &writer, &instructions, &flowGraph, &callGraph);

  auto bbs = 0;
  for (auto func: flowGraph.GetFunctions())
    bbs += func.second->GetBasicBlocks().size();


  LOG(INFO) << absl::StrCat(
    GetModuleName(), ": exported ", flowGraph.GetFunctions().size(),
    " functions with ", instructions.size(), " instructions in ",
    absl::FormatDuration(absl::Seconds(timer.elapsed())));

}

/**
 * Analyze program flow
 * Use BinaryNinja's analysis paired with Capstone to construct information necessary for BinExport.
 *
 * @param entryPoints
 * @param modules
 * @param writer
 * @param instructions
 * @param flowGraph
 * @param callGraph
 */
void BinjaExport::AnalyzeFlowBN(EntryPoints *entryPoints, std::map<Address, std::string> *modules, ChainWriter *writer,
                                Instructions *instructions, FlowGraph *flowGraph, CallGraph *callGraph) {

  Timer<> timer;
  AddressReferences addrRefs;

  // Add segments and address space
  AddressSpace addressSpace;
  AddressSpace flags;
  for (const auto &segment : m_view->GetSegments()) {
    const BinaryNinja::DataBuffer &dataBuffer = m_view->ReadBuffer(segment.start, segment.length);
    const auto data = (char *) dataBuffer.GetData();
    std::vector<Byte> bytes(data, data + dataBuffer.GetLength());
    addressSpace.AddMemoryBlock(segment.start, bytes, segment.flags);
    flags.AddMemoryBlock(segment.start,
                         AddressSpace::MemoryBlock(segment.length),
                         GetSegmentPermissions(segment));
  }

  Instruction::SetBitness(GetArchitectureBitness());
  Instruction::SetMemoryFlags(&flags);

  //TODO: lambda?
  auto branches = [](BinaryNinja::InstructionInfo ii) {
    std::vector<std::pair<BNBranchType, u_int64_t>> b;
    if (!ii.branchCount)
      return b;
    for (int i = 0; i < ii.branchCount; i += 1) {
      b.emplace_back(std::make_pair(ii.branchType[i], ii.branchTarget[i]));
    }
    return b;
  };

  auto isKnownFunction = [&entryPoints](Address address) -> bool {
    return std::count(entryPoints->begin(), entryPoints->end(),
                      EntryPoint(address, EntryPoint::Source::CALL_TARGET)) > 0;
  };
  const auto &imports = m_view->GetSymbolsOfType(BNSymbolType::ImportedFunctionSymbol);

  for (const auto &func: m_view->GetAnalysisFunctionList()) {
    // TODO: find xrefs to this function, add them accordingly?
    // Add function to the callgraph
    callGraph->AddFunction(func->GetStart());

    // Add edges from xrefs
    // This is basically walking the callgraph in reverse, creating edges
    for (auto &&reference : m_view->GetCodeReferences(func->GetStart())) {
      // Code reference may not be a control flow instruction,
//            callGraph->AddEdge(reference.addr, func->GetStart());
    }

    BinaryNinja::InstructionInfo info;

    for (const auto &basicBlock : func->GetBasicBlocks()) {
      for (uint64_t instrAddress = basicBlock->GetStart();
           instrAddress < basicBlock->GetEnd(); instrAddress += info.length) {

        const auto &instructionBuffer = m_view->ReadBuffer(instrAddress,
                                                           m_arch->GetMaxInstructionLength());
        m_arch->GetInstructionInfo(static_cast<const uint8_t *>(instructionBuffer.GetData()),
                                   instrAddress,
                                   m_arch->GetMaxInstructionLength(), info);

        // TODO: ParseInstruction should probably be inlined since it's not that large, this way we could also reuse InstructionInfo
        auto &&instr = ParseInstruction(instrAddress, basicBlock, callGraph, flowGraph);
        instr.SetVirtualMemory(&addressSpace); // Backing with VM we should not need to implement GetBytes

        auto isImportFunction = [&imports](Address addr) -> bool {
          auto test = std::count_if(imports.begin(), imports.end(),
                                    [&addr](BinaryNinja::Ref<BinaryNinja::Symbol> symbol) {
                                      return addr == symbol->GetAddress();
                                    });
          return test > 0;
        };

        // Fetch instruction branch list
        std::vector<std::pair<BNBranchType, u_int64_t>> branchList;
        {
          branchList = branches(info);
        }
        // Analyze instruction flow
        // Branching instruction
        if (!branchList.empty()) {
          for (const auto &br: branchList) {
            switch (br.first) {
              case UnconditionalBranch:
                flowGraph->AddEdge(
                    FlowGraphEdge(instrAddress, br.second, FlowGraphEdge::TYPE_UNCONDITIONAL));
                addrRefs.emplace_back(instrAddress, GetSourceExpressionId(instr, br.second),
                                      br.second, TYPE_UNCONDITIONAL);
                break;
              case TrueBranch:
              case FalseBranch:
                flowGraph->AddEdge(FlowGraphEdge(instrAddress, br.second,
                                                 br.first == TrueBranch ? FlowGraphEdge::TYPE_TRUE
                                                                        : FlowGraphEdge::TYPE_FALSE));
                addrRefs.emplace_back(instrAddress, GetSourceExpressionId(instr, br.second),
                                      br.second,
                                      br.first == TrueBranch ? TYPE_TRUE : TYPE_FALSE);
                break;
              case CallDestination:
                // This should be all resolved call destinations including imports
                if (!isKnownFunction(br.second))
                  LOG(WARNING) << "call destination is not a known target";

//                {
//                  auto name = m_view->GetSymbolByAddress(br.second) ? m_view->GetSymbolByAddress(
//                      br.second)->GetFullName() : "";
//                  std::cout << func->GetSymbol()->GetFullName() << " -> "
//                            << (isImportFunction(br.second) ? "[I]" : "") << name << std::endl;
//                }

                instr.SetFlag(FLAG_CALL, true);
                callGraph->AddFunction(br.second);
                callGraph->AddEdge(instrAddress, br.second);
                // This does not yet handle indirect calls that are not imports ex: call [offset*eax*4] / vcall ??
                addrRefs.emplace_back(instrAddress, GetSourceExpressionId(instr, br.second),
                                      br.second,
                                      isKnownFunction(br.second) &&
                                          !isImportFunction(br.second) ? TYPE_CALL_DIRECT
                                                                       : TYPE_CALL_INDIRECT);

                break;
              case FunctionReturn:break;
              case SystemCall:break;
              case IndirectBranch:
                break; // TODO: Handle?
              case UnresolvedBranch:
                // IMPORT THUNKS
                auto result = std::find_if(imports.begin(), imports.end(),
                                           [&](BinaryNinja::Ref<BinaryNinja::Symbol> symbol) {
                                             return instrAddress == symbol->GetAddress();
                                           });
                if (result != imports.end()) {
                  // TODO: Should probably add a data reference to the GOT entry

//                  std::cout << "function THUNK " << (*result)->GetFullName() << std::endl;
                } else {
                  if (basicBlock->HasUndeterminedOutgoingEdges()) {}

                  // switches, indirect jmps
                  for (const BinaryNinja::BasicBlockEdge &edge: basicBlock->GetOutgoingEdges()) {
                    if (edge.type == IndirectBranch) {
                      flowGraph->AddEdge(FlowGraphEdge(instrAddress, edge.target->GetStart(),
                                                       FlowGraphEdge::TYPE_SWITCH));
                      addrRefs.emplace_back(instrAddress,
                                            GetSourceExpressionId(instr, edge.target->GetStart()),
                                            edge.target->GetStart(), TYPE_SWITCH);
                    }
                  }
//                  std::cout << "UnresolvedBranch" << std::endl;
                }
                break;
            }
          }

        } else {
          // Last instruction in a basic block that flows without branching
          if (instrAddress + info.length == basicBlock->GetEnd()) {
            for (auto &&edge : ((BinaryNinja::BasicBlock *) basicBlock)->GetOutgoingEdges()) {
              flowGraph->AddEdge(FlowGraphEdge(instrAddress, edge.target->GetStart(),
                                               FlowGraphEdge::TYPE_UNCONDITIONAL));
              addrRefs.emplace_back(instrAddress, GetSourceExpressionId(instr, edge.target->GetStart()),
                                    edge.target->GetStart(), TYPE_UNCONDITIONAL);
              break;
            }
          }
          // String references
          auto &&r = std::find_if(m_strRefs.begin(), m_strRefs.end(), [&](const RefPair &e) {
            return e.second.addr == instrAddress;
          });

          if (r != m_strRefs.end()) {
            addrRefs.emplace_back(instrAddress, GetSourceExpressionId(instr, (*r).first.start),
                                  (*r).first.start, TYPE_DATA_STRING, (*r).first.length);
            auto &&buf = m_view->ReadBuffer((*r).first.start, (*r).first.length);
            std::string s(static_cast<const char *>(buf.GetData()), buf.GetLength());
            auto &&comments = callGraph->GetComments();
            comments.emplace_back(instrAddress,
                                  instr.GetOperandCount() + 1,
                                  CallGraph::CacheString(std::string(s.c_str(), s.length())),
                                  Comment::REGULAR, true);

//            std::cout << func->GetSymbol()->GetFullName() << "[0x" << std::hex << instrAddress
//                      << "]-0x" << (*r).first.start << " " << s
//                      << std::endl;
          }
          // TODO: data xrefs

          // Comments
          auto &&s = func->GetCommentForAddress(instrAddress);
          if (!s.empty())
            callGraph->GetComments().emplace_back(instrAddress,
                                                  instr.GetOperandCount() + 1,
                                                  CallGraph::CacheString(std::string(s.c_str(), s.length())),
                                                  Comment::REGULAR, true);
        }
        instructions->push_back(instr);
      }

    }
  }

  SortInstructions(instructions);
  std::sort(addrRefs.begin(), addrRefs.end());
  ReconstructFlowGraph(instructions, *flowGraph, callGraph);
  flowGraph->ReconstructFunctions(instructions, callGraph);
//    flowGraph->PruneFlowGraphEdges();

  // mark nops?
  // comments

  // BinExport moves functions from the CallGraph into the FlowGraph, so we must name them after ReconstructFunctions
  for (auto &&function : flowGraph->GetFunctions()) {
    auto sym = m_view->GetSymbolByAddress(function.first);
    if (sym) {
      function.second->SetName(sym->GetFullName(), sym->GetRawName());
      function.second->SetType((*funcTypeMap.find(sym->GetType())).second);
    } // skip autonamed functions ex: sub_XXXXX
  }

  BNTypesContainer types(addressSpace);
  TypeSystem typeSystem(types, addressSpace);
  //TODO: implement BNTypesContainer

  // post process comments
  // ida specific stuff
  writer->Write(*callGraph, *flowGraph, *instructions, addrRefs, &typeSystem, addressSpace);

}

/**
 * Architecture agnostic instruction handling
 * @param address
 * @param basicBlock
 * @param callGraph
 * @param flowGraph
 * @return
 */
Instruction
BinjaExport::ParseInstruction(Address address, const BinaryNinja::Ref<BinaryNinja::BasicBlock> basicBlock,
                              CallGraph *callGraph,
                              FlowGraph *flowGraph) {

  if (address == 0)
    return Instruction(0);

  const auto &instructionBuffer = m_view->ReadBuffer(address, m_arch->GetMaxInstructionLength());

  // This should never happen but...
  BinaryNinja::InstructionInfo ii;
  if (!m_arch->GetInstructionInfo(static_cast<const uint8_t *>(instructionBuffer.GetData()), address,
                                  m_arch->GetMaxInstructionLength(), ii))
    return Instruction(0);

  std::vector<BinaryNinja::InstructionTextToken> tokens;
  size_t len = ii.length;
  m_arch->GetInstructionText(static_cast<const uint8_t *>(instructionBuffer.GetData()), address, len, tokens);
  auto mnemonic = !tokens.empty() ? tokens.begin()->text : std::string("");

  Address nextInstruction = basicBlock->GetEnd() != address + ii.length ? address + ii.length : 0;

  // instruction flags
  // deal with hidden operands? not sure what that means really
  // prefix string instructions ?

  // return instruction

  return Instruction(address, nextInstruction, static_cast<uint16_t>(ii.length), mnemonic,
                     ParseOperandsX86(address, basicBlock, basicBlock->GetFunction()->GetLowLevelIL(), callGraph,
                                      flowGraph));
}

/**
 * Maps BN Segment permissions to BinExport permissions
 * @param segment
 * @return
 */
int BinjaExport::GetSegmentPermissions(const BinaryNinja::Segment &segment) {
  int flags = 0;
  flags |= segment.flags & SegmentReadable ? AddressSpace::kRead : 0;
  flags |= segment.flags & SegmentWritable ? AddressSpace::kWrite : 0;
  flags |= segment.flags & SegmentExecutable ? AddressSpace::kExecute : 0;
  return flags;
}

/**
 * Parse X86/X64 operands
 * @param address
 * @param block
 * @param func
 * @param pCallGraph
 * @param pFlowGraph
 * @return
 */
const Operands BinjaExport::ParseOperandsX86(Address address,
                                             const BinaryNinja::Ref<BinaryNinja::BasicBlock> block,
                                             const BinaryNinja::Ref<BinaryNinja::LowLevelILFunction> func,
                                             CallGraph *pCallGraph,
                                             FlowGraph *pFlowGraph) {
// TODO: finish implementing types/symbols/MEM
  Operands operands;

  const auto &instructionBuffer = m_view->ReadBuffer(address, m_arch->GetMaxInstructionLength());

  csh handle;
  cs_insn *insn;
  if (cs_open(CS_ARCH_X86, m_arch->GetName() == "x86_64" ? CS_MODE_64 : CS_MODE_32, &handle) != CS_ERR_OK)
    throw;
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  size_t count = cs_disasm(handle, static_cast<const uint8_t *>(instructionBuffer.GetData()),
                           instructionBuffer.GetLength(),
                           address, 1, &insn);
  if (count == 1) {
    cs_detail *detail = insn[0].detail;
    for (uint8_t i = 0; i < detail->x86.op_count; ++i) {
      cs_x86_op *op = &(detail->x86.operands[i]);
      Expressions expressions;
      Expression *expression = nullptr;
      switch (op->type) {
        case X86_OP_INVALID:
          LOG(WARNING) << absl::StrCat("Invalid operands for inttruction at ", absl::Hex(insn[0].address, absl::kZeroPad8));
          break;
        case X86_OP_REG:
          expressions.push_back(expression = Expression::Create(expression, GetSizePrefix(op->size), 0,
                                                                Expression::TYPE_SIZEPREFIX, 0));
          expressions.push_back(expression = Expression::Create(expression, cs_reg_name(handle, op->reg), 0,
                                                                Expression::TYPE_REGISTER, 0));
          break;
        case X86_OP_IMM:HandleImmediateExpression(op, expressions);
          break;
        case X86_OP_MEM:
          switch (MemoryOperandType(op)) {
            case MemOpType::MEM_TYPE_DIRECT:HandleMemoryExpression(handle, op, expressions, pFlowGraph);
              break;
            case MemOpType::MEM_TYPE_PHRASE:HandlePhraseExpression(handle, op, expressions, pFlowGraph);
              break;
            case MemOpType::MEM_TYPE_DISP:HandleDisplacementExpression(handle, op, expressions);
              break;
            case MemOpType::MEM_TYPE_UNKNOWN:\
              LOG(WARNING) << absl::StrCat("Unknown memory operand type at ", absl::Hex(insn[0].address, absl::kZeroPad8));
              break;
          }
          break;
        case X86_OP_FP:
          LOG(WARNING) << absl::StrCat("Unhandled FPU operation at ", absl::Hex(insn[0].address, absl::kZeroPad8));
          break;
      }
      operands.push_back(Operand::CreateOperand(expressions));
    }
    cs_free(insn, count);
  } else {
    LOG(ERROR) << absl::StrCat("Error decoding instruction at ", absl::Hex(insn[0].address, absl::kZeroPad8));
    throw;
  }

  operands.shrink_to_fit();
  return operands;
}

void BinjaExport::HandleImmediateExpression(const cs_x86_op *op, Expressions &expressions) {
  Expression *expression = nullptr;
  expressions.push_back(expression = Expression::Create(expression, GetSizePrefix(op->size), 0,
                                                        Expression::TYPE_SIZEPREFIX, 0));
  Name name = GetName(static_cast<Address>(op->imm), true);
  expressions.push_back(expression = Expression::Create(expression, name.name, op->imm,
                                                        name.empty()
                                                        ? Expression::TYPE_IMMEDIATE_INT
                                                        : name.type, 0));
}

void BinjaExport::HandleDisplacementExpression(csh handle, const cs_x86_op *op, Expressions &expressions) {
  int8_t pos = 0;
  Expression *expression = nullptr;
  Expression *reg_expr = nullptr;
  expressions.push_back(
      expression = Expression::Create(expression, GetSizePrefix(op->size), 0, Expression::TYPE_SIZEPREFIX, pos));
  if (op->mem.segment != X86_REG_INVALID) {
    auto &&x = cs_reg_name(handle, op->mem.segment);
//    std::cout << std::string(x) << std::endl;
  }
  if (op->mem.segment != X86_REG_INVALID) {
    std::string x(cs_reg_name(handle, op->mem.segment));
    x += ":";
    expressions.push_back(
        expression = Expression::Create(
            expression, x, 0, Expression::TYPE_OPERATOR, 0));
  }
  expressions.push_back(expression = Expression::Create(expression, "[", 0, Expression::TYPE_DEREFERENCE, pos));
  expressions.push_back(expression = Expression::Create(expression, "+", 0, Expression::TYPE_OPERATOR, pos));
  expressions.push_back(
      reg_expr = Expression::Create(expression, cs_reg_name(handle, op->mem.base), 0, Expression::TYPE_REGISTER,
                                    pos));
  // TODO: lookup symbols types and change expression type accordingly
  // TODO: bindiff does not post process signed values

  if (op->mem.index != X86_REG_INVALID) {
    if (op->mem.scale) {
      Expression *parent = nullptr;
      expressions.push_back(parent = Expression::Create(expression, "*", 0, Expression::TYPE_OPERATOR, ++pos));
      expressions.push_back(
          Expression::Create(parent, cs_reg_name(handle, op->mem.index), 0, Expression::TYPE_REGISTER, 0));
      expressions.push_back(
          Expression::Create(parent, "", 1 << op->mem.scale, Expression::TYPE_IMMEDIATE_INT, 1));
    } else {
      expressions.push_back(Expression::Create(
          expression, cs_reg_name(handle, op->mem.index), 0,
          Expression::TYPE_REGISTER, ++pos));
    }
  }
  expressions.push_back(
      expression = Expression::Create(expression, std::__cxx11::string(), op->mem.disp,
                                      Expression::TYPE_IMMEDIATE_INT,
                                      ++pos));
}

/**
 * Ascii size prefixing used in BinDiff
 * @param size
 * @return
 */
const std::string BinjaExport::GetSizePrefix(const size_t size) {
  return "b" + std::to_string(size);
}

void BinjaExport::HandleMemoryExpression(csh handle, cs_x86_op *op, Expressions &expressions, FlowGraph *flowGraph) {
  Expression *expression = nullptr;
  Name name = GetName(static_cast<Address>(op->mem.disp), false);

  expressions.push_back(
      expression = Expression::Create(
          expression, GetSizePrefix(op->size), 0, Expression::TYPE_SIZEPREFIX, 0));

  // TODO: structure name/type support

  if (op->mem.segment != X86_REG_INVALID) {
    std::string x(cs_reg_name(handle, op->mem.segment));
    x += ":";
    expressions.push_back(
        expression = Expression::Create(
            expression, x, 0, Expression::TYPE_OPERATOR, 0));
  }

  expressions.push_back(
      expression = Expression::Create(
          expression, "[", 0, Expression::Expression::TYPE_DEREFERENCE, 0));

  Expression *parent = expression;

  if (op->mem.scale && op->mem.index != X86_REG_INVALID) {
    if (op->mem.disp || !name.empty()) {
      expressions.push_back(
          parent = Expression::Create(
              expression, "+", 0, Expression::TYPE_OPERATOR, 0));
      expressions.push_back(Expression::Create(parent, name.name, op->mem.disp,
                                               name.empty() ? Expression::TYPE_IMMEDIATE_INT : name.type, 0));
    }
    expressions.push_back(
        parent = Expression::Create(
            parent, "*", 0, Expression::TYPE_OPERATOR, 1));
    expressions.push_back(
        Expression::Create(parent, cs_reg_name(handle, op->mem.index), 0, Expression::TYPE_REGISTER, 0));
    // LSH 1 on scale is invalid result?
    expressions.push_back(Expression::Create(parent, "", op->mem.scale, Expression::TYPE_IMMEDIATE_INT, 1));
  } else {
    expressions.push_back(
        expression = Expression::Create(
            parent, name.name, op->mem.disp, name.empty() ? Expression::TYPE_IMMEDIATE_INT : name.type, 0));

  }

}

BinjaExport::Name BinjaExport::GetName(Address address, bool user_names_only) {
  Expression::Type type = Expression::TYPE_INVALID;
  std::string name;
  auto symbol = m_view->GetSymbolByAddress(address);
  if (symbol) {
    switch (symbol->GetType()) {
      case FunctionSymbol:type = Expression::TYPE_FUNCTION;
        break;
      case ImportAddressSymbol:type = Expression::TYPE_GLOBALVARIABLE;
        break;
      case ImportedFunctionSymbol:type = Expression::TYPE_FUNCTION;
        break;
      case DataSymbol:type = Expression::TYPE_GLOBALVARIABLE;
        break;
      case ImportedDataSymbol:type = Expression::TYPE_GLOBALVARIABLE;
        break;
    }
    name = m_view->GetSymbolByAddress(address)->GetFullName();
  }
  return Name(name, type);
}

BinjaExport::MemOpType BinjaExport::MemoryOperandType(cs_x86_op *op) {
  // convenience lambdas
  auto hasBase = [](cs_x86_op *op) { return op->mem.base != X86_REG_INVALID; };
  auto hasIndex = [](cs_x86_op *op) { return op->mem.index != X86_REG_INVALID; };
  auto hasDisp = [](cs_x86_op *op) { return op->mem.disp != 0; };
  auto hasScale = [](cs_x86_op *op) { return op->mem.scale != 0; };
  auto isPhrase = [&](cs_x86_op *op) { return (hasBase(op) && hasIndex(op) && !hasDisp(op)); };
  auto isDisp = [&](cs_x86_op *op) { return ((hasBase(op) && hasDisp(op))); };
  auto isDirect = [&](cs_x86_op *op) { return (!hasBase(op) && hasDisp(op)); };

  if (isPhrase(op)) {
    return MemOpType::MEM_TYPE_PHRASE;
  } else if (isDisp(op)) {
    return MemOpType::MEM_TYPE_DISP;
  } else if (isDirect(op) || (hasBase(op) && !hasIndex(op) && !hasDisp(op))) {
    return MemOpType::MEM_TYPE_DIRECT;
  } else
    return MemOpType::MEM_TYPE_UNKNOWN;
}

void BinjaExport::HandlePhraseExpression(csh handle, cs_x86_op *op, Expressions expressions, FlowGraph *flowGraph) {
  // TODO: symbol names and type substitution
  //m_view->GetSymbolByAddress()
  Expression *expression = nullptr;
  expressions.push_back(
      expression = Expression::Create(
          expression, GetSizePrefix(op->size), 0, Expression::TYPE_SIZEPREFIX, 0));
  if (op->mem.segment != X86_REG_INVALID) {
    std::string x(cs_reg_name(handle, op->mem.segment));
    x += ":";
    expressions.push_back(
        expression = Expression::Create(
            expression, x, 0, Expression::TYPE_OPERATOR, 0));
  }
  expressions.push_back(
      expression = Expression::Create(
          expression, "[", 0, Expression::TYPE_DEREFERENCE, 0));
  if (op->mem.index != X86_REG_INVALID) {
    expressions.push_back(
        expression = Expression::Create(
            expression, "+", 0, Expression::TYPE_OPERATOR, 0));
  }
  Expression *temp = nullptr;
  expressions.push_back(
      temp = Expression::Create(
          expression, cs_reg_name(handle, op->mem.base), 0, Expression::TYPE_REGISTER, 0));

  // TODO: stack variable names

  if (op->mem.index != X86_REG_INVALID) {
    if (op->mem.scale != 0) {
      Expression *parent = nullptr;
      expressions.push_back(
          parent = Expression::Create(
              expression, "*", 0, Expression::TYPE_OPERATOR, 1));
      expressions.push_back(
          Expression::Create(
              parent, cs_reg_name(handle, op->mem.index), 0, Expression::TYPE_REGISTER, 0));
      expressions.push_back(
          Expression::Create(
              parent, "", 1 << op->mem.scale, Expression::TYPE_IMMEDIATE_INT, 1));
    } else {
      expressions.push_back(
          Expression::Create(expression, cs_reg_name(handle, op->mem.index), 0, Expression::TYPE_REGISTER,
                             1));
    }
  }

}
std::string BinjaExport::GetFileName() { return m_view->GetFile()->GetFilename(); }

