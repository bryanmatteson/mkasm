// Exercise installed LLVM's compiled disassembler and code emitter, independently
// of mkasm's imported bit layouts. One request per line: index hex-bytes.
// A decode/re-emit can normalize physical bits; callers must not count that as
// byte parity. In particular, disassembler-only operand bits need not survive.
#include <llvm/ADT/SmallVector.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCCodeEmitter.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCFixup.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCTargetOptions.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/TargetParser/Triple.h>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();
  llvm::Triple triple("amdgcn-amd-amdhsa");
  std::string error;
  const auto *target = llvm::TargetRegistry::lookupTarget(triple, error);
  if (!target) { std::cerr << error; return 2; }
  std::unique_ptr<llvm::MCRegisterInfo> regs(target->createMCRegInfo(triple));
  std::unique_ptr<llvm::MCInstrInfo> info(target->createMCInstrInfo());
  std::unique_ptr<llvm::MCSubtargetInfo> sub(target->createMCSubtargetInfo(triple, argv[1], argv[2]));
  llvm::MCTargetOptions options;
  std::unique_ptr<llvm::MCAsmInfo> asmInfo(target->createMCAsmInfo(*regs, triple, options));
  llvm::MCContext ctx(triple, asmInfo.get(), regs.get(), sub.get());
  std::unique_ptr<llvm::MCDisassembler> decoder(target->createMCDisassembler(*sub, ctx));
  std::unique_ptr<llvm::MCCodeEmitter> emitter(target->createMCCodeEmitter(*info, ctx));
  std::unique_ptr<llvm::MCInstPrinter> printer(target->createMCInstPrinter(triple, 0, *asmInfo, *info, *regs));
  if (!decoder || !emitter || !printer) return 2;
  std::string line;
  while (std::getline(std::cin, line)) {
    std::istringstream request(line);
    unsigned index;
    std::string hex;
    if (!(request >> index >> hex) || hex.size() % 2) return 2;
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.size(); i += 2) {
      unsigned byte;
      std::istringstream pair(hex.substr(i, 2));
      pair >> std::hex >> byte;
      if (!pair || byte > 255) return 2;
      bytes.push_back(byte);
    }
    llvm::MCInst inst;
    uint64_t size = 0;
    const auto status = decoder->getInstruction(inst, size, bytes, 0, llvm::nulls());
    std::cout << index << '\t' << unsigned(status) << '\t' << size;
    if (status != llvm::MCDisassembler::Success) {
      std::cout << "\t-\t-\t-\n";
      continue;
    }
    llvm::SmallVector<char, 32> code;
    llvm::SmallVector<llvm::MCFixup, 4> fixups;
    emitter->encodeInstruction(inst, code, fixups, *sub);
    if (!fixups.empty()) { std::cerr << "unexpected fixups"; return 2; }
    std::string text;
    llvm::raw_string_ostream stream(text);
    printer->printInst(&inst, 0, "", *sub, stream);
    for (char &c : text) if (c == '\t' || c == '\n' || c == '\r') c = ' ';
    std::cout << '\t' << info->getName(inst.getOpcode()).str() << '\t';
    for (const auto c : code)
      std::cout << std::hex << std::setfill('0') << std::setw(2) << unsigned(uint8_t(c));
    std::cout << std::dec << '\t' << text << '\n';
  }
}
