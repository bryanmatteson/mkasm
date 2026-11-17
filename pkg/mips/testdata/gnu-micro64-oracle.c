/* GNU binutils 2.44's native microMIPS operand decoder.
   SPDX-License-Identifier: GPL-3.0-or-later
   Select a primary opcode row explicitly so aliases cannot hide operand errors.
   stdin: decimal-row hexadecimal-logical-instruction-word, one per line. */
#include "mips-dis.c"
#include <stdarg.h>

static int styled(void *s, enum disassembler_style style, const char *fmt, ...) {
  (void)style;
  va_list a; va_start(a, fmt); int n = vfprintf(s, fmt, a); va_end(a); return n;
}
static int plain(void *s, const char *fmt, ...) {
  va_list a; va_start(a, fmt); int n = vfprintf(s, fmt, a); va_end(a); return n;
}
int main(void) {
  char names[32][8]; const char *gpr[32];
  for (int i = 0; i < 32; i++) {
    snprintf(names[i], sizeof(names[i]), "$%d", i); gpr[i] = names[i];
  }
  unsigned row, word;
  while (scanf("%u %x", &row, &word) == 2) {
    if (row >= (unsigned)bfd_micromips_num_opcodes) return 2;
    const struct mips_opcode *op = &micromips_opcodes[row];
    if (op->pinfo == INSN_MACRO || (word & op->mask) != op->match) return 3;
    struct disassemble_info info;
    init_disassemble_info(&info, stdout, plain, styled);
    set_default_mips_dis_options(&info);
    mips_isa = ISA_MIPS64;
    mips_gpr_names = gpr; mips_fpr_names = mips_fpr_names_numeric;
    if (!validate_insn_args(op, decode_micromips_operand, word)) return 4;
    printf("%s ", op->name);
    print_insn_args(&info, op, decode_micromips_operand, word, 1, 4);
    putchar('\n');
  }
  return ferror(stdin) ? 5 : 0;
}
