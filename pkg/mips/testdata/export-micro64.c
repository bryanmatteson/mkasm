/* Export GNU binutils 2.44's actual microMIPS64 machine rows and operands.
   SPDX-License-Identifier: GPL-3.0-or-later
   Compile against the matching configured GNU source/build headers. */
#include "micromips-opc.c"

static int selected(const struct mips_opcode *p) {
  return p->pinfo != INSN_MACRO &&
    ((p->membership & INSN_ISA_MASK) == I3 || (p->ase & (IVIRT64 | MSA64)));
}
static void operand(const struct mips_operand *o) {
  const char *kind = o->type == OP_INT ? "int" :
    o->type == OP_MSB ? "msb" : o->type == OP_LWM_SWM_LIST ? "register_list" :
    o->type == OP_IMM_INDEX ? "index" :
    o->type == OP_REG || o->type == OP_OPTIONAL_REG ? "reg" : NULL;
  if (!kind) { fprintf(stderr, "unhandled micro64 operand %d\n", o->type); exit(1); }
  printf("{\"kind\":\"%s\",\"size\":%u,\"lsb\":%u", kind, o->size, o->lsb);
  if (o->type == OP_INT) {
    const struct mips_int_operand *i = (const struct mips_int_operand *)o;
    printf(",\"max\":%u,\"bias\":%d,\"shift\":%u", i->max_val, i->bias, i->shift);
  } else if (o->type == OP_MSB) {
    const struct mips_msb_operand *m = (const struct mips_msb_operand *)o;
    printf(",\"bias\":%d,\"add_lsb\":%u,\"opsize\":%u", m->bias, m->add_lsb, m->opsize);
  } else if (o->type == OP_REG || o->type == OP_OPTIONAL_REG) {
    const struct mips_reg_operand *r = (const struct mips_reg_operand *)o;
    const char *bank = r->reg_type == OP_REG_GP ? "gpr" :
      r->reg_type == OP_REG_FP ? "fpr" : r->reg_type == OP_REG_MSA ? "msa" :
      r->reg_type == OP_REG_COPRO ? "copro" : NULL;
    if (!bank) { fprintf(stderr, "unhandled micro64 register bank %d\n", r->reg_type); exit(1); }
    printf(",\"bank\":\"%s\",\"registers\":[", bank);
    for (unsigned n = 0; n < (1u << o->size); n++)
      printf("%s%d", n ? "," : "", mips_decode_reg_operand(r, n));
    printf("]");
  }
  printf("}");
}
int main(void) {
  printf("{\"source\":\"GNU binutils 2.44 opcodes/micromips-opc.c\",\"license\":\"GPL-3.0-or-later\",\"instructions\":[");
  int sep = 0;
  for (int n = 0; n < bfd_micromips_num_opcodes; n++) {
    const struct mips_opcode *p = &micromips_opcodes[n];
    if (!selected(p)) continue;
    printf("%s{\"row\":%d,\"name\":\"%s\",\"args\":\"%s\",\"match\":%lu,\"mask\":%lu,\"virt\":%d,\"msa\":%d",
      sep++ ? "," : "", n, p->name, p->args, p->match, p->mask, !!(p->ase & IVIRT64), !!(p->ase & MSA64));
    printf(",\"read\":[%d,%d,%d,%d],\"write\":[%d,%d],\"read_hi\":%d,\"read_lo\":%d,\"write_hi\":%d,\"write_lo\":%d,\"load\":%d,\"store\":%d,\"operands\":[",
      !!(p->pinfo & INSN_READ_1), !!(p->pinfo & INSN_READ_2), !!(p->pinfo & INSN_READ_3), !!(p->pinfo & INSN_READ_4),
      !!(p->pinfo & INSN_WRITE_1), !!(p->pinfo & INSN_WRITE_2),
      !!(p->pinfo & INSN_READ_HI), !!(p->pinfo & INSN_READ_LO), !!(p->pinfo & INSN_WRITE_HI), !!(p->pinfo & INSN_WRITE_LO),
      !!(p->pinfo & INSN_LOAD_MEMORY), !!(p->pinfo & INSN_STORE_MEMORY));
    int arg = 0;
    for (const char *s = p->args; *s; s++) {
      if (*s == ',' || *s == '(' || *s == ')') continue;
      const struct mips_operand *o = decode_micromips_operand(s);
      if (!o) { fprintf(stderr, "missing operand %s\n", s); return 1; }
      if (arg++) printf(",");
      operand(o);
      if (*s == '+' || *s == 'm') s++;
    }
    printf("]}");
  }
  printf("]}\n");
  return 0;
}
