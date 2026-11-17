/* Export resolved GNU binutils 2.44 MIPS16 descriptors.
   SPDX-License-Identifier: GPL-3.0-or-later
   Uses the retained mips16-opc.c and the matching upstream headers. */
#include "mips16-opc.c"

static const char *kind(enum mips_operand_type t) {
  switch (t) {
  case OP_INT: return "int";
  case OP_MSB: return "msb";
  case OP_REG: return "reg";
  case OP_OPTIONAL_REG: return "optional_reg";
  case OP_PCREL: return "pcrel";
  case OP_REG28: return "gp";
  case OP_PC: return "pc";
  case OP_ENTRY_EXIT_LIST: return "entry_exit";
  case OP_SAVE_RESTORE_LIST: return "save_restore";
  default: fprintf(stderr, "unhandled operand kind %d\n", t); exit(1);
  }
}

static void operand(const struct mips_operand *o) {
  printf("{\"kind\":\"%s\",\"size\":%u,\"lsb\":%u", kind(o->type), o->size, o->lsb);
  if (o->type == OP_INT || o->type == OP_PCREL) {
    const struct mips_int_operand *i = (const struct mips_int_operand *)o;
    printf(",\"max\":%u,\"bias\":%d,\"shift\":%u", i->max_val, i->bias, i->shift);
    if (o->type == OP_PCREL) {
      const struct mips_pcrel_operand *p = (const struct mips_pcrel_operand *)o;
      printf(",\"align\":%u,\"isa\":%u,\"flip_isa\":%u", p->align_log2,p->include_isa_bit,p->flip_isa_bit);
    }
    /* Independent upstream extraction samples for domain-boundary tests. */
    printf(",\"samples\":[");
    unsigned n[4] = {0, 1, (1u<<o->size)/2, (1u<<o->size)-1};
    for (int k=0;k<4;k++) {
      unsigned w=mips_insert_operand(o, 0, n[k]);
      unsigned raw=mips_extract_operand(o,w);
      printf("%s[%u,%d]",k?",":"",raw,mips_decode_int_operand(i,raw));
    }
    printf("]");
  } else if (o->type == OP_REG || o->type == OP_OPTIONAL_REG) {
    const struct mips_reg_operand *r = (const struct mips_reg_operand *)o;
    printf(",\"bank\":\"%s\",\"registers\":[", r->reg_type==OP_REG_GP?"gpr":r->reg_type==OP_REG_COPRO?"copro":"hardware");
    for(unsigned k=0;k<(1u<<o->size);k++) printf("%s%d",k?",":"",mips_decode_reg_operand(r,k));
    printf("]");
  } else if (o->type == OP_MSB) {
    const struct mips_msb_operand *m = (const struct mips_msb_operand *)o;
    printf(",\"bias\":%d,\"add_lsb\":%u,\"opsize\":%u",m->bias,m->add_lsb,m->opsize);
  }
  printf("}");
}

int main(void) {
  printf("{\"source\":\"GNU binutils 2.44 opcodes/mips16-opc.c\",\"license\":\"GPL-3.0-or-later\",\"operands\":{");
  int sep=0;
  for (int c=33;c<127;c++) {
    const struct mips_operand *s=decode_mips16_operand(c,false), *e=decode_mips16_operand(c,true);
    if(!s) continue;
    printf("%s\"%c\":{\"short\":",sep++?",":"",c); operand(s);
    printf(",\"extended\":");operand(e);printf("}");
  }
  printf("},\"instructions\":[");
  sep=0;
  for(int i=0;i<bfd_mips16_num_opcodes;i++) {
    const struct mips_opcode *p=&mips16_opcodes[i];
    if(p->pinfo==INSN_MACRO) continue;
    printf("%s{\"row\":%d,\"name\":\"%s\",\"args\":\"%s\",\"match\":%lu,\"mask\":%lu",sep++?",":"",i,p->name,p->args,p->match,p->mask);
    printf(",\"short_only\":%d,\"alias\":%d,\"delay\":%d,\"branch\":%d,\"conditional\":%d",!!(p->pinfo2&INSN2_SHORT_ONLY),!!(p->pinfo2&INSN2_ALIAS),!!(p->pinfo&INSN_UNCOND_BRANCH_DELAY),!!(p->pinfo2&INSN2_UNCOND_BRANCH),!!(p->pinfo2&INSN2_COND_BRANCH));
    printf(",\"isa\":%lu,\"e2\":%d,\"e2mt\":%d,\"interaptiv\":%d",p->membership&INSN_ISA_MASK,!!(p->ase&ASE_MIPS16E2),!!(p->ase&ASE_MIPS16E2_MT),!!(p->membership&INSN_INTERAPTIV_MR2));
    printf(",\"read\":[%d,%d,%d,%d],\"write\":[%d,%d]",!!(p->pinfo&INSN_READ_1),!!(p->pinfo&INSN_READ_2),!!(p->pinfo&INSN_READ_3),!!(p->pinfo&INSN_READ_4),!!(p->pinfo&INSN_WRITE_1),!!(p->pinfo&INSN_WRITE_2));
    printf(",\"implicit_read\":[%d,%d,%d,%d,%d,%d,%d],\"implicit_write\":[%d,%d,%d,%d,%d]}",!!(p->pinfo&INSN_READ_GPR_24),!!(p->pinfo2&INSN2_READ_SP),!!(p->pinfo2&INSN2_READ_GPR_31),!!(p->pinfo&INSN_READ_HI),!!(p->pinfo&INSN_READ_LO),!!(p->pinfo2&INSN2_READ_PC),!!(p->pinfo2&INSN2_READ_GPR_16),!!(p->pinfo&INSN_WRITE_GPR_24),!!(p->pinfo2&INSN2_WRITE_SP),!!(p->pinfo&INSN_WRITE_GPR_31),!!(p->pinfo&INSN_WRITE_HI),!!(p->pinfo&INSN_WRITE_LO));
  }
  puts("]}");return 0;
}
