/* Independent GNU binutils 2.44 disassembler oracle.
   SPDX-License-Identifier: GPL-3.0-or-later
   Compile against the pinned upstream mips-dis.c, libopcodes and libbfd. */
#include "mips-dis.c"
#include <stdarg.h>

static int styled(void *s, enum disassembler_style style, const char *fmt, ...) {
  (void)style;
  va_list a;va_start(a,fmt);int n=vfprintf(s,fmt,a);va_end(a);return n;
}
static int plain(void *s,const char *fmt,...) {
  va_list a;va_start(a,fmt);int n=vfprintf(s,fmt,a);va_end(a);return n;
}
int main(void) {
  char gpr_text[32][12];const char *gpr[32];
  for(int i=0;i<32;i++) { snprintf(gpr_text[i],sizeof(gpr_text[i]),"$%s",mips_gpr_names_oldabi[i]);gpr[i]=gpr_text[i]; }
  char line[128];
  while(fgets(line,sizeof(line),stdin)) {
    char order[3],hex[17]; unsigned long long address;
    unsigned offset=0,legacy=0;
    if(sscanf(line,"%2s %llx %16s %u %u",order,&address,hex,&offset,&legacy)<3) return 2;
    unsigned char bytes[8]={0};size_t n=strlen(hex)/2;
    for(size_t i=0;i<n;i++) { unsigned x;sscanf(hex+2*i,"%2x",&x);bytes[i]=x; }
    struct disassemble_info info;
    init_disassemble_info(&info,stdout,plain,styled);
    info.buffer=bytes;info.buffer_length=n;info.buffer_vma=address;
    info.endian=order[0]=='l'?BFD_ENDIAN_LITTLE:BFD_ENDIAN_BIG;
    info.arch=bfd_arch_mips;info.mach=bfd_mach_mips16;
    info.read_memory_func=buffer_read_memory;info.print_address_func=generic_print_address;
    set_default_mips_dis_options(&info);
    /* Deliberate source union, like the unfiltered catalog. CPU gating is
       independently tested through assembler options and catalog features. */
    mips_isa=ISA_MIPS64;mips_processor=CPU_INTERAPTIV_MR2;
    mips_ase=legacy?0:ASE_MIPS16E2|ASE_MIPS16E2_MT;
    mips_gpr_names=gpr;mips_fpr_names=mips_fpr_names_numeric;
    int length=print_insn_mips16(address+offset,&info);
    printf("\t%d\n",length);
  }
  return 0;
}
