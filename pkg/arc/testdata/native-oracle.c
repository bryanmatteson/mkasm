/* Test-only consumer of GNU libopcodes' public ARC tables. This program calls
   binutils' compiled insertion functions, independently of the Go C-source
   importer. Build against a configured binutils tree; see ../README.md. */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include "opcode/arc.h"

static void emit(unsigned long long v,int n,int big) {
  for (int half = n / 2 - 1; half >= 0; --half) {
    unsigned h = (unsigned)(v >> (half * 16)) & 65535;
    if (big) printf("%02x%02x", h >> 8, h & 255);
    else printf("%02x%02x", h & 255, h >> 8);
  }
}
int main(void) {
 unsigned row,big;while(scanf("%u %u",&row,&big)==2) {
  int choice[4];long long values[16];for(int i=0;i<4;i++)if(scanf("%d",&choice[i])!=1)return 2;for(int i=0;i<16;i++)if(scanf("%lld",&values[i])!=1)return 2;
  const struct arc_opcode *op=&arc_opcodes[row];unsigned long long image=op->opcode;unsigned limm=0;bool haslimm=false;const char *error=NULL;
  for(int i=0;i<16&&op->operands[i];i++) {const struct arc_operand *o=&arc_operands[op->operands[i]];if(values[i]==LLONG_MIN || (o->flags&ARC_OPERAND_DUPLICATE))continue;if(o->flags&ARC_OPERAND_LIMM){limm=values[i];if(o->bits==34)limm=values[i]>>2;haslimm=true;continue;}if(o->insert)image=o->insert(image,values[i],&error);else image|=((unsigned long long)values[i]&((1ULL<<o->bits)-1))<<o->shift;}
  for(int i=0;i<4&&op->flags[i];i++) {const struct arc_flag_class *cl=&arc_flag_classes[op->flags[i]];int c=choice[i];if(c<0)continue;if(cl->flag_class&F_CLASS_OPTIONAL){if(!c)continue;c--;}const struct arc_flag_operand *f=&arc_flag_operands[cl->flags[c]];if(!f->name){fprintf(stderr,"invalid flag row=%u mnemonic=%s class=%d choice=%d\n",row,op->name,i,c);return 3;}if (!strcmp(f->name,"t") || !strcmp(f->name,"nt")) { if(f->bits==1) {long long target=0;for(int j=0;j<16&&op->operands[j];j++)if(arc_operands[op->operands[j]].flags&ARC_OPERAND_PCREL)target=values[j];unsigned p=!strcmp(f->name,"t")?arc_Toperand:arc_NToperand;if(op->insn_class==BBIT0||op->insn_class==BBIT1)p=!strcmp(f->name,"t")?arc_NToperand:arc_Toperand;image=arc_operands[p].insert(image,target,&error);continue;} }
#ifdef ARC_OPCODE_ARC64
  if(cl->insert)image=cl->insert(image,f->code,&error);else
#endif
  image|=(unsigned long long)f->code<<f->shift;}
  emit(image,arc_opcode_len(op),big);if(haslimm)emit(limm,4,big);putchar('\n');
 }
 return 0;
}
