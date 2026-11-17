/* Compile twice against unmodified GNU LE and QEMU BE generated ISA modules.
 * This adapter calls the vendor field functions; it contains no encoding masks,
 * opcodes, field shifts, or mkasm-derived mapping tables. The module sources
 * retain their own licenses and are external inputs to the reference build. */
#define xtensa_modules MODULE_SYMBOL
#include XTENSA_MODULES

void FUNCTION_NAME(unsigned word, unsigned *fields, int format) {
  xtensa_insnbuf_word instruction[4] = {word, 0, 0, 0};
#ifdef REFERENCE_DECODE
  fields[0] = Field_op0_Slot_inst_get(instruction);
  fields[1] = Field_t_Slot_inst_get(instruction);
  fields[2] = Field_s_Slot_inst_get(instruction);
  fields[3] = Field_r_Slot_inst_get(instruction);
  fields[4] = Field_op1_Slot_inst_get(instruction);
  fields[5] = Field_op2_Slot_inst_get(instruction);
  fields[6] = Field_imm8_Slot_inst_get(instruction);
  fields[7] = Field_sr_Slot_inst_get(instruction);
  fields[8] = Field_st_Slot_inst_get(instruction);
#else
  instruction[0] = 0;
  Field_op0_Slot_inst_set(instruction, fields[0]);
  if (format == 3) {
    Field_st_Slot_inst_set(instruction, fields[8]);
    Field_r_Slot_inst_set(instruction, fields[3]);
  } else {
    Field_t_Slot_inst_set(instruction, fields[1]);
    if (format == 2) Field_sr_Slot_inst_set(instruction, fields[7]);
    else {
      Field_s_Slot_inst_set(instruction, fields[2]);
      Field_r_Slot_inst_set(instruction, fields[3]);
    }
  }
  if (format == 1) Field_imm8_Slot_inst_set(instruction, fields[6]);
  else {
    Field_op1_Slot_inst_set(instruction, fields[4]);
    Field_op2_Slot_inst_set(instruction, fields[5]);
  }
  fields[9] = instruction[0];
#endif
}
