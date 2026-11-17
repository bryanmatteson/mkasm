// Independent bytecode emitter: this uses the ASM implementation shipped in
// OpenJDK, never mkasm's opcode definitions or encoding routines. Each method is
// a framing test; JVM type verification is covered by Fixture.java separately.
import java.io.*;
import java.util.*;
import jdk.internal.org.objectweb.asm.*;

public final class ASMOracle implements Opcodes {
  static String emit(int op, boolean wide, int offset, boolean boundary) {
    ClassWriter c = new ClassWriter(0);
    c.visit(V1_7, ACC_PUBLIC, "Reference", null, "java/lang/Object", null);
    if (op == 19) for (int n = 0; n < 300; n++) c.newUTF8("padding" + n);
    MethodVisitor m = c.visitMethod(ACC_PUBLIC | ACC_STATIC, "sample", "()V", null, null);
    m.visitCode();
    for (int n = 0; n < offset; n++) m.visitInsn(NOP);
    Label here = new Label();
    m.visitLabel(here);
    String operands = "";
    int local = wide ? (boundary ? 65535 : 300) : (boundary ? 255 : 8);
    if (op == BIPUSH || op == SIPUSH) {
      int value = op == BIPUSH ? (boundary ? 127 : -128) : (boundary ? 32767 : -32768);
      m.visitIntInsn(op, value); operands = " " + value;
    } else if (op >= 18 && op <= 20) {
      Object value = op == 20 ? Long.valueOf(0x1122334455667788L) : "reference";
      int index = c.newConst(value);
      m.visitLdcInsn(value); operands = " #" + index;
    } else if ((op >= ILOAD && op <= ALOAD) || (op >= ISTORE && op <= ASTORE) || op == RET) {
      m.visitVarInsn(op, local); operands = " " + local;
    } else if (op == IINC) {
      int value = wide ? (boundary ? 32767 : -32768) : (boundary ? 127 : -128);
      m.visitIincInsn(local, value); operands = " " + local + " " + value;
    } else if ((op >= IFEQ && op <= JSR) || op == IFNULL || op == IFNONNULL || op == 200 || op == 201) {
      m.visitJumpInsn(op, here); operands = " " + offset;
    } else if (op == TABLESWITCH) {
      m.visitTableSwitchInsn(-1, 0, here, here, here);
      operands = " {\"default\":" + offset + ",\"low\":-1,\"targets\":[" + offset + "," + offset + "]}";
    } else if (op == LOOKUPSWITCH) {
      m.visitLookupSwitchInsn(here, new int[]{-7, 11}, new Label[]{here, here});
      operands = " {\"default\":" + offset + ",\"pairs\":[{\"match\":-7,\"target\":" + offset + "},{\"match\":11,\"target\":" + offset + "}]}";
    } else if (op >= GETSTATIC && op <= PUTFIELD) {
      int index = c.newField("Reference", "value", "I");
      m.visitFieldInsn(op, "Reference", "value", "I"); operands = " #" + index;
    } else if (op >= INVOKEVIRTUAL && op <= INVOKEINTERFACE) {
      boolean itf = op == INVOKEINTERFACE;
      String owner = itf ? "java/util/function/IntUnaryOperator" : "Reference";
      String desc = boundary ? "(ID)I" : "(I)I";
      int index = c.newMethod(owner, "apply", desc, itf);
      m.visitMethodInsn(op, owner, "apply", desc, itf);
      operands = " #" + index + (itf ? " " + (boundary ? 4 : 2) : "");
    } else if (op == INVOKEDYNAMIC) {
      Handle bootstrap = new Handle(H_INVOKESTATIC, "Reference", "bootstrap", "()Ljava/lang/invoke/CallSite;", false);
      int index = c.newInvokeDynamic("call", "()I", bootstrap);
      m.visitInvokeDynamicInsn("call", "()I", bootstrap); operands = " #" + index;
    } else if (op == NEW || op == ANEWARRAY || op == CHECKCAST || op == INSTANCEOF) {
      int index = c.newClass("java/lang/Object");
      m.visitTypeInsn(op, "java/lang/Object"); operands = " #" + index;
    } else if (op == NEWARRAY) {
      m.visitIntInsn(op, boundary ? T_BOOLEAN : T_INT); operands = boundary ? " boolean" : " int";
    } else if (op == MULTIANEWARRAY) {
      int index = c.newClass("[[[Ljava/lang/Object;");
      int dims = boundary ? 3 : 2;
      m.visitMultiANewArrayInsn("[[[Ljava/lang/Object;", dims); operands = " #" + index + " " + dims;
    } else {
      m.visitInsn(op);
    }
    m.visitInsn(RETURN);
    m.visitMaxs(64, 65535);
    m.visitEnd(); c.visitEnd();
    return operands + "\t" + Base64.getEncoder().encodeToString(c.toByteArray());
  }
  public static void main(String[] args) throws Exception {
    try (Scanner s = new Scanner(System.in)) {
      while (s.hasNextInt()) {
        int op = s.nextInt(); boolean wide = s.nextInt() != 0;
        int offset = s.nextInt(); boolean boundary = s.nextInt() != 0;
        System.out.println(emit(op, wide, offset, boundary));
      }
    }
  }
}
