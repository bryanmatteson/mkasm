package jvm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// This class-file reader is deliberately limited to extracting Code attributes
// for independent javac/javap tests; the public backend accepts method bytecode.
type classCursor struct {
	r   *bytes.Reader
	err error
}

func (c *classCursor) u1() byte {
	v, e := c.r.ReadByte()
	if e != nil {
		c.err = e
	}
	return v
}
func (c *classCursor) u2() uint16 {
	var b [2]byte
	_, e := io.ReadFull(c.r, b[:])
	if e != nil {
		c.err = e
	}
	return binary.BigEndian.Uint16(b[:])
}
func (c *classCursor) u4() uint32 {
	var b [4]byte
	_, e := io.ReadFull(c.r, b[:])
	if e != nil {
		c.err = e
	}
	return binary.BigEndian.Uint32(b[:])
}
func (c *classCursor) take(n int) []byte {
	if n < 0 || n > c.r.Len() {
		c.err = io.ErrUnexpectedEOF
		return nil
	}
	b := make([]byte, n)
	_, e := io.ReadFull(c.r, b)
	if e != nil {
		c.err = e
	}
	return b
}

type methodCode struct {
	name string
	code []byte
}

func extractCode(class []byte) ([]methodCode, error) {
	c := &classCursor{r: bytes.NewReader(class)}
	if c.u4() != 0xcafebabe {
		return nil, fmt.Errorf("bad class magic")
	}
	c.u2()
	c.u2()
	count := int(c.u2())
	utf := map[uint16]string{}
	for i := 1; i < count; i++ {
		tag := c.u1()
		switch tag {
		case 1:
			n := int(c.u2())
			utf[uint16(i)] = string(c.take(n))
		case 3, 4:
			c.take(4)
		case 5, 6:
			c.take(8)
			i++
		case 7, 8, 16, 19, 20:
			c.take(2)
		case 9, 10, 11, 12, 17, 18:
			c.take(4)
		case 15:
			c.take(3)
		default:
			return nil, fmt.Errorf("bad pool tag %d", tag)
		}
	}
	c.take(6)
	interfaces := int(c.u2())
	c.take(interfaces * 2)
	fields := int(c.u2())
	for i := 0; i < fields; i++ {
		c.take(6)
		attrs := int(c.u2())
		for j := 0; j < attrs; j++ {
			c.u2()
			n := int(c.u4())
			c.take(n)
		}
	}
	methods := int(c.u2())
	var out []methodCode
	for i := 0; i < methods; i++ {
		c.u2()
		name := utf[c.u2()]
		c.u2()
		attrs := int(c.u2())
		for j := 0; j < attrs; j++ {
			attr := utf[c.u2()]
			n := int(c.u4())
			body := c.take(n)
			if attr == "Code" {
				code := &classCursor{r: bytes.NewReader(body)}
				code.u2()
				code.u2()
				size := int(code.u4())
				data := code.take(size)
				if code.err != nil {
					return nil, code.err
				}
				out = append(out, methodCode{name, data})
			}
		}
	}
	return out, c.err
}
func TestJavacJavapClassWorkflow(t *testing.T) {
	for _, tool := range []string{"javac", "javap", "java"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("JDK unavailable")
		}
	}
	dir := t.TempDir()
	if artifact := os.Getenv("MKASM_JVM_ARTIFACT_DIR"); artifact != "" {
		dir = filepath.Join(artifact, "javac")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	var src strings.Builder
	src.WriteString(`import java.util.function.IntUnaryOperator;
public class Fixture {
 static int dense(int x){switch(x){case -1:return 2;case 0:return 3;case 1:return 5;default:return 7;}}
 static int sparse(int x){switch(x){case -100:return 11;case 1000:return 13;case 100000:return 17;default:return 19;}}
 static String dynamic(int x){return "x="+x;}
 static int[][] arrays(int x){return new int[x][3];}
 static int invoke(IntUnaryOperator op){return op.applyAsInt(5);}
 static int loops(int x){int sum=0;for(int i=0;i<x;i++){sum+=i;}return sum;}
 static int wide(int x){
`)
	for i := 0; i < 270; i++ {
		fmt.Fprintf(&src, " int a%d=x+%d;\n", i, i)
	}
	src.WriteString(" a269+=300; return ")
	for i := 0; i < 270; i++ {
		if i > 0 {
			src.WriteByte('+')
		}
		fmt.Fprintf(&src, "a%d", i)
	}
	src.WriteString("; }\n public static void main(String[] args){if(dense(0)!=3 || sparse(1000)!=13 || !dynamic(9).equals(\"x=9\") || arrays(2)[0].length!=3 || invoke(x->x+1)!=6 || loops(4)!=6 || wide(1)!=36885)throw new AssertionError();}\n}\n")
	if err := os.WriteFile(filepath.Join(dir, "Fixture.java"), []byte(src.String()), 0644); err != nil {
		t.Fatal(err)
	}
	run := func(tool string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(tool, args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", tool, err, out)
		}
		return out
	}
	run("javac", "-g:none", "Fixture.java")
	javap := run("javap", "-c", "-p", "Fixture.class")
	if err := os.WriteFile(filepath.Join(dir, "javap.txt"), javap, 0644); err != nil {
		t.Fatal(err)
	}
	class, err := os.ReadFile(filepath.Join(dir, "Fixture.class"))
	if err != nil {
		t.Fatal(err)
	}
	methods, err := extractCode(class)
	if err != nil {
		t.Fatal(err)
	}
	c := catalog(t)
	seen := map[byte]bool{}
	wideSeen := false
	var expected []string
	for _, method := range methods {
		instructions, err := c.DecodeMethod(method.code)
		if err != nil {
			t.Fatalf("%s: %v", method.name, err)
		}
		roundtrip, err := c.EncodeMethod(instructions)
		if err != nil || !bytes.Equal(roundtrip, method.code) {
			t.Fatalf("%s binary roundtrip %v", method.name, err)
		}
		var textBytes []byte
		for _, in := range instructions {
			seen[in.Opcode] = true
			wideSeen = wideSeen || in.Wide
			name := in.Mnemonic
			if in.Wide {
				name += "_w"
			}
			expected = append(expected, fmt.Sprintf("%d:%s", in.Offset, name))
			b, err := c.Assemble(in.Format(), in.Offset)
			if err != nil {
				t.Fatalf("%s %s: %v", method.name, in.Format(), err)
			}
			textBytes = append(textBytes, b...)
		}
		if !bytes.Equal(textBytes, method.code) {
			t.Fatalf("%s text roundtrip changed code", method.name)
		}
		if err := os.WriteFile(filepath.Join(dir, method.name+".code"), method.code, 0644); err != nil {
			t.Fatal(err)
		}
	}
	matches := regexp.MustCompile(`(?m)^\s*([0-9]+):\s+([a-z][a-z0-9_]*)`).FindAllSubmatch(javap, -1)
	var actual []string
	for _, m := range matches {
		n, _ := strconv.Atoi(string(m[1]))
		actual = append(actual, fmt.Sprintf("%d:%s", n, m[2]))
	}
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("javap opcode offsets differ\nactual:%v\nexpected:%v", actual, expected)
	}
	for _, op := range []byte{0xaa, 0xab, 0xba, 0xb9, 0xc5, 0x84} {
		if !seen[op] {
			t.Fatalf("javac fixture missing opcode %x", op)
		}
	}
	if !wideSeen {
		t.Fatal("javac fixture has no wide instruction")
	}
	// Replace every Code attribute's original bytes with independently re-encoded
	// bytes and ask the real JVM to verify and execute the resulting class.
	for _, method := range methods {
		ins, err := c.DecodeMethod(method.code)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := c.EncodeMethod(ins)
		if err != nil {
			t.Fatal(err)
		}
		at := bytes.Index(class, method.code)
		if at < 0 {
			t.Fatal("Code bytes missing")
		}
		copy(class[at:at+len(encoded)], encoded)
	}
	if err := os.WriteFile(filepath.Join(dir, "Fixture.class"), class, 0644); err != nil {
		t.Fatal(err)
	}
	run("java", "-Xverify:all", "-cp", dir, "Fixture")
	t.Logf("%d methods, %d instructions matched javap; re-encoded class verified and executed", len(methods), len(expected))
}
