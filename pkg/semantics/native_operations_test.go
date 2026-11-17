package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustTypedIntegerAndFloatOperations(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{"runtime.rs": RustRuntime, "native.rs": nativeOperationTests} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "native.rs", "-Dwarnings", "-o", "native-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile typed operations: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "native-tests"))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute typed operations: %v\n%s", err, out)
	}
}

const nativeOperationTests = `
#[allow(dead_code)] mod runtime;
use runtime::*;
struct State;
impl Machine for State {
    fn read_register(&self,_:Register)->Value { panic!("constant expression read a register") }
    fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError> {panic!("constant expression read memory")}
}
fn binary(op:BinaryOp,w:u8,a:u64,b:u64)->u64 {
    evaluate_expression(&Expr::binary(op,Expr::constant(w,a),Expr::constant(w,b)),&State,&[]).unwrap().bits
}
#[test] fn narrow_products_and_total_division_are_exact() {
    for a in 0..=255u64 { for b in 0..=255u64 {
        assert_eq!(binary(BinaryOp::UnsignedMultiplyHigh,8,a,b),(a*b)>>8);
        assert_eq!(binary(BinaryOp::SignedMultiplyHigh,8,a,b),(((a as u8 as i8 as i16)*(b as u8 as i8 as i16))>>8) as u8 as u64);
        assert_eq!(binary(BinaryOp::Udiv,8,a,b),if b==0 {0}else{a/b});
        assert_eq!(binary(BinaryOp::Urem,8,a,b),if b==0 {0}else{a%b});
        let sa=a as u8 as i8 as i16; let sb=b as u8 as i8 as i16;
        assert_eq!(binary(BinaryOp::Sdiv,8,a,b),if b==0 {0}else{(sa/sb) as u8 as u64});
        assert_eq!(binary(BinaryOp::Srem,8,a,b),if b==0 {0}else{(sa%sb) as u8 as u64});
    }}
    assert_eq!(binary(BinaryOp::Sdiv,64,1<<63,u64::MAX),1<<63);
    assert_eq!(binary(BinaryOp::Srem,64,1<<63,u64::MAX),0);
    assert_eq!(binary(BinaryOp::UnsignedMultiplyHigh,64,u64::MAX,u64::MAX),u64::MAX-1);
    assert_eq!(binary(BinaryOp::SignedMultiplyHigh,64,1<<63,u64::MAX),0);
}
#[test] fn counts_and_permutations_use_the_declared_width() {
    for width in 1..=64 {
        for input in [0,1,u64::MAX,0x123456789abcdef0] {
            let value=input & mask(width);
            for (op,expected) in [
                (UnaryOp::CountLeadingZeros,u64::from(value.leading_zeros())-u64::from(64-width)),
                (UnaryOp::PopulationCount,u64::from(value.count_ones())),
                (UnaryOp::ReverseBits,value.reverse_bits()>>(64-width)),
            ] { assert_eq!(evaluate_expression(&Expr::unary(op,Expr::constant(width,value)),&State,&[]).unwrap().bits,expected); }
            let expression=Expr::unary(UnaryOp::ReverseBytes,Expr::constant(width,value));
            if width%8==0 {assert_eq!(evaluate_expression(&expression,&State,&[]).unwrap().bits,value.swap_bytes()>>(64-width));}
            else {assert_eq!(evaluate_expression(&expression,&State,&[]),Err(EvalError::InvalidExpression));}
        }
    }
}
#[test] fn floating_nodes_validate_all_operands_and_require_an_explicit_engine() {
    let mut operation=FloatExpression {
        operation:FloatOperation::Divide,environment:FloatEnvironment::X86Mxcsr,width:32,
        inputs:vec![Expr::constant(32,0x3f800000),Expr::constant(32,0)],
        control:Box::new(Expr::constant(32,0x1f80)),status:Box::new(Expr::constant(32,0)),projection:FloatProjection::Value,
    };
    assert_eq!(evaluate_expression(&Expr::float(operation.clone()),&State,&[]),Err(EvalError::Unsupported));
    operation.inputs.pop();
    assert_eq!(evaluate_expression(&Expr::float(operation),&State,&[]),Err(EvalError::InvalidExpression));
}
#[test] fn typed_float_dimensions_cover_mixed_width_and_relation_results() {
    let valid = [
        (FloatOperation::FusedMultiplyAdd{negate_product:false,negate_addend:true},32,vec![32,32,32]),
        (FloatOperation::Compare{source_width:64,signal_all_nans:true},4,vec![64,64]),
        (FloatOperation::Convert{source_width:64,round_to_odd:true},32,vec![64]),
        (FloatOperation::ToInteger{source_width:64,signed:true,fractional_bits:32,rounding:FloatRounding::Zero},32,vec![64]),
        (FloatOperation::FromInteger{source_width:32,signed:false,fractional_bits:16},64,vec![32]),
        (FloatOperation::RoundToIntegral{rounding:FloatRounding::Environment,exact:true},32,vec![32]),
    ];
    for (operation,width,inputs) in valid {
        let mut f=FloatExpression{operation,environment:FloatEnvironment::A64,width,
            inputs:inputs.iter().map(|w| Expr::constant(*w,0)).collect(),
            control:Box::new(Expr::constant(32,0)),status:Box::new(Expr::constant(32,0)),projection:FloatProjection::Value};
        for projection in [FloatProjection::Value,FloatProjection::Status,FloatProjection::Trapped] {
            f.projection=projection;
            let expression=Expr::float(f.clone());
            assert_eq!(validate_expression(&expression,&[]),Ok(()),"{operation:?} {projection:?}");
            assert_eq!(evaluate_expression(&expression,&State,&[]),Err(EvalError::Unsupported));
        }
        f.inputs[0]=Expr::constant(8,0);
        assert_eq!(validate_expression(&Expr::float(f),&[]),Err(EvalError::InvalidExpression));
    }
    let bad = [
        (FloatOperation::Compare{source_width:64,signal_all_nans:false},32,vec![64,64]),
        (FloatOperation::Convert{source_width:32,round_to_odd:true},16,vec![32]),
        (FloatOperation::ToInteger{source_width:32,signed:false,fractional_bits:33,rounding:FloatRounding::Zero},32,vec![32]),
        (FloatOperation::ToInteger{source_width:32,signed:false,fractional_bits:1,rounding:FloatRounding::NearestEven},32,vec![32]),
        (FloatOperation::FromInteger{source_width:16,signed:false,fractional_bits:17},32,vec![16]),
    ];
    for (operation,width,inputs) in bad {
        let f=FloatExpression{operation,environment:FloatEnvironment::A64,width,
            inputs:inputs.iter().map(|w| Expr::constant(*w,0)).collect(),
            control:Box::new(Expr::constant(32,0)),status:Box::new(Expr::constant(32,0)),projection:FloatProjection::Value};
        assert_eq!(validate_expression(&Expr::float(f),&[]),Err(EvalError::InvalidExpression));
    }
}
#[test] fn a_trap_commits_earlier_status_but_no_later_outputs_or_pipeline_advance() {
    let mut recipe=Recipe::new(4,64);
    recipe.write(register("status",0,32,32),WritePolicy::ZeroUpper,Expr::constant(32,4));
    recipe.effects.push(Effect::Trap{kind:TrapKind::FloatingPoint,condition:Expr::constant(1,1)});
    recipe.write(register("result",0,64,64),WritePolicy::ZeroUpper,Expr::constant(64,7));
    recipe.write_always(register("pipeline",0,8,8),WritePolicy::ZeroUpper,Expr::constant(8,0));
    let transition=evaluate(&recipe,&State).unwrap();
    assert_eq!(transition.trap,Some(TrapKind::FloatingPoint));
    assert_eq!(transition.registers.len(),1);
    assert_eq!(transition.registers[0].register.bank,"status");
}
`
