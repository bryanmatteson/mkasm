package codec

import (
	"bytes"
	"strings"
	"testing"
)

func TestOperandSpansAndExactEdits(t *testing.T) {
	c := exampleCatalog(t)
	for _, tc := range []struct {
		id     string
		values map[string]int64
	}{
		{"MOV", map[string]int64{"Rd": 2, "imm": -8}},
		{"REPEAT", map[string]int64{"count": 3, "src": 5}},
		{"BR", map[string]int64{"Target": -8}},
		{"LOOKUP", map[string]int64{"number": 21, "offset": -32}},
		{"PADDING", map[string]int64{"ignored": 15, "value": 3}},
		{"VISIBLE_OPTIONAL", map[string]int64{"value": 7}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			b, err := c.Encode(tc.id, tc.values)
			if err != nil {
				t.Fatal(err)
			}
			d, err := c.Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			desc := d.Describe(0x1000)
			if desc.Text != d.Format(0x1000) || len(desc.Operands) != len(syntaxHoles(d.Encoding.Syntax)) {
				t.Fatalf("description differs from formatter: %+v", desc)
			}
			for _, span := range desc.Operands {
				if span.Start < 0 || span.End > len(desc.Text) || span.Start > span.End || span.Value != d.Values[span.Name] {
					t.Fatalf("invalid operand span: %+v", span)
				}
				if span.Position.Relative {
					target, ok := span.Position.Target(0x1000, span.Value)
					value, inverse := span.Position.ValueForTarget(0x1000, target)
					if !ok || !inverse || value != span.Value {
						t.Fatalf("position roundtrip: %+v", span)
					}
				}
			}
			before := d.Format(0x1000)
			if err := d.SetOperand("missing", 1); err == nil || d.Format(0x1000) != before {
				t.Fatal("unknown edit changed instruction")
			}
			if tc.id == "MOV" {
				if err := d.SetOperand("Rd", 4); err == nil || d.Values["Rd"] != 2 {
					t.Fatal("rejected edit was committed")
				}
				if err := d.SetOperand("Rd", 3); err != nil || !strings.HasPrefix(d.Format(0), "mov r3") {
					t.Fatal("valid edit failed", err)
				}
			}
		})
	}
}

func TestPrintedOptionalOperandOverridesOmittedDefault(t *testing.T) {
	c := exampleCatalog(t)
	forms, err := c.Assemble("visible 7", 0)
	if err != nil || len(forms) != 1 || !bytes.Equal(forms[0], []byte{0xf4, 7}) {
		t.Fatalf("printed optional operand: %x, %v", forms, err)
	}
}

func TestRelocationRetainsTargetsAndIgnoredFields(t *testing.T) {
	c := exampleCatalog(t)
	for _, tc := range []struct {
		id       string
		values   map[string]int64
		from, to uint64
		want     []byte
	}{
		{"BR", map[string]int64{"Target": 4}, 0x1000, 0x1002, []byte{0xa0, 1}},
		{"WRAP", map[string]int64{"Target": -4}, 0, 0xfffc, []byte{0xb0, 0}},
		{"PADDING", map[string]int64{"ignored": 15, "value": 3}, 0x1000, 0x1002, []byte{0xeb, 0xf3}},
	} {
		b, err := c.Encode(tc.id, tc.values)
		if err != nil {
			t.Fatal(err)
		}
		d, err := c.Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		next, err := d.Relocated(tc.from, tc.to)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := Encode(next.Encoding, next.Values)
		if err != nil || !bytes.Equal(encoded, tc.want) {
			t.Fatalf("%s: %x, %v", tc.id, encoded, err)
		}
		a, ao := d.BranchTarget(tc.from)
		btarget, bo := next.BranchTarget(tc.to)
		if a != btarget || ao != bo {
			t.Fatal("target changed during relocation")
		}
		original, _ := Encode(d.Encoding, d.Values)
		if !bytes.Equal(original, b) {
			t.Fatal("relocation mutated the source")
		}
	}
	branch, _ := c.Decode([]byte{0xb1, 5})
	if _, err := branch.Relocated(0x1ff, 0x3f0); err == nil {
		t.Fatal("accepted a target outside the relocated page")
	}
}

const rustAnalysisConsumer = `
#[test] fn relative_data_is_not_a_branch(){
let d=decode(&[0xe2,2,0,0,0]).unwrap();assert_eq!(d.branch_target(0x1000),None);
let described=d.describe(0x1000);assert!(described.operands[0].position_dependent());
let moved=d.relocated(0x1000,0x1002).unwrap();assert_eq!(moved.branch_target(0x1002),None);
assert_eq!(moved.describe(0x1002).operands[0].position.target(0x1002,moved.values[0]),described.operands[0].position.target(0x1000,d.values[0]));
}
#[test] fn spans_domains_templates_edits_and_relocation(){
let mut d=decode(&[0x82,0xfc]).unwrap();let described=d.describe(0x1000);assert_eq!(described.text,d.format(0x1000));assert_eq!(described.operands.len(),2);for s in &described.operands{assert_eq!(s.value,d.values[s.operand_index]);assert!(s.domain.contains(s.value));assert!(!s.position_dependent());}
assert_eq!(&described.text[described.operands[0].start..described.operands[0].end],"r2");assert_eq!(described.operands[0].domain,Domain::new(0,3,1,true));assert_eq!(described.operands[1].domain,Domain::new(-256,254,2,true));
assert_eq!(describe(&[0x82,0xfc],0x1000).unwrap(),described);assert!(d.set_operand("Rd",4).is_err());assert_eq!(d.operand("Rd"),Some(2));d.set_operand("Rd",3).unwrap();let mut out=[0xcc;4];assert_eq!(d.encode_into(&mut out).unwrap(),2);assert_eq!(out,[0x83,0xfc,0xcc,0xcc]);
let t=Template::parse("mov $r:register, ${n:integer}").unwrap();let holes=t.holes();assert_eq!(holes.len(),2);assert_eq!(holes[0].name,"r");assert_eq!(holes[0].domains[0].kind,"register");assert_eq!(t.hole_position(0),Some(Position::Fixed));assert!(Template::parse("mov $r:immediate, 0").is_err());assert!(t.could_match(&[0x82,0xfc]));assert!(!t.could_match(&[0x82]));assert!(t.byte_filters().any(|f|f.matches(&[0x82,0xfc])));assert!(t.encode(&[("r",2),("n",-8)]).unwrap().contains(&vec![0x82,0xfc]));
let upper=Template::parse("mov $Upper, ${lower}").unwrap();assert!(upper.holes().iter().any(|h|h.name=="Upper"));assert!(upper.matches(&[0x82,0xfc]).unwrap().1.contains(&("Upper".into(),2)));
let t=Template::parse_at("implicit $Target",0x1002).unwrap();assert_eq!(t.matches(&[0xf3,0]).unwrap().1,vec![("Target".into(),0)]);assert_eq!(t.holes()[0].domains[0].domain,Domain::new(0,0,1,true));assert!(t.encode(&[("Target",1)]).is_err());assert_eq!(t.encode(&[("Target",0)]).unwrap(),vec![vec![0xf3,0]]);
let t=Template::parse("visible $Value").unwrap();assert_eq!(t.matches(&[0xf4,7]).unwrap().1,vec![("Value".into(),7)]);assert_eq!(t.encode(&[("Value",7)]).unwrap(),vec![vec![0xf4,7]]);assert_eq!(assemble("visible 7").unwrap(),vec![vec![0xf4,7]]);
let t=Template::parse("divide $zero, ${Source}, $Target").unwrap();assert_eq!(t.matches(&[0xf5,0x21]).unwrap().1,vec![("Source".into(),1),("Target".into(),2)]);assert_eq!(t.encode(&[("Source",1),("Target",2)]).unwrap(),vec![vec![0xf5,0x21]]);
let t=Template::parse("divide $ZERO, $at, ${Target}").unwrap();assert_eq!(t.matches(&[0xf5,0x21]).unwrap().1,vec![("Target".into(),2)]);let t=Template::parse("dollar $zero").unwrap();assert!(t.holes().is_empty());assert!(t.matches(&[0xf6,0]).is_some());assert!(t.matches(&[0xf6,1]).is_none());let t=Template::parse("dollar ${zero}").unwrap();assert_eq!(t.matches(&[0xf6,2]).unwrap().1,vec![("zero".into(),2)]);
let t=Template::parse_with_features("long $word",0,Some(profile("short").unwrap()));assert!(t.is_err());let t=Template::parse_with_features("long $word",0,Some(profile("long").unwrap())).unwrap();assert_eq!(t.encodings(),vec!["PROFILE_LONG"]);assert_eq!(t.holes()[0].domains[0].domain,Domain::new(0,65535,1,true));
let t=Template::for_encoding("PADDING",0).unwrap();assert_eq!(t.holes().len(),2);assert_eq!(t.matches(&[0xeb,0xf3]).unwrap().1,vec![("ignored".into(),15),("value".into(),3)]);assert_eq!(t.encode(&[("ignored",15),("value",3)]).unwrap(),vec![vec![0xeb,0xf3]]);
let d=decode(&[0xa0,2]).unwrap();let target=d.branch_target(0x1000);let moved=d.relocated(0x1000,0x1002).unwrap();assert_eq!(moved.branch_target(0x1002),target);assert_eq!(encode(moved.encoding().id,&moved.values[..moved.encoding().operands.len()]).unwrap(),[0xa0,1]);let mut buffer=[0xcc;4];assert_eq!(d.relocate_into(0x1000,0x2000,&mut buffer),Err(Error::Operand));assert_eq!(buffer,[0xcc;4]);assert_eq!(d.relocate_into(0x1000,0x1002,&mut buffer).unwrap(),2);
let d=decode(&[0xb0,0xfe]).unwrap();let moved=d.relocated(0,0xfffc).unwrap();assert_eq!(moved.branch_target(0xfffc),Some(0xfffe));assert_eq!(moved.operand("Target"),Some(0));assert!(decode(&[0xb1,5]).unwrap().relocated(0x1ff,0x3f0).is_err());
let d=decode(&[0xe5,100]).unwrap();let p=d.describe(0x1002).operands[0].position;assert_eq!(p.target(0x1002,100),Some(0x1066));assert_eq!(p.value_for_target(0x1002,0x1066),Some(100));assert_eq!(p.value_for_target(0x1002,0x1_0000_0000),None);
let u=catalog_entry("U64").unwrap().1.operands[0].domain();assert_eq!(u.max,u64::MAX as i128);assert!(u.contains(u64::MAX as i128));let s=catalog_entry("S64").unwrap().1.operands[0].domain();assert_eq!(s.min,i64::MIN as i128);assert_eq!(s.max,i64::MAX as i128);let lookup=catalog_entry("LOOKUP").unwrap().1.operands[0].domain();assert!(lookup.contains(21));assert!(!lookup.exact);assert!(Template::for_encoding("TUPLES",0).unwrap().holes().iter().all(|h|h.domains.iter().all(|d|!d.domain.exact)));
assert_eq!(Domain::new(-10,11,4,true).max,10);assert!(Domain::new(i128::MIN,i128::MAX,1,false).contains(i128::MAX));assert!(Domain::new(i128::MIN,i128::MAX,2,false).contains(i128::MAX-1));assert_eq!(Position::Fixed.target(0,1),None);
}
#[test] fn every_example_rejects_extreme_edits_and_bindings_atomically(){
    for(index,e)in ENCODINGS.iter().enumerate(){
        let values=representative(index).unwrap();let bytes=encode(e.id,&values).unwrap();let template=Template::for_encoding(e.id,0x1000).unwrap();
        for(n,o)in e.operands.iter().enumerate(){for value in [i128::MIN,i128::MAX]{
            let mut invalid=values.clone();invalid[n]=value;let mut output=[0xcc;256];assert_eq!(encode_into(index,&invalid,&mut output),Err(Error::Operand),"{} {}",e.id,o.name);assert_eq!(output,[0xcc;256]);
            if !o.implicit{let holes=e.operands.iter().zip(&invalid).filter(|(o,_)|!o.implicit).map(|(o,&v)|(o.name,v)).collect::<Vec<_>>();assert!(template.encode(&holes).is_err(),"{} {} template",e.id,o.name);}
        }}
        assert_eq!(encode(e.id,&values).unwrap(),bytes);
    }
}
`
