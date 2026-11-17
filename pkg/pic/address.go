package pic

import (
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"strings"
)

// TargetWithPage resolves a direct target using the hardware page latch.
// On baseline PIC12 pageLatch is the normalized PA field (STATUS bits6:5).
// On midrange PIC14 and PIC17 LCALL it is PCLATH. address is a physical byte
// offset, including PIC24 phantom bytes. Indirect register targets remain unknown.
// The general BranchTarget method uses the current code page when no latch
// context is supplied; this helper resolves cross-page transfers explicitly.
func TargetWithPage(d *codec.Decoded, address uint64, pageLatch uint8) (uint64, bool) {
	m := strings.ToUpper(d.Encoding.Mnemonic)
	var low uint64
	found := false
	for _, o := range d.Encoding.Operands {
		if o.Kind == "address" {
			low = uint64(d.Values[o.Name])
			found = true
			break
		}
	}
	if !found {
		return d.BranchTarget(address)
	}
	for _, feature := range d.Encoding.Features {
		if (feature == "pic-pic12" || feature == "pic-pic16c5x") && (m == "CALL" || m == "GOTO") {
			return (uint64(pageLatch&3) << 10) | low, true
		}
		if (feature == "pic-pic14" || feature == "pic-pic14-enhanced") && (m == "CALL" || m == "GOTO") {
			mask := uint8(0x18)
			if feature == "pic-pic14-enhanced" {
				mask = 0x78
			}
			return (uint64(pageLatch&mask) << 9) | low, true
		}
		if feature == "pic-pic17" && m == "LCALL" {
			return uint64(pageLatch)<<9 | low, true
		}
	}
	return d.BranchTarget(address)
}

const pageRuntime = `
/// Resolve a direct target with normalized PIC12 PA or PIC14/PIC17 PCLATH.
/// All returned addresses are physical byte offsets.
pub fn target_with_page(d:&Decoded,address:u64,page_latch:u8)->Option<u64>{
 let e=d.encoding();let m=e.mnemonic.to_ascii_uppercase();
 let low=d.operands().find(|(o,_)|o.kind=="address").map(|(_,v)|v as u64);
 if let Some(low)=low {for &f in e.features {
  if (f=="pic-pic12"||f=="pic-pic16c5x")&&(m=="CALL"||m=="GOTO"){return Some(((page_latch as u64&3)<<10)|low);}
  if (f=="pic-pic14"||f=="pic-pic14-enhanced")&&(m=="CALL"||m=="GOTO"){let mask=if f=="pic-pic14-enhanced"{0x78}else{0x18};return Some((((page_latch&mask)as u64)<<9)|low);}
  if f=="pic-pic17"&&m=="LCALL"{return Some(((page_latch as u64)<<9)|low);}
 }}d.branch_target(address)
}
`
