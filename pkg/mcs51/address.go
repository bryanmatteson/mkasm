package mcs51

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

var aliasOnce sync.Once
var directNames, bitNames map[string]int64

func aliases() {
	aliasOnce.Do(func() {
		directNames = map[string]int64{"A": 0xe0}
		bitNames = map[string]int64{}
		var ps struct {
			Symbols []struct {
				Name    string `xml:"name,attr"`
				Address string `xml:"address,attr"`
			} `xml:"default_symbols>symbol"`
		}
		if err := xml.Unmarshal([]byte(processorSpec), &ps); err != nil {
			panic(err)
		}
		for _, s := range ps.Symbols {
			space, v, ok := strings.Cut(s.Address, ":")
			if !ok {
				continue
			}
			n, err := strconv.ParseInt(v, 16, 64)
			if err != nil {
				continue
			}
			if space == "SFR" || space == "INTMEM" {
				directNames[s.Name] = n
			}
			if space == "BITS" {
				bitNames[s.Name] = n
			}
		}
		for b := 0; b < 256; b++ {
			address, bit, _ := ResolveBit(uint8(b))
			bitNames[fmt.Sprintf("0x%x.%d", address, bit)] = int64(b)
			for n, v := range directNames {
				if v == int64(address) {
					bitNames[fmt.Sprintf("%s.%d", n, bit)] = int64(b)
				}
			}
		}
	})
}
func directAliases() map[string]int64 { aliases(); return directNames }
func bitAliases() map[string]int64    { aliases(); return bitNames }

// RegisterAddress maps the encoded logical R0..R7 through PSW.RS1:RS0 into
// internal RAM. The bank state is not part of an instruction's encoding.
func RegisterAddress(reg, psw uint8) (uint8, error) {
	if reg > 7 {
		return 0, fmt.Errorf("MCS-51 register must be R0..R7")
	}
	return ((psw>>3)&3)*8 + reg, nil
}

// ResolveDirect distinguishes directly addressed internal RAM from SFR space.
// Upper internal RAM remains accessible through @R0/@R1, never direct mode.
func ResolveDirect(address uint8) (space string, offset uint8) {
	if address < 128 {
		return "INTMEM", address
	}
	return "SFR", address
}

// ResolveBit returns the byte and bit in INTMEM (bits 00..7f => bytes20..2f)
// or the bit-addressable SFR byte (bits80..ff => byte bitaddr&f8).
func ResolveBit(address uint8) (byteAddress uint8, bit uint8, space string) {
	if address < 128 {
		return 0x20 + address/8, address & 7, "INTMEM"
	}
	return address & 0xf8, address & 7, "SFR"
}

// ExternalIndirectAddress models classic MOVX @Ri's external address bus:
// the logical Ri value supplies A0..7 and the current P2 latch supplies A8..15.
func ExternalIndirectAddress(riValue, p2 uint8) uint16 { return uint16(p2)<<8 | uint16(riValue) }

// ComputedCodeAddress handles MOVC/JMP @A+DPTR and MOVC @A+PC. PC-relative
// table reads use the address after the instruction; all additions wrap to the
// selected core's code address width (16, or 24 in DS80C390 flat mode).
func ComputedCodeAddress(pc uint32, length uint8, acc uint8, dptr uint32, usePC, flat390 bool) uint32 {
	base := dptr
	if usePC {
		base = pc + uint32(length)
	}
	mask := uint32(0xffff)
	if flat390 {
		mask = 0xffffff
	}
	return (base + uint32(acc)) & mask
}
