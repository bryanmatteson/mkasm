	.file	"object-bpf.c"
	.text
	.hidden	entry                           # -- Begin function entry
	.globl	entry
	.p2align	3
	.type	entry,@function
entry:                                  # @entry
.Lfunc_begin0:
	.cfi_startproc
# %bb.0:
	.file	1 "/mkasm" "object-bpf.c"
	.loc	1 2 3 prologue_end              # object-bpf.c:2:3
.Ltmp0:
	call external
	exit
.Ltmp1:
.Ltmp2:
.Lfunc_end0:
	.size	entry, .Lfunc_end0-entry
	.cfi_endproc
                                        # -- End function
	.section	.debug_abbrev,"",@progbits
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	37                              # DW_AT_producer
	.byte	14                              # DW_FORM_strp
	.byte	19                              # DW_AT_language
	.byte	5                               # DW_FORM_data2
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	16                              # DW_AT_stmt_list
	.byte	23                              # DW_FORM_sec_offset
	.byte	27                              # DW_AT_comp_dir
	.byte	14                              # DW_FORM_strp
	.ascii	"\264B"                         # DW_AT_GNU_pubnames
	.byte	25                              # DW_FORM_flag_present
	.byte	17                              # DW_AT_low_pc
	.byte	1                               # DW_FORM_addr
	.byte	18                              # DW_AT_high_pc
	.byte	6                               # DW_FORM_data4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	1                               # DW_FORM_addr
	.byte	18                              # DW_AT_high_pc
	.byte	6                               # DW_FORM_data4
	.byte	64                              # DW_AT_frame_base
	.byte	24                              # DW_FORM_exprloc
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	63                              # DW_AT_external
	.byte	25                              # DW_FORM_flag_present
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	3                               # Abbreviation Code
	.byte	36                              # DW_TAG_base_type
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	62                              # DW_AT_encoding
	.byte	11                              # DW_FORM_data1
	.byte	11                              # DW_AT_byte_size
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	0                               # EOM(3)
	.section	.debug_info,"",@progbits
.Lcu_begin0:
	.long	.Ldebug_info_end0-.Ldebug_info_start0 # Length of Unit
.Ldebug_info_start0:
	.short	4                               # DWARF version number
	.long	.debug_abbrev                   # Offset Into Abbrev. Section
	.byte	8                               # Address Size (in bytes)
	.byte	1                               # Abbrev [1] 0xb:0x40 DW_TAG_compile_unit
	.long	.Linfo_string0                  # DW_AT_producer
	.short	12                              # DW_AT_language
	.long	.Linfo_string1                  # DW_AT_name
	.long	.Lline_table_start0             # DW_AT_stmt_list
	.long	.Linfo_string2                  # DW_AT_comp_dir
                                        # DW_AT_GNU_pubnames
	.quad	.Lfunc_begin0                   # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0       # DW_AT_high_pc
	.byte	2                               # Abbrev [2] 0x2a:0x19 DW_TAG_subprogram
	.quad	.Lfunc_begin0                   # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	90
	.long	.Linfo_string3                  # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	1                               # DW_AT_decl_line
	.long	67                              # DW_AT_type
                                        # DW_AT_external
	.byte	3                               # Abbrev [3] 0x43:0x7 DW_TAG_base_type
	.long	.Linfo_string4                  # DW_AT_name
	.byte	5                               # DW_AT_encoding
	.byte	8                               # DW_AT_byte_size
	.byte	0                               # End Of Children Mark
.Ldebug_info_end0:
	.section	.debug_str,"MS",@progbits,1
.Linfo_string0:
	.asciz	"go-mkasm object integration"   # string offset=0
.Linfo_string1:
	.asciz	"object-bpf.c"                  # string offset=28
.Linfo_string2:
	.asciz	"/mkasm"                        # string offset=41
.Linfo_string3:
	.asciz	"entry"                         # string offset=48
.Linfo_string4:
	.asciz	"long long"                     # string offset=54
	.section	.debug_pubnames,"",@progbits
	.long	.LpubNames_end0-.LpubNames_start0 # Length of Public Names Info
.LpubNames_start0:
	.short	2                               # DWARF Version
	.long	.Lcu_begin0                     # Offset of Compilation Unit Info
	.long	75                              # Compilation Unit Length
	.long	42                              # DIE offset
	.asciz	"entry"                         # External Name
	.long	0                               # End Mark
.LpubNames_end0:
	.section	.debug_pubtypes,"",@progbits
	.long	.LpubTypes_end0-.LpubTypes_start0 # Length of Public Types Info
.LpubTypes_start0:
	.short	2                               # DWARF Version
	.long	.Lcu_begin0                     # Offset of Compilation Unit Info
	.long	75                              # Compilation Unit Length
	.long	67                              # DIE offset
	.asciz	"long long"                     # External Name
	.long	0                               # End Mark
.LpubTypes_end0:
	.section	.BTF,"",@progbits
	.short	60319                           # 0xeb9f
	.byte	1
	.byte	0
	.long	24
	.long	0
	.long	48
	.long	48
	.long	43
	.long	0                               # BTF_KIND_FUNC_PROTO(id = 1)
	.long	218103809                       # 0xd000001
	.long	2
	.long	0
	.long	2
	.long	1                               # BTF_KIND_INT(id = 2)
	.long	16777216                        # 0x1000000
	.long	8
	.long	16777280                        # 0x1000040
	.long	11                              # BTF_KIND_FUNC(id = 3)
	.long	201326593                       # 0xc000001
	.long	1
	.byte	0                               # string offset=0
	.ascii	"long long"                     # string offset=1
	.byte	0
	.ascii	"entry"                         # string offset=11
	.byte	0
	.ascii	".text"                         # string offset=17
	.byte	0
	.ascii	"/mkasm/object-bpf.c"           # string offset=23
	.byte	0
	.section	.BTF.ext,"",@progbits
	.short	60319                           # 0xeb9f
	.byte	1
	.byte	0
	.long	32
	.long	0
	.long	20
	.long	20
	.long	28
	.long	48
	.long	0
	.long	8                               # FuncInfo
	.long	17                              # FuncInfo section string offset=17
	.long	1
	.long	.Lfunc_begin0
	.long	3
	.long	16                              # LineInfo
	.long	17                              # LineInfo section string offset=17
	.long	1
	.long	.Ltmp0
	.long	23
	.long	0
	.long	2051                            # Line 2 Col 3
	.section	.debug_line,"",@progbits
.Lline_table_start0:
