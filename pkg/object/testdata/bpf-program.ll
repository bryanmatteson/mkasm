source_filename = "object-bpf.c"

declare i64 @external(i64)

define hidden i64 @entry(i64 %context) !dbg !4 {
  %result = call i64 @external(i64 %context), !dbg !8
  ret i64 %result, !dbg !8
}

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}
!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "go-mkasm object integration", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug)
!1 = !DIFile(filename: "object-bpf.c", directory: "/mkasm")
!2 = !{i32 2, !"Dwarf Version", i32 4}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = distinct !DISubprogram(name: "entry", scope: !1, file: !1, line: 1, type: !5, scopeLine: 1, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0)
!5 = !DISubroutineType(types: !6)
!6 = !{!7, !7}
!7 = !DIBasicType(name: "long long", size: 64, encoding: DW_ATE_signed)
!8 = !DILocation(line: 2, column: 3, scope: !4)
