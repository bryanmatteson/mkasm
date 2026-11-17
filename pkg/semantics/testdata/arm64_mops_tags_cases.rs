const MOPS_GROUPS:&[([u32;3],bool,bool,bool)]=&[
    ([0x19000400, 0x19400400, 0x19800400],false,false,true), // cpyfp
    ([0x1900c400, 0x1940c400, 0x1980c400],false,false,true), // cpyfpn
    ([0x19008400, 0x19408400, 0x19808400],false,false,true), // cpyfprn
    ([0x19002400, 0x19402400, 0x19802400],false,false,true), // cpyfprt
    ([0x1900e400, 0x1940e400, 0x1980e400],false,false,true), // cpyfprtn
    ([0x1900a400, 0x1940a400, 0x1980a400],false,false,true), // cpyfprtrn
    ([0x19006400, 0x19406400, 0x19806400],false,false,true), // cpyfprtwn
    ([0x19003400, 0x19403400, 0x19803400],false,false,true), // cpyfpt
    ([0x1900f400, 0x1940f400, 0x1980f400],false,false,true), // cpyfptn
    ([0x1900b400, 0x1940b400, 0x1980b400],false,false,true), // cpyfptrn
    ([0x19007400, 0x19407400, 0x19807400],false,false,true), // cpyfptwn
    ([0x19004400, 0x19404400, 0x19804400],false,false,true), // cpyfpwn
    ([0x19001400, 0x19401400, 0x19801400],false,false,true), // cpyfpwt
    ([0x1900d400, 0x1940d400, 0x1980d400],false,false,true), // cpyfpwtn
    ([0x19009400, 0x19409400, 0x19809400],false,false,true), // cpyfpwtrn
    ([0x19005400, 0x19405400, 0x19805400],false,false,true), // cpyfpwtwn
    ([0x1d000400, 0x1d400400, 0x1d800400],false,false,false), // cpyp
    ([0x1d00c400, 0x1d40c400, 0x1d80c400],false,false,false), // cpypn
    ([0x1d008400, 0x1d408400, 0x1d808400],false,false,false), // cpyprn
    ([0x1d002400, 0x1d402400, 0x1d802400],false,false,false), // cpyprt
    ([0x1d00e400, 0x1d40e400, 0x1d80e400],false,false,false), // cpyprtn
    ([0x1d00a400, 0x1d40a400, 0x1d80a400],false,false,false), // cpyprtrn
    ([0x1d006400, 0x1d406400, 0x1d806400],false,false,false), // cpyprtwn
    ([0x1d003400, 0x1d403400, 0x1d803400],false,false,false), // cpypt
    ([0x1d00f400, 0x1d40f400, 0x1d80f400],false,false,false), // cpyptn
    ([0x1d00b400, 0x1d40b400, 0x1d80b400],false,false,false), // cpyptrn
    ([0x1d007400, 0x1d407400, 0x1d807400],false,false,false), // cpyptwn
    ([0x1d004400, 0x1d404400, 0x1d804400],false,false,false), // cpypwn
    ([0x1d001400, 0x1d401400, 0x1d801400],false,false,false), // cpypwt
    ([0x1d00d400, 0x1d40d400, 0x1d80d400],false,false,false), // cpypwtn
    ([0x1d009400, 0x1d409400, 0x1d809400],false,false,false), // cpypwtrn
    ([0x1d005400, 0x1d405400, 0x1d805400],false,false,false), // cpypwtwn
    ([0x1dc00400, 0x1dc04400, 0x1dc08400],true,true,false), // setgp
    ([0x1dc02400, 0x1dc06400, 0x1dc0a400],true,true,false), // setgpn
    ([0x1dc01400, 0x1dc05400, 0x1dc09400],true,true,false), // setgpt
    ([0x1dc03400, 0x1dc07400, 0x1dc0b400],true,true,false), // setgptn
    ([0x19c00400, 0x19c04400, 0x19c08400],true,false,false), // setp
    ([0x19c02400, 0x19c06400, 0x19c0a400],true,false,false), // setpn
    ([0x19c01400, 0x19c05400, 0x19c09400],true,false,false), // setpt
    ([0x19c03400, 0x19c07400, 0x19c0b400],true,false,false), // setptn
];
const TAG_CASES:&[(u32,&str)]=&[
    (0xd9600000,"LDG_64Loffset_ldsttags"),
    (0xd9e00000,"LDGM_64bulk_ldsttags"),
    (0xd9a00400,"ST2G_64Spost_ldsttags"),
    (0xd9a00c00,"ST2G_64Spre_ldsttags"),
    (0xd9a00800,"ST2G_64Soffset_ldsttags"),
    (0xd9200400,"STG_64Spost_ldsttags"),
    (0xd9200c00,"STG_64Spre_ldsttags"),
    (0xd9200800,"STG_64Soffset_ldsttags"),
    (0xd9a00000,"STGM_64bulk_ldsttags"),
    (0x68800000,"STGP_64_ldstpair_post"),
    (0x69800000,"STGP_64_ldstpair_pre"),
    (0x69000000,"STGP_64_ldstpair_off"),
    (0xd9e00400,"STZ2G_64Spost_ldsttags"),
    (0xd9e00c00,"STZ2G_64Spre_ldsttags"),
    (0xd9e00800,"STZ2G_64Soffset_ldsttags"),
    (0xd9600400,"STZG_64Spost_ldsttags"),
    (0xd9600c00,"STZG_64Spre_ldsttags"),
    (0xd9600800,"STZG_64Soffset_ldsttags"),
    (0xd9200000,"STZGM_64bulk_ldsttags"),
];
