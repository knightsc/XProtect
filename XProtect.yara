import "hash"

private rule Macho
{
    meta:
        description = "private rule to match Mach-O binaries"
    condition:
        uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca

}

rule EleanorA
{
    meta:
        description = "OSX.Eleanor.A"
    condition:
        hash.sha1(0, filesize) == "de642751e96b8c53744f031a6f7e929d53226321" or
        hash.sha1(0, filesize) == "1f782e84ddbf5fd76426f6f9bf3d4238d2ec9a4b"
}

rule HMining_Binary_A
{
    meta:
        description = "OSX.HMining.A"

    strings:
        $a = {68 69 64 65 4F 70 65 72 61 74 6F 72 57 69 64 6F 77 41 66 74 65 72 41 64 6D 69 6E}
        $b = {48 8B 85 98 FE FF FF 48 89 44 24 38 48 8B 85 90 FE FF FF 48 89 44 24 30 48 8B 85 80 FE FF FF 48 8B 8D 88 FE FF FF 48 89 4C 24 28 48 89 44 24 20 48 8B 85 00 FF FF FF 48 89 44 24 18 48 8B 85 F8 FE FF FF 48 89 44 24 10 48 8B 85 E8 FE FF FF 48 8B 8D F0 FE FF FF 48 89 4C 24 08 48 89 04 24}
        $c = {61 6C 6C 43 6F 6D 70 65 74 69 74 6F 72 73 41 67 65 6E 74 44 65 6D 6F 6E 64}
        $d = {63 72 65 61 74 65 41 6E 64 4C 6F 61 64 41 67 65 6E 74 50 6C 69 73 74 50 61 74 68 3A 61 67 65 6E 74 50 6C 69 73 74 4E 61 6D 65 3A 61 67 65 6E 74 50 6C 69 73 74 4B 65 79 41 72 72 3A 61 67 65 6E 74 50 6C 69 73 74 56 61 6C 41 72 72 3A 69 73 41 64 6D 69 6E 3A}
    condition:
        Macho and (($a and $b) or ($c and $d))
}

rule TroviProxyApp
{
	meta:
        description = "OSX.Trovi.A"
    strings:
        $a = {72 65 63 65 69 76 69 6E 67 57 65 62 73 69 74 65 53 74 61 72 74 65 64}
        $b = {68 74 6D 6C 49 6E 6A 65 63 74 65 64}
    condition:
		Macho and ($a and $b)
}

rule HMining
{
    meta:
        description = "OSX.Hmining.A"
    strings:
        $a = {68 69 64 65 4F 70 65 72 61 74 6F 72 57 69 64 6F 77 41 66 74 65 72 41 64 6D 69 6E}
        $b = {48 8B 85 98 FE FF FF 48 89 44 24 38 48 8B 85 90 FE FF FF 48 89 44 24 30 48 8B 85 80 FE FF FF 48 8B 8D 88 FE FF FF 48 89 4C 24 28 48 89 44 24 20 48 8B 85 00 FF FF FF 48 89 44 24 18 48 8B 85 F8 FE FF FF 48 89 44 24 10 48 8B 85 E8 FE FF FF 48 8B 8D F0 FE FF FF 48 89 4C 24 08 48 89 04 24}
    condition:
        Macho and ($a and $b)
}


rule BundloreA
{
    meta:
        description = "OSX.Bundlore.A"
    strings:
        $a = {5F 5F 6D 6D 5F 67 65 74 49 6E 6A 65 63 74 65 64 50 61 72 61 6D 73}
        $b = {5F 5F 6D 6D 5F 72 75 6E 53 68 65 6C 6C 53 63 72 69 70 74 41 73 52 6F 6F 74}
    condition:
        Macho and ($a and $b)
}

rule GenieoE
{
    meta:
        description = "OSX.Genieo.E"
    strings:
        $a = {47 4E 53 69 6E 67 6C 65 74 6F 6E 47 6C 6F 62 61 6C 43 61 6C 63 75 6C 61 74 6F 72}
        $b = {47 4E 46 61 6C 6C 62 61 63 6B 52 65 70 6F 72 74 48 61 6E 64 6C 65 72}
    condition:
        Macho and ($a and $b)
}

rule InstallCoreA
{
    
    meta:
        description = "OSX.InstallCore.A"
    strings:
        $a = {C6 45 A0 65 C6 45 A1 52 C6 45 A2 4A C6 45 A3 50 C6 45 A4 5B C6 45 A5 57 C6 45 A6 72 C6 45 A7 48 C6 45 A8 53 C6 45 A9 5D C6 45 AA 25 C6 45 AB 33 C6 45 AC 42 C6 45 A0 53 B8 01 00 00 00}
        $b = {49 89 DF 48 89 C3 FF D3 4C 89 EF FF D3 48 8B 7D B0 FF D3 48 8B 7D B8 FF D3 4C 89 FF FF D3 4C 8B 6D C0 48 8B 7D A8}
        $c = {49 43 4A 61 76 61 53 63 72 69 70 74 45 6E 76 69 72 6F 6E 6D 65 6E 74 49 6E 66 6F}
    condition:
        Macho and ($a or $b or $c)
}


rule KeRangerA
{
    meta:
        description = "OSX.KeRanger.A"

    strings:
        $a = {48 8D BD D0 EF FF FF BE 00 00 00 00 BA 00 04 00 00 31 C0 49 89 D8 ?? ?? ?? ?? ?? 31 F6 4C 89 E7 ?? ?? ?? ?? ?? 83 F8 FF 74 57 C7 85 C4 EB FF FF 00 00 00 00}

    condition:
        Macho and $a
}

rule CrossRiderA : adware
{
	meta:
		description="OSX.CrossRider.A"
	strings:
		$a = {E9 00 00 00 00 48 8B 85 00 FE FF FF 8A 08 88 8D 5F FE FF FF 0F BE 95 5F FE FF FF 83 C2 D0 89 55 E0 48 8B B5 60 FE FF FF 48 8B BD 40 FE FF FF}
	condition:
		Macho and $a
}


rule GenieoDropper
{
    meta:
        description = "OSX.GenieoDropper.A"
    strings:
        $a = {66756E6374696F6E204163636570744F666665727328297B}
        $b = {747261636B416E616C79746963734576656E742822657865637574696F6E222C224A7352756E22293B}
    condition:
        $a and $b
}

rule XcodeGhost
{
    meta:
        description = "OSX.XcodeGhost.A"
    strings:
        $a = {8346002008903046 [-] 082108A800910021019101210296032203955346CDF810B0059406900120}
        $b = {8346002007902046 [-] 082107A8009100210DF10409032289E8320801214346059606900120}
        $c = {8346002007903046 [-] 082107A800910021019101210296032203955346CDF810B0059406900020}
    condition:
        Macho and ($a or $b or $c)
}

rule GenieoD
{
    meta:
        description = "OSX.Genieo.D"
    strings:
        $a = {49 89 C4 0F 57 C0 0F 29 85 80 FE FF FF 0F 29 85 70 FE FF FF 0F 29 85 60 FE FF FF 0F 29 85 50 FE FF FF 41 B8 10 00 00 00 4C 89 E7 48 8B B5 40 FE FF FF 48 8D 95 50 FE FF FF 48}
        $b = {F2 0F 59 C1 F2 0F 5C D0 F2 0F 11 55 B8 0F 28 C2 F2 0F 10 55 D8 F2 0F 10 5D C8 F2 0F 58 DA F2 0F 59 D1 F2 0F 5C DA F2 0F 11 5D B0 0F 28 CB 31 FF BE 05 00 00 00 31 D2}
    condition:
        $a or $b
}

rule GenieoC
{
    meta:
        description = "OSX.Genieo.C"
    condition:
        Macho and hash.sha1(0, filesize) == "a3e827031f1466444272499ef853484bac1eb90b"
}

rule GenieoB
{
    meta:
        description = "OSX.Genieo.B"
    condition:
        Macho and (hash.sha1(0, filesize) == "495735da5fb582b93d90fff2c8b996d25e21aa31" or hash.sha1(0, filesize) == "0e196c0677bf6f94411229defc94639dd1b62b76")
}

rule VindinstallerA
{
    meta:
        description = "OSX.Vindinstaller.A"
    condition:
        Macho and hash.sha1(0, filesize) == "c040eee0f0d06d672cbfca94f2cbfc19795dd98d"
}

rule OpinionSpyB
{
    meta:
        description = "OSX.OpinionSpy.B"
    condition:
		hash.sha1(0, filesize) == "a0d0b9d34f07c7d99852b9b833ba8f472bb56516"
}

rule GenieoA
{
	meta:
        description = "OSX.Genieo.A"
    condition:
        Macho and hash.sha1(0, filesize) == "d07341c08173d0e885e6cafd7d5c50ebde07b205"
}

rule InstallImitatorC
{
	meta:
        description = "OSX.InstallImitator.C"
    condition:
        Macho and hash.sha1(0, filesize) == "eeac1275e018e886b3288daae7b07842aec57efd"
}

rule InstallImitatorB
{
    
    meta:
        description = "OSX.InstallImitator.B"
    strings:
        $a = {4989C64C89FF41FFD44889DF41FFD4488B7DC041FFD4488B7DA841FFD4488B5DB84889DF41FFD4488B7DB041FFD44889DF41FFD44C89F74883C4385B415C415D415E415F5D}
    condition:
        Macho and $a
}

rule InstallImitatorA
{
    
    meta:
        description = "OSX.InstallImitator.A"
    condition:
        Macho and (
        	hash.sha1(0, filesize) == "f58722369a28920076220247a0c4e3360765f0ba" or
        	hash.sha1(0, filesize) == "3b7e269867c5e1223f502d39dc14de30b1efdda9" or
        	hash.sha1(0, filesize) == "734d7e37ec664a7607e62326549cb7d3088ed023" or
        	hash.sha1(0, filesize) == "ea45a2a22ca9a02c07bb4b2367e5d64ea7314731" or
        	hash.sha1(0, filesize) == "f9646dc74337ee23a8c159f196419c46518a8095" or
        	hash.sha1(0, filesize) == "cd9b8da9e01f3ebf0e13c526a372fa65495e3778" or
        	hash.sha1(0, filesize) == "16b59ab450a9c1adab266aefcf4e8f8cf405ac9c" or
        	hash.sha1(0, filesize) == "4c87de3aa5a9c79c7f477baa4a23fba0e62dc9d8" or
        	hash.sha1(0, filesize) == "4df5387fe72b8abe0e341012334b8993f399d366"
        )
}

rule VSearchA
{
    meta:
        description = "OSX.VSearch.A"
    condition:
        Macho and (
        	hash.sha1(0, filesize) == "6c6acb179b232c0f1a6bb27699809320cc2c1529" or
        	hash.sha1(0, filesize) == "cebb19fee8fd72c0975ea9a19feea3b5ce555f94" or
        	hash.sha1(0, filesize) == "1503f1d7d275e976cd94cfd72929e0409e0cf76a" or
        	hash.sha1(0, filesize) == "c50adfa949a70b33d77050d7f0e2f86bccbc25cf" or
        	hash.sha1(0, filesize) == "40346b3946d7824d38f5ba71181f5c06805200af"
        )
}

rule MachookA
{
    meta:
        description = "OSX.Machook.A"
    condition:
        Macho and (
        	hash.sha1(0, filesize) == "e2b9578780ae318dbdb949aac32a7dde6c77d918" or
        	hash.sha1(0, filesize) == "bb8cbc2ab928d66fa1f17e02ff2634ad38a477d6"
        )
}

rule MachookB
{
    meta:
        description = "OSX.Machook.B"
    condition:
        Macho and (
            hash.sha1(0, filesize) == "ae3e35f8ac6a2a09abdb17dbce3874b9fd9a7b7b"
        )
}

rule IWormA
{
    meta:
        description = "OSX.iWorm.A"
        xprotect_rule = true
    condition:
        Macho and (
        	hash.sha1(0, filesize) == "c0800cd5095b28da4b6ca01468a279fb5be6921a"
        )
}

rule IWormBC
{
    meta:
        description = "OSX.iWorm.B/C"
        xprotect_rule = true
    condition:
        hash.sha1(0, filesize) == "5e68569d32772a479dfa9e6a23b2f3ae74b2028f"
        
}

rule NetWeirdB
{
    meta:
        description = "OSX.NetWeird.ii"
        xprotect_rule = true
    condition:
        Macho and (
        	hash.sha1(0, filesize) == "ed119afc2cc662e983fed2517e44e321cf695eee" or
        	hash.sha1(0, filesize) == "b703e0191eabaa41e1188c6a098fed36964732e2"
        )
}

rule NetWeirdA
{
    meta:
        description = "OSX.NetWeird.i"
        xprotect_rule = true
    condition:
        Macho and (
            hash.sha1(0, filesize) == "6f745ef4f9f521984d8738300148e83f50d01a9d" or
            hash.sha1(0, filesize) == "56abae0864220fc56ede6a121fde676b5c22e2e9"
        )
}

rule GetShellA
{
    meta:
        description = "OSX.GetShell.A"
        xprotect_rule = true
    condition:
        Macho and (
        	hash.sha1(0, filesize) == "112d4e785e363abfec51155a5536c072a0da4986"
        )
}

rule LaoShuA
{
    meta:
        description = "OSX.LaoShu.A"
        xprotect_rule = true
    condition:
        Macho and (
        	hash.sha1(0, filesize) == "2e243393a4e997d53d3d80516571a64f10313116"
        )
}

rule AbkA
{
    meta:
        description = "OSX.Abk.A"
        xprotect_rule = true
    condition:
        Macho and (
        	hash.sha1(0, filesize) == "3edb177abc8934fdc7d537f5115bb4fb6ab41c3f"
        )
}

rule CoinThiefA
{
    meta:
        description = "OSX.CoinThief.A"
        xprotect_rule = true
    condition:
        Macho and (
        	hash.sha1(0, filesize) == "37c4bc94f2c08e90a47825fe7b2afbce908b5d74"
        )
}

rule CoinThiefB
{
    meta:
        description = "OSX.CoinThief.B"
        xprotect_rule = true
    condition:
        Macho and (
            hash.sha1(0, filesize) == "c2b81f705670c837c0bf5a2ddd1e398e967c0a08" or
            hash.sha1(0, filesize) == "02e243157dbc8803a364e9410a5c41b36de64c95" 
        )
}

rule CoinThiefC
{
    meta:
        description = "OSX.CoinThief.C"
        xprotect_rule = true
    condition:
        Macho and (
            hash.sha1(0, filesize) == "d4d1480a623378202517cf86efc4ec27f3232f0d"
        )
}

rule RSPlugA
{
    meta:
        description = "OSX.RSPlug.A"
        xprotect_rule = true
    strings:
        $a = {4D6F7A696C6C61706C75672E706C7567696E00 [-] 5665726966696564446F776E6C6F6164506C7567696E00 [-] 5665726966696564446F776E6C6F6164506C7567696E2E7273726300}
        $b = {3C6B65793E4946506B67466C616744656661756C744C6F636174696F6E3C2F6B65793E [-] 3C737472696E673E2F4C6962726172792F496E7465726E657420506C75672D496E732F3C2F737472696E673E}
        $c = {23212F62696E2F [0-2] 7368}
    condition:
        $a and $b and $c
}

rule IServiceA
{
    meta:
        description = "OSX.Iservice.A/B"
        xprotect_rule = true
    strings:
        $a = {27666F72272073746570206D7573742062652061206E756D6265720025733A25753A206661696C656420617373657274696F6E20602573270A0000002F55736572732F6A61736F6E2F64696172726865612F6165732F6165735F6D6F6465732E63000000625F706F73203D3D2030000062616E0036392E39322E3137372E3134363A3539323031007177666F6A7A6C6B2E66726565686F737469612E636F6D3A31303234000000007374617274757000666600002C000000726F6F74000000002F62696E2F7368}
    condition:
        Macho and $a
}

rule HellRTS
{
    meta:
        description = "OSX.HellRTS.A"
        xprotect_rule = true
    strings:
        $a = {656C6C5261697365722053657276657200165F44454255475F4C4F475F505249564154452E747874 [-] 5374617274536572766572203E20212053455256455220524553544152544544 [-] 2F7573722F62696E2F64656661756C7473207772697465206C6F67696E77696E646F77204175746F4C61756E636865644170706C69636174696F6E44696374696F6E617279202D61727261792D61646420273C646963743E3C6B65793E486964653C2F6B65793E3C00192F3E3C6B65793E506174683C2F6B65793E3C737472696E673E00113C2F737472696E673E3C2F646963743E27 [-] 48656C6C52616973657220536572766572}
    condition:
        hash.sha1(0, filesize) == "a8dccca2a734b23a64deeb54c6741611467230a8" or 
        hash.sha1(0, filesize) == "797d7b60081368e50cb7d89c5d51c5d267a88a88" or 
        $a
}

rule OpinionSpyA
{
    meta:
        description = "OSX.OpinionSpy"
        xprotect_rule = true
    strings:
    	$a = {504B010214000A0000000800547D8B3B9B0231BC [4] 502D0700250000000000 [12] 636F6D2F697A666F7267652F697A7061636B2F70616E656C732F706F696E7374616C6C6572}
    condition:
		$a
}

rule MacDefenderA
{
    meta:
        description = "OSX.MacDefender.A"
        xprotect_rule = true
    strings:
    	$a = {3C6B65793E434642756E646C654964656E7469666965723C2F6B65793E [-] 3C737472696E673E636F6D2E41564D616B6572732E [-] 2E706B673C2F737472696E673E}
    	$b = {436F6E74726F6C43656E746572442E6E6962 [-] 5669727573466F756E642E706E67 [-] 57616C6C65742E706E67 [-] 61666669642E747874}
    condition:
		$a or $b
}

rule MacDefenderB
{
    meta:
        description = "OSX.MacDefender.B"
        xprotect_rule = true
    strings:
    	$a = {436F6E74656E7473 [-] 496E666F2E706C697374 [-] 4D61634F53 [-] 5265736F7572636573 [-] 0000 (0AF101134A4495 | 0B20012B644D93 | 0B1F01B1239428 | 0B1F0158C4CC11) 000000000000000000000008446F776E6C6F6164506963742E706E6700000000}

    condition:
		($a or
		hash.sha1(0, filesize) == "03fce25a7823e63139752506668eededae4d33b7" or 
		hash.sha1(0, filesize) == "0dceacd1eb6d25159bbf9408bfa0b75dd0eac181" or
		hash.sha1(0, filesize) == "1191ed22b3f3a7578e0cedf8993f6d647a7302b1" or
		hash.sha1(0, filesize) == "5fd47e23be3a2a2de526398c53bc27ebc4794e61" or
		hash.sha1(0, filesize) == "6b1b5d799bbc766f564c838c965baf2ca31502df" or
		hash.sha1(0, filesize) == "7eb5702f706e370ced910dd30f73fef3e725c2bb" or
		hash.sha1(0, filesize) == "7815c43edd431d6f0a96da8e166347f36ee9f932" or
		hash.sha1(0, filesize) == "a172738a91bada5967101e9d3d7ef2f7c058b75b" or
		hash.sha1(0, filesize) == "b350021f80ff6dacd31a53d8446d21e333e68790" or
		hash.sha1(0, filesize) == "eb876a4fd893fd54da1057d854f5043f6c144b67" or
		hash.sha1(0, filesize) == "3596070edc0badcf9e29f4b1172f00cebb863396" or
		hash.sha1(0, filesize) == "8cfce1b81e03242c36de4ad450f199f6f4d76841"
		)
}

rule QHostWBA
{
    meta:
        description = "OSX.QHostWB.A"
        xprotect_rule = true
    strings:
    	$a = {3C6B65793E434642756E646C654964656E7469666965723C2F6B65793E0A093C737472696E673E636F6D2E466C617368506C617965722E666C617368706C617965722E706B673C2F737472696E673E [-] 3C6B65793E4946506B67466C6167417574686F72697A6174696F6E416374696F6E3C2F6B65793E0A093C737472696E673E526F6F74417574686F72697A6174696F6E3C2F737472696E673E}

    condition:
		($a or hash.sha1(0, filesize) == "968430f1500fc475b6507f3c1d575714c785801a"
		)
}

rule RevirA
{
    meta:
        description = "OSX.Revir.A"
        xprotect_rule = true
    condition:
        Macho and (
        	hash.sha1(0, filesize) == "60b0ef03b65d08e4ea753c63a93d26467e9b953e"
        )
}

rule RevirB
{
    meta:
        description = "OSX.Revir.ii"
        xprotect_rule = true
    condition:
        Macho and filesize <= 50000 and (
            hash.sha1(0, filesize) == "20196eaac0bf60ca1184a517b88b564bf80d64b2"
        )
}

rule FlashbackA
{
    meta:
        description = "OSX.Flashback.A"
        xprotect_rule = true
    condition:
        filesize <= 200000 and (
        	hash.sha1(0, filesize) == "4cca20ffe6413a34176daab9b073bcd7f78a02b9" or
            hash.sha1(0, filesize) == "2b69d70a55e6effcabe5317334c09c83e8d615eb" or
            hash.sha1(0, filesize) == "bd5e541ee0aeba084f10b1149459db7898677e40" or
            hash.sha1(0, filesize) == "033de56ba7d4e5198838530c75c7570cd5996da8" or
            hash.sha1(0, filesize) == "a99f651cdcef3766572576c5dab58ba48c0819c0" or
            hash.sha1(0, filesize) == "6da26fd20abb4815c56f638924dc82cf6ca65caf" or
            hash.sha1(0, filesize) == "ffdcd8fb4697d4c88513b99cc748e73cf50f9186" or
            hash.sha1(0, filesize) == "026107095b367d7c1249ef7ad356ecd613ebe814" or
            hash.sha1(0, filesize) == "02a35e2ef3ccdf50d0755b27b42c21e8ce857d09"
        )
}

rule FlashbackB
{
    meta:
        description = "OSX.Flashback.B"
        xprotect_rule = true
    condition:
        filesize <= 200000 and (
            hash.sha1(0, filesize) == "fd7810b4458a583cca9c610bdf5a4181baeb2233" or
            hash.sha1(0, filesize) == "7004aec6b8193b8c3e8032d720dc121b23b921b7" or
            hash.sha1(0, filesize) == "b87a94ddd93fc036215056fbbed92380eefcadc2" or
            hash.sha1(0, filesize) == "3f40c8d93bc7d32d3c48eedacc0cd411cf273dba"
        ) or
        filesize <= 300000 and (
            hash.sha1(0, filesize) == "e266dd856008863704dd9af7608a58137d8936ba" or
            hash.sha1(0, filesize) == "7b6d5edf04a357d123f2da219f0c7c085ffa67fc" or
            hash.sha1(0, filesize) == "284484b13022e809956bb20b6ba741bd2c0a7117"
        )
}

rule FlashbackC
{
    meta:
        description = "OSX.Flashback.C"
        xprotect_rule = true
    condition:
        filesize <= 300000 and (
            hash.sha1(0, filesize) == "12f814ef8258caa2b84bf763af8333e738b5df76" or
            hash.sha1(0, filesize) == "131db26684cfa17a675f5ff9a67a82ce2864ac95" or
            hash.sha1(0, filesize) == "140fba4cafa2a3dff128c5cceeb12ce3e846fa2b" or
            hash.sha1(0, filesize) == "585e1e8aa48680ba2c4c159c6a422f05a5ca1e5c" or
            hash.sha1(0, filesize) == "392b6b110cec1960046061d37ca0368d1c769c65" or
            hash.sha1(0, filesize) == "b95a2a9a15a67c1f4dfce1f3ee8ef4429f86747c"
        )
}

rule DevilRobberA
{
    meta:
        description = "OSX.DevilRobber.A"
        xprotect_rule = true
    strings:
        $a = {504C4953545F4E414D453D2224484F4D452F4C6962726172792F4C61756E63684167656E74732F636F6D2E6170706C652E6C6567696F6E2E706C69737422 [-] 63686D6F64202B78202224484F4D452F244D41494E5F4449522F24455845435F4E414D4522 [-] 636F6D2E6170706C652E6C6567696F6E}
        $b = {3C6B65793E434642756E646C6545786563757461626C653C2F6B65793E [-] 3C737472696E673E707265666C696768743C2F737472696E673E}
    condition:
        (Macho and $a) or $b
}

rule DevilRobberB
{
    meta:
        description = "OSX.DevilRobber.B"
        xprotect_rule = true
    strings:
        $a = {455845435F4E414D453D [-] 53485F4E414D453D [-] 415243484956455F4E414D453D [-] 504C4953545F4E414D453D2224484F4D452F4C6962726172792F4C61756E63684167656E74732F636F6D2E6170706C652E6D6F707065722E706C697374220A [-] 63686D6F64202B78202224484F4D452F244D41494E5F4449522F24455845435F4E414D4522 [-] 63686D6F64202B78202224484F4D452F244D41494E5F4449522F645F73746172742E736822 [-] 3C737472696E673E636F6D2E6170706C652E6D6F707065723C2F737472696E673E}
    condition:
        $a
}

rule FileStealB
{
    meta:
        description = "OSX.FileSteal.ii"
        xprotect_rule = true
    condition:
        Macho and (
        	hash.sha1(0, filesize) == "1eedde872cc14492b2e6570229c0f9bc54b3f258"
        )
}

rule FileStealA
{
    meta:
        description = "OSX.FileSteal.i"
        xprotect_rule = true
    strings:
        $a = {46696C654261636B757041707044656C6567617465 [-] 5461736B57726170706572 [-] 2F7573722F62696E2F6375726C [-] 5A697055706C6F6164}
    condition:
        Macho and $a
}

rule MDropperA
{
    meta:
        description = "OSX.Mdropper.i"
        xprotect_rule = true
    strings:
        $a = {2F746D702F6C61756E63682D6873002F746D702F6C61756E63682D687365002F746D702F [-] 0023212F62696E2F73680A2F746D702F6C61756E63682D68736520260A6F70656E202F746D702F66696C652E646F6320260A0A [-] 00005F5F504147455A45524F00 [-] 005F5F6D685F657865637574655F686561646572}
    condition:
        $a
}

rule FkCodecA
{
    meta:
        description = "OSX.FkCodec.i"
        xprotect_rule = true
    strings:
        $a = {3C6B65793E6E616D653C2F6B65793E0A093C646963743E0A09093C6B65793E656E3C2F6B65793E0A09093C737472696E673E436F6465632D4D3C2F737472696E673E0A093C2F646963743E0A093C6B65793E76657273696F6E3C2F6B65793E}
    condition:
        $a 
}

rule MaControlA
{
    meta:
        description = "OSX.MaControl.i"
        xprotect_rule = true
    condition:
        Macho and filesize <= 110000 and (
        	hash.sha1(0, filesize) == "8a86ff808d090d400201a1f94d8f706a9da116ca"
        )
}

rule RevirC
{
    meta:
        description = "OSX.Revir.iii"
        xprotect_rule = true
    condition:
        Macho and (
            hash.sha1(0, filesize) == "265dafd0978c0b3254b1ac27dbedb59593722d2d"
        )
}

rule RevirD
{
    meta:
        description = "OSX.Revir.iv"
        xprotect_rule = true
    condition:
        Macho and (
            hash.sha1(0, filesize) == "782312db766a42337af30093a2fd358eeed97f53"
        )
}

rule SMSSendA
{
    meta:
        description = "OSX.SMSSend.i"
        xprotect_rule = true
    condition:
        Macho and (
        	hash.sha1(0, filesize) == "6c2b47384229eba6f398c74a0ba1516b3a674723"
        )
}

rule SMSSendB
{
    meta:
        description = "OSX.SMSSend.ii"
        xprotect_rule = true
    condition:
        Macho and (
            hash.sha1(0, filesize) == "a07d8497519404728f431aeec1cd35d37efc1cbb"
        )
}

rule EICAR
{
    meta:
        description = "OSX.eicar.com.i"
        xprotect_rule = true
    condition:
        hash.sha1(0, filesize) == "3395856ce81f2b7382dee72602f798b642f14140"
}

rule AdPluginA
{
    meta:
        description = "OSX.AdPlugin.i"
        xprotect_rule = true
    condition:
        hash.sha1(0, filesize) == "f63805148d85d8b757a50580bba11e02c192a2b8"
}

rule AdPluginB
{
    meta:
        description = "OSX.AdPlugin2.i"
        xprotect_rule = true
    condition:
        hash.sha1(0, filesize) == "fe59a309e5689374dba50bc7349d62148f1ab9aa"
}

rule LeverageA
{
    meta:
        description = "OSX.Leverage.a"
        xprotect_rule = true
    condition:
        Macho and (
        	hash.sha1(0, filesize) == "41448afcb7b857866a5f6e77d3ef3a393598f91e"
        )
}

rule PrxlA
{
    meta:
        description = "OSX.Prxl.2"
        xprotect_rule = true
    condition:
        Macho and (
        	hash.sha1(0, filesize) == "edff0cd0111ee1e3a85dbd0961485be1499bdb66" or
            hash.sha1(0, filesize) == "429ed6bced9bb18b95e7a5b5de9a7b023a2a7d2c" or
            hash.sha1(0, filesize) == "f1a32e53439d3adc967a3b47f9071de6c10fce4e"
        )
}

