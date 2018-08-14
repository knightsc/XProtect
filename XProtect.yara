import "hash"

private rule Macho
{
    meta:
        description = "private rule to match Mach-O binaries"
    condition:
        uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca

}

rule XProtect_OSX_ATG15_B
{
    meta:
        description = "OSX.ATG15.B"
        xprotect_rule = true
    strings:
        $a1 = { 80 7C 39 3C 32 BA BB 80 F3 B9 B4 34 B8 34 39 80 }
        $a2 = { FC BF 34 BA 7C BA 34 36 B9 BC BA 3C 80 7C 39 3C }
        $a3 = { 32 BA BB 76 BA 34 3C B9 BF B7 8F 30 B3 B9 3C 32 }
        $b1 = { 9C 85 89 27 8B 9C 85 89 27 8B 9C 85 89 27 8B 9C }
    condition:
      Macho and filesize < 200KB and all of them
}

rule XProtect_OSX_Genieo_G
{
    meta:
        description = "OSX.Genieo.G"

    strings:        
        $a1 = {67 65 74 53 61 66 61 72 69 48 69 73 74 6F 72 79}
        $a2 = {69 6E 73 74 61 6C 6C 2F 67 65 74 5F 73 69 6E 67 6C 65 5F 62 72 6F 77 73 65 72 3F 73 65 73 73 69 6F 6E 5F 69 64 3D 25 40 26 65 6D 69 64 3D 25 40 26 6F 73 5F 76 65 72 73 69 6F 6E 3D 25 40 25 40 26 64 6F 77 6E 6C 6F 61 64 5F 75 72 6C}
        $a3 = {41 70 70 49 6E 73 74 61 6C 6C 65 72}
        
    condition:
        Macho and filesize < 2000000 and
        (all of ($a*))
}

rule XProtect_OSX_Proton_B
{
    meta:
        description = "OSX.Proton.B"
        
    condition:
        Macho and filesize < 800000 and hash.sha1(0, filesize) == "a8ea82ee767091098b0e275a80d25d3bc79e0cea"
}

rule XProtect_OSX_Dok_B
{
    meta:
        description = "OSX.Dok.B"

    strings:
        $a1 = {53 65 6C 66 49 6E 73 74 61 6C 6C}
        $a2 = {49 73 4C 6F 67 69 6E 53 63 72 69 70 74 45 78 69 73 74 73}
        $a3 = {41 64 64 4C 6F 67 69 6E 53 63 72 69 70 74}
        
        $b1 = {49 79 45 76 64 58 4E 79 4C 32 4A 70 62 69 39 6C 62 6E 59 67 63 48 6C 30 61 47 39 75 43 69 4D 67 4C 53 6F 74 49 47 4E 76 5A 47 6C 75 5A 7A 6F 67 64 58 52 6D 4C 54 67 67 4C 53 6F 74 43 6D 6C 74 63}
    condition:
        Macho and filesize < 600000 and filesize > 10000 and all of them
}

rule XProtect_OSX_Dok_A
{
    meta:
        description = "OSX.Dok.A"

    strings:
        $a1 = {49 73 4C 6F 67 69 6E 53 63 72 69 70 74 45 78 69 73 74 73}
        $a2 = {43 6C 6F 73 65 41 6C 6C 42 72 6F 77 73 65 72 73}

        $b1 = {73 65 63 75 72 69 74 79 20 61 64 64 2D 74 72 75 73 74 65 64 2D 63 65 72 74 20 2D 64 20 2D 72 20 74 72 75 73 74 52 6F 6F 74 20 2D 6B 20 2F 4C 69 62 72 61 72 79 2F 4B 65 79 63 68 61 69 6E 73 2F 53 79 73 74 65 6D 2E 6B 65 79 63 68 61 69 6E}
        $b2 = {74 63 70 34 2D 4C 49 53 54 45 4E 3A 35 35 35 35 2C 72 65 75 73 65 61 64 64 72 2C 66 6F 72 6B 2C 6B 65 65 70 61 6C 69 76 65 2C 62 69 6E 64 3D 31 32 37 2E 30 2E 30 2E 31}

    condition:
        Macho and filesize < 60000 and all of them
}

rule OSX_Bundlore_A
{
    meta:
            description = "OSX.Bundlore.A"
            
    strings:
            $a1 = { 4F 66 66 65 72 73 49 6E 73 74 61 6C 6C 53 63 72 69 70 74 55 72 6C }
            $a2 = { 53 6F 66 74 77 61 72 65 49 6E 73 74 61 6C 6C 53 63 72 69 70 74 55 72 6C }
            $a3 = { 63 6F 6D 2E 67 6F 6F 67 6C 65 2E 43 68 72 6F 6D 65 }
            $a4 = { 2E 74 6D 70 6D 61 }
            $a5 = { 50 6C 65 61 73 65 20 77 61 69 74 20 77 68 69 6C 65 20 79 6F 75 72 20 73 6F 66 74 77 61 72 65 20 69 73 20 62 65 69 6E 67 20 69 6E 73 74 61 6C 6C 65 64 2E 2E 2E }
    condition:
            filesize < 500000 and Macho and 4 of ($a*)
}

rule OSX_Findzip_A {
  meta:
    description = "OSX.Findzip.A"

  strings:
	$a = {54 6b 39 55 49 46 6c 50 56 56 49 67 54 45 46 4f 52 31 56 42 52 30 55 2f 49 46 56 54 52 53 42 6f 64 48 52 77 63 7a 6f 76 4c 33 52 79 59 57 35 7a 62 47 46 30 5a 53 35 6e 62 32 39 6e 62 47 55 75 59 32 39 74 44 51 6f 4e 43 6c 64 6f 59 58 51 67 61 47 46 77 63 47 56 75 5a 57 51 67 64 47 38 67 65 57 39 31 63 69 42 6d 61 57 78 6c 63 79 41 2f 44 51 70}
	$b1 = {2f 75 73 72 2f 62 69 6e 2f 66 69 6e 64}
	$b2 = {7b 7d 2e 63 72 79 70 74}
	$b3 = {52 45 45 41 44 4d 45 21 2e 74 78 74}
    $b4 = {2f 75 73 72 2f 62 69 6e 2f 64 69 73 6b 75 74 69 6c}

  condition:
    filesize < 100000 and Macho and ($a or (all of ($b*)))
}

rule OSX_Proton_A
{
    meta:
            description = "OSX.Proton.A"
           
    strings:
            $a1 = {4E 65 74 77 6F 72 6B 20 43 6F 6E 66 69 67 75 72 61 74 69 6F 6E 20 6E 65 65 64 73 20 74 6F 20 75 70 64 61 74 65 20 44 48 43 50 20 73 65 74 74 69 6E 67 73 2E 20 54 79 70 65 20 79 6F 75 72 20 70 61 73 73 77 6F 72 64 20 74 6F 20 61 6C 6C 6F 77 20 74 68 69 73 2E}
            $a2 = {49 6E 73 74 61 6C 6C 65 72 20 77 61 6E 74 73 20 74 6F 20 6D 61 6B 65 20 63 68 61 6E 67 65 73 2E 20 54 79 70 65 20 79 6F 75 72 20 70 61 73 73 77 6F 72 64 20 74 6F 20 61 6C 6C 6F 77 20 74 68 69 73}
            $b1 = {66 69 6C 65 5F 75 70 6C 6F 61 64}
            $b2 = {73 73 68 5F 74 75 6E 6E 65 6C}
            $b3 = {64 6F 77 6E 6C 6F 61 64 5F 66 69 6C 65}
            $b4 = {65 78 65 63 5F 70 75 73 68}
            $b5 = {66 76 5F 61 63 74 69 6F 6E}
    condition:
      Macho and filesize < 200000 and all of ($b*) and any of ($a*)
}

rule OSX_XAgent_A
{
    meta:
        description = "OSX.XAgent.A"

    strings:
        $a = {49 0F BE 14 07 41 8D 45 FD 49 0F BE 34 07 41 8D 7D FF 41 8D 45 FE 49 0F BE 1C 07 48 83 FB 3D B8 00 00 00 00 B9 01 00 00 00 74 0A 42 0F B6 04 33 B9 02 00 00 00 42 8A 1C 32 42 0F B6 34 36 89 FA 49 0F BE 3C 17 45 31 C0 48 83 FF 3D 74 0E 46 0F B6 04 37 41 83 E0 3F B9 03 00 00 00 C0 E3 02 40 88 F2 C0 EA 04 80 E2 03 08 DA 88 55 D5 C1 E6 04 89 C2 C1 EA 02 83 E2 0F 09 F2 88 55 D6 C1 E0 06 44 09 C0 88 45 D7 4C 89 E7}

        $s1 = {53 45 4C 45 43 54 20 68 6F 73 74 6E 61 6D 65 2C 20 65 6E 63 72 79 70 74 65 64 55 73 65 72 6E 61 6D 65 2C 20 65 6E 63 72 79 70 74 65 64 50 61 73 73 77 6F 72 64}
        $s2 = {72 6D 20 2D 72 66 20 25 40 2F 4C 69 62 72 61 72 79 2F 41 73 73 69 73 74 61 6E 74 73 2F 2E 6C 6F 63 61 6C 2F}

    condition:
        Macho and filesize < 400000 and ((all of ($s*)) and $a)
}

rule OSX_iKitten_A
{
    meta:
        description = "OSX.iKitten.A"
        
    strings:
        $a = {48 83 F8 00 48 89 85 C0 FE FF FF 0F 84 FC 01 00 00 31 C0 89 C1 48 8D 95 F0 FE FF FF 48 83 C2 10 48 8B B5 00 FF FF FF 48 8B 36 48 8B BD C0 FE FF FF 48 89 B5 B8 FE FF FF 48 89 95 B0 FE FF FF 48 89 8D A8 FE FF FF 48 89 BD A0 FE FF FF 48 8B 85 A0 FE FF FF 48 8B 8D A8 FE FF FF 48 8B 95 B0 FE FF FF 48 8B 32 48 8B BD B8 FE FF FF 48 39 3E 48 89 85 98 FE FF FF 48 89 8D 90 FE FF FF 0F 84 0F 00 00 00 48 8B 85 C8 FE FF FF 48 89 C7}
        $b = {48 89 45 E0 48 8B 3D 80 38 03 00 48 8B 35 E9 33 03 00 41 B8 04 00 00 00 44 89 C1 45 31 C0 44 89 C2 48 89 55 C0 48 89 C2 48 89 4D B8 4C 8B 45 C0 48 8B 45 C8 ?? ?? 48 89 C7 ?? ?? ?? ?? ?? 48 89 45 D8 48 8B 35 4A 34 03 00 48 8D 15 13 18 03 00 48 8D 0D 6C 17 03 00 48 89 C7 48 8B 45 C8 ?? ?? 48 89 C7}

        $s1 = {69 66 20 63 61 74 20 2F 65 74 63 2F 72 63 2E 63 6F 6D 6D 6F 6E 20 7C 20 67 72 65 70 20 25 40 3B}
        $s2 = {7A 69 70 20 2D 72 20 2D 6A 20 25 40 20 25 40}

    condition:
        Macho and filesize < 400000 and $a and $b and (all of ($s*))
}

rule OSX_HMining_C
{
    meta:
        description = "OSX.HMining.C"
    strings:
        $a1 = {55 48 89 E5 41 57 41 56 53 50 4C 8B 7F 48 4C 8B 77 50 48 8B 5F 58 48 89 DF ?? ?? ?? ?? ?? 4C 89 FF 4C 89 F6 48 89 DA ?? ?? ?? ?? ?? 48 89 C7 48 83 C4 08 5B 41 5E 41 5F 5D}
        $a2 = {55 48 89 E5 41 57 41 56 41 54 53 41 89 CE 48 89 D3 48 89 DF ?? ?? ?? ?? ?? 48 89 DF ?? ?? ?? ?? ?? 48 89 CB 48 89 C7 48 89 D6 48 89 DA 44 89 F1 ?? ?? ?? ?? ?? 49 89 C6 49 89 D7 49 89 CC 48 89 DF ?? ?? ?? ?? ?? 4C 89 F7 4C 89 FE 4C 89 E2 ?? ?? ?? ?? ?? 48 89 C7 5B 41 5C 41 5E 41 5F 5D}
    condition:
        Macho and filesize <= 600000 and
        all of ($a*)
}

rule HMiningB
{
    meta:
        description = "OSX.HMining.B"
    strings:
        $a1 = {48 89 C7 41 FF D6 48 89 85 E8 FE FF FF 0F 57 C0 0F 29 85 40 FF FF FF 0F 29 85 30 FF FF FF 0F 29 85 20 FF FF FF 0F 29 85 10 FF FF FF ?? ?? ?? ?? ?? ?? ?? 48 8D 95 10 FF FF FF 48 8D 8D 50 FF FF FF 41 B8 10 00 00 00 48 89 C7 41 FF D6 48 89 85 08 FF FF FF 48 85 C0 B8 00 00 00 00 48 89 85 D8 FE FF FF 0F 84 44 01 00 00 48 8B 85 20 FF FF FF 48 8B 00 48 89 85 F8 FE FF FF}
        $a2 = {48 89 DF ?? ?? ?? 49 89 C4 4C 89 65 B8 ?? ?? ?? ?? ?? ?? ?? BA 04 00 00 00 4C 89 F7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 C7 ?? ?? ?? 48 89 45 C8 ?? ?? ?? ?? ?? ?? ?? 48 89 DF 41 FF D7 4C 89 F9 48 85 C0 74 59 ?? ?? ?? ?? ?? ?? ?? 45 31 FF 45 31 F6 4C 8B 6D C8 41 8A 45 00 43 30 04 3C 49 FF C5 41 FF C6 4D 63 F6 48 8B 7D C0 48 89 DE 49 89 CC 41 FF D4 49 39 C6 4C 0F 44 6D C8 B8 00 00 00 00 44 0F 44 F0 49 FF C7 48 8B 7D D0 48 89 DE 41 FF D4 4C 89 E1 4C 8B 65 B8 49 39 C7 72 B8 48 8B 45 D0 48 83 C4 28 5B 41 5C 41 5D 41 5E 41 5F 5D C3 }
    condition:
        Macho and filesize <= 500000 and all of ($a*)
}

rule NetwireA
{
	meta:
		description = "OSX.Netwire.A"
	strings:
		$a = { 03 04 15 1A 0D 0A 65 78 69 74 0D 0A 0D 0A 65 78 69 74 0A 0A 00 }
		$b = { 55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 33 3B 20 57 4F 57 36 34 3B 20 54 72 69 64 65 6E 74 2F 37 2E 30 3B 20 72 76 3A 31 31 2E 30 29 20 6C 69 6B 65 20 47 65 63 6B 6F 0D 0A 41 63 63 65 70 74 3A 20 74 65 78 74 2F 68 74 6D 6C 2C 61 70 70 6C 69 63 61 74 69 6F 6E 2F 78 68 74 6D 6C 2B 78 6D 6C 2C 61 70 70 6C 69 63 61 74 69 6F 6E 2F 78 6D 6C 3B 71 3D 30 2E 39 2C 69 6D 61 67 65 2F 77 65 62 70 2C 2A 2F 2A 3B 71 3D 30 2E 38 }

	condition:
		all of them		
}

rule BundloreB
{
    meta:
        description = "OSX.Bundlore.B"
    strings:
        $a = {5F 5F 4D 41 5F 41 70 70 44 65 6C 65 67 61 74 65}
        $b = {5F 5F 4D 41 5F 44 65 74 65 63 74 65 64 50 72 6F 64 75 63 74 73 48 61 6E 64 6C 65 72}
        $c = {5F 5F 4D 41 5F 44 6D 67 53 6F 75 72 63 65 52 65 61 64 65 72}
    condition:
        2 of ($a,$b,$c)
}

rule EleanorA
{
    meta:
        description = "OSX.Eleanor.A"
    condition:
        filesize <= 3500 and uint8(0) == 0x23 and 
        (
            hash.sha1(0, filesize) == "de642751e96b8c53744f031a6f7e929d53226321" or
            hash.sha1(0, filesize) == "1f782e84ddbf5fd76426f6f9bf3d4238d2ec9a4b"
        )
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

rule OSX_Genieo_F
{
    meta:
        description = "OSX.Genieo.F"
    strings:
        $a1 = {72 65 6D 6F 76 65 58 61 74 74 72 54 6F}
        $a2 = {67 65 74 43 72 79 70 74 65 64 44 61 74 61 46 72 6F 6D 55 72 6C}
        $a3 = {67 65 74 42 65 73 74 4F 66 66 65 72 43 6F 6E 66 69 67 3A 61 63 63 65 70 74 65 64 4F 66 66 65 72 73}
        $b1 = {53 61 66 61 72 69 45 78 74 65 6E 73 69 6F 6E 49 6E 73 74 61 6C 6C 65 72}
        $b2 = {54 61 72 43 6F 6D 70 72 65 73 73 6F 72}
    condition:
        Macho and filesize < 2500000 and all of them
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
        $c = {49 6E 73 74 61 6C 6C 4D 61 63 41 70 70 44 65 6C 65 67 61 74 65}
    condition:
        ($a or $b) and $c
}

rule GenieoC
{
    meta:
        description = "OSX.Genieo.C"
    condition:
        Macho and filesize <= 500000 and 
        hash.sha1(0, filesize) == "a3e827031f1466444272499ef853484bac1eb90b"
}

rule GenieoB
{
    meta:
        description = "OSX.Genieo.B"
    condition:
        Macho and filesize <= 600000 and
       (hash.sha1(0, filesize) == "495735da5fb582b93d90fff2c8b996d25e21aa31" or hash.sha1(0, filesize) == "0e196c0677bf6f94411229defc94639dd1b62b76")
}

rule VindinstallerA
{
    meta:
        description = "OSX.Vindinstaller.A"
    condition:
        Macho and filesize <= 1200000 and
        hash.sha1(0, filesize) == "c040eee0f0d06d672cbfca94f2cbfc19795dd98d"
}

rule OpinionSpyB
{
    meta:
        description = "OSX.OpinionSpy.B"
    condition:
		filesize <= 9000000 and hash.sha1(0, filesize) == "a0d0b9d34f07c7d99852b9b833ba8f472bb56516"
}

rule GenieoA
{
	meta:
        description = "OSX.Genieo.A"
    condition:
        Macho and filesize <= 400000 and
        hash.sha1(0, filesize) == "d07341c08173d0e885e6cafd7d5c50ebde07b205"
}

rule InstallImitatorC
{
	meta:
        description = "OSX.InstallImitator.C"
    condition:
        Macho and filesize <= 400000 and 
        hash.sha1(0, filesize) == "eeac1275e018e886b3288daae7b07842aec57efd"
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
        Macho and filesize <= 800000 and
        (
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
        Macho and filesize <= 2000000 and 
        (
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
        Macho and filesize <= 40000 and 
        (
        	hash.sha1(0, filesize) == "e2b9578780ae318dbdb949aac32a7dde6c77d918" or
        	hash.sha1(0, filesize) == "bb8cbc2ab928d66fa1f17e02ff2634ad38a477d6"
        )
}

rule MachookB
{
    meta:
        description = "OSX.Machook.B"
    condition:
        Macho and filesize <= 100000 and 
        (
            hash.sha1(0, filesize) == "ae3e35f8ac6a2a09abdb17dbce3874b9fd9a7b7b"
        )
}

rule IWormA
{
    meta:
        description = "OSX.iWorm.A"
        xprotect_rule = true
    condition:
        Macho and filesize <= 200000 and 
        (
        	hash.sha1(0, filesize) == "c0800cd5095b28da4b6ca01468a279fb5be6921a"
        )
}

rule IWormBC
{
    meta:
        description = "OSX.iWorm.B/C"
        xprotect_rule = true
    condition:
        filesize <= 500 and hash.sha1(0, filesize) == "5e68569d32772a479dfa9e6a23b2f3ae74b2028f"
        
}

rule NetWeirdB
{
    meta:
        description = "OSX.NetWeird.ii"
        xprotect_rule = true
    condition:
        Macho and filesize <= 200000 and
        (
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
        Macho and filesize <= 200000 and 
        (
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
        Macho and filesize <= 21000 and 
        (
        	hash.sha1(0, filesize) == "112d4e785e363abfec51155a5536c072a0da4986"
        )
}

rule LaoShuA
{
    meta:
        description = "OSX.LaoShu.A"
        xprotect_rule = true
    condition:
        Macho and filesize <= 50000 and 
        (
        	hash.sha1(0, filesize) == "2e243393a4e997d53d3d80516571a64f10313116"
        )
}

rule AbkA
{
    meta:
        description = "OSX.Abk.A"
        xprotect_rule = true
    condition:
        Macho and filesize <= 250000 and
        (
        	hash.sha1(0, filesize) == "3edb177abc8934fdc7d537f5115bb4fb6ab41c3f"
        )
}

rule CoinThiefA
{
    meta:
        description = "OSX.CoinThief.A"
        xprotect_rule = true
    condition:
        filesize <= 350000 and (
        	hash.sha1(0, filesize) == "37c4bc94f2c08e90a47825fe7b2afbce908b5d74"
        )
}

rule CoinThiefB
{
    meta:
        description = "OSX.CoinThief.B"
        xprotect_rule = true
    condition:
        filesize <= 3000000 and (
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
        Macho and filesize <= 29000 and   
        (
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
	filesize <= 100000 and
        hash.sha1(0, filesize) == "797d7b60081368e50cb7d89c5d51c5d267a88a88" or
        hash.sha1(0, filesize) == "a8afa8e646bd6a02cfaa844735b94c50820bb9f5" or
        hash.sha1(0, filesize) == "0ba58f54b44b2ee8a1f149e1a686deeedebb79ba" or
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
		filesize <= 1000000 and
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
		filesize <= 15000 and ($a or hash.sha1(0, filesize) == "968430f1500fc475b6507f3c1d575714c785801a"
		)
}

rule RevirA
{
    meta:
        description = "OSX.Revir.A"
        xprotect_rule = true
    condition:
        Macho and filesize <= 300000 and 
        (
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
        Macho and filesize <= 115000 and 
        (
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
        Macho and filesize <= 25000 and 
        (
            hash.sha1(0, filesize) == "265dafd0978c0b3254b1ac27dbedb59593722d2d"
        )
}

rule RevirD
{
    meta:
        description = "OSX.Revir.iv"
        xprotect_rule = true
    condition:
        Macho and filesize <= 40000 and 
        (
            hash.sha1(0, filesize) == "782312db766a42337af30093a2fd358eeed97f53"
        )
}

rule SMSSendA
{
    meta:
        description = "OSX.SMSSend.i"
        xprotect_rule = true
    condition:
        Macho and filesize <= 15000000 and 
        (
        	hash.sha1(0, filesize) == "6c2b47384229eba6f398c74a0ba1516b3a674723"
        )
}

rule SMSSendB
{
    meta:
        description = "OSX.SMSSend.ii"
        xprotect_rule = true
    condition:
        Macho and filesize <= 15000000 and (
            hash.sha1(0, filesize) == "a07d8497519404728f431aeec1cd35d37efc1cbb"
        )
}

rule EICAR
{
    meta:
        description = "OSX.eicar.com.i"
        xprotect_rule = true
    condition:
        filesize <= 100000000 and hash.sha1(0, filesize) == "3395856ce81f2b7382dee72602f798b642f14140"
}

rule AdPluginA
{
    meta:
        description = "OSX.AdPlugin.i"
        xprotect_rule = true
    condition:
        filesize <= 500000 and hash.sha1(0, filesize) == "f63805148d85d8b757a50580bba11e02c192a2b8"
}

rule AdPluginB
{
    meta:
        description = "OSX.AdPlugin2.i"
        xprotect_rule = true
    condition:
        filesize <= 40000 and hash.sha1(0, filesize) == "fe59a309e5689374dba50bc7349d62148f1ab9aa"
}

rule LeverageA
{
    meta:
        description = "OSX.Leverage.a"
        xprotect_rule = true
    condition:
        Macho and filesize <= 2500000 and 
        (
        	hash.sha1(0, filesize) == "41448afcb7b857866a5f6e77d3ef3a393598f91e"
        )
}

rule PrxlA
{
    meta:
        description = "OSX.Prxl.2"
        xprotect_rule = true
    condition:
        Macho and filesize <= 24000 and 
        (
            hash.sha1(0, filesize) == "edff0cd0111ee1e3a85dbd0961485be1499bdb66" or
            hash.sha1(0, filesize) == "429ed6bced9bb18b95e7a5b5de9a7b023a2a7d2c" or
            hash.sha1(0, filesize) == "f1a32e53439d3adc967a3b47f9071de6c10fce4e"
        )
}



