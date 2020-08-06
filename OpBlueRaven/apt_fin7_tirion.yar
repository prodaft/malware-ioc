import "pe"
rule apt_Fin7_Tirion_plugins
{

    meta:
        author = "Yusuf Arslan POLAT"
        description = "Tirion Loader's plugins. It is used by Fin7 group. Need manual verification"
        version = "1.0"
        date = "2020-07-22"    
        reference = "https://threatintelligence.blog/"
        copyright = "PRODAFT"
        SHA256 = "fdc0ec0cc895f5b0440d942c0ab60eedeb6e6dca64a93cecb6f1685c0a7b99ae"
   
    strings:
        $a1 = "ReflectiveLoader" ascii
        $a2 = "plg.dll" fullword ascii
    condition:
        uint16(0) == 0x5A4D  and (all of ($a*)) and filesize < 15000 and (pe.exports("?ReflectiveLoader@@YA_KPEAX@Z") or
            pe.exports("?ReflectiveLoader@@YGKPAX@Z"))
}

rule apt_Fin7_Tirion_PswInfoGrabber
{

    meta:
        author = "Yusuf Arslan POLAT"
        description = "Tirion Loader's PswInfoGrabber plugin. It is used by Fin7 group."
        version = "1.0"
        date = "2020-07-22"    
        reference = "https://threatintelligence.blog/"
        copyright = "PRODAFT"
        SHA256 = "e7d89d1f23c2c31e2cd188042436ce6d83dac571a5f30e76cbbcdfaf51e30ad9"
   
    strings:
        $a1 = "IE/Edge Grabber Begin" fullword ascii
        $a2 = "Mail Grabber Begin" fullword ascii
        $a3 = "PswInfoGrabber" ascii
        $a4 = "Chrome Login Profile: '"
        $a5 = "[LOGIN]:[HOST]:"
    condition:
        uint16(0) == 0x5A4D  and (all of ($a*)) and filesize < 150KB
}

rule apt_Fin7_Tirion_loader
{

    meta:
        author = "Yusuf Arslan POLAT"
        description = "Tirion Loader's loader component. It is used by Fin7 group."
        version = "1.0"
        date = "2020-07-22"    
        reference = "https://threatintelligence.blog/"
        copyright = "PRODAFT"
        SHA256 = "429adaf706bd0829e1a8de7bf0ea544a41b01a383dab3db26a14cc4a287b6881"
   
    strings:
        $a1 = "HOST_PORTS" fullword ascii
        $a2 = "KEY_PASSWORD" fullword ascii
        $a3 = "HOSTS_CONNECT" ascii
        $a4 = "SystemFunction036"
        $a5 = "ReflectiveLoader"
    condition:
        uint16(0) == 0x5A4D  and (all of ($a*)) and filesize < 15KB
}