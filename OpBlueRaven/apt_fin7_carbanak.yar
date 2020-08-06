rule apt_Fin7_Carbanak_keylogplugin  
{

    meta:
        author = "Yusuf Arslan POLAT"
        description = "Carbanak backdoor's keylogger plugin. It is used by Fin7 group"
        version = "1.0"
        date = "2020-07-21"    
        reference = "https://threatintelligence.blog/"
        copyright = "PRODAFT"
        SHA256 = "db486e0cb94cf2bbe38173b7ce0eb02731ad9a435a04899a03d57b06cecddc4d"
   
    strings:
        $a1 = "SA45E91.tmp" fullword ascii
        $a2 = "%02d.%02d.%04d %02d:%02d" fullword ascii
        $a3 = "Event time:" fullword ascii
        $a4 = "MY_CLASS" fullword ascii
        $a5 = "RegisterRawInputDevices" fullword ascii 

    condition:
        uint16(0) == 0x5A4D  and (all of ($a*)) and filesize < 15000
}

rule apt_Fin7_Carbanak_procmonplugin  
{

    meta:
        author = "Yusuf Arslan POLAT"
        description = "Carbanak backdoor's process monitoring plugin. It is used by Fin7 group"
        version = "1.0"
        date = "2020-07-21"    
        reference = "https://threatintelligence.blog/"
        copyright = "PRODAFT"
        SHA256 = "3bf8610241a808e85e6ebaac2bb92ba4ae92c3ec1a6e56e21937efec71ea5425"
   
    strings:
        $a1 = "[%02d.%02d.%04d %02d:%02d:%02d]" fullword ascii
        $a2 = "%s open %s" fullword ascii
        $a3 = "added monitoring %s" fullword ascii
        $a4 = "pm.dll" fullword ascii
        $a5 = "CreateToolhelp32Snapshot" fullword ascii  

    condition:
        uint16(0) == 0x5A4D  and (all of ($a*)) and filesize < 10000
}

rule apt_Fin7_Carbanak_hdplugin  
{

    meta:
        author = "Yusuf Arslan POLAT"
        description = "Carbanak backdoor's hidden desktop plugin. It is used by Fin7 group"
        version = "1.0"
        date = "2020-07-21"    
        reference = "https://threatintelligence.blog/"
        copyright = "PRODAFT"
        SHA256 = "39b545c7cd26258a9e45923053a5a64c9461470c3d7bfce3be1c776b287e8a95"
   
    strings:
        $a1 = "hd%s%s" fullword ascii
        $a2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" fullword ascii
        $a3 = "StartHDServer" fullword ascii
        $a4 = "SetThreadDesktop" fullword ascii
    condition:
        uint16(0) == 0x5A4D  and (all of ($a*)) and filesize < 15000
}
rule apt_Fin7_Carbanak_hvncplugin  
{

    meta:
        author = "Yusuf Arslan POLAT"
        description = "Carbanak backdoor's hvnc plugin. It is used by Fin7 group"
        version = "1.0"
        date = "2020-07-21"    
        reference = "https://threatintelligence.blog/"
        copyright = "PRODAFT"
        SHA256 = "40ce820df679b59476f5d277350dca43e3b3f8cac7ec47ad638371aaa646c315"
   
    strings:
        $a1 = "VncStartServer" fullword ascii
        $a2 = "VncStopServer" fullword ascii
        $a3 = "RFB 003.008" fullword ascii
        $a4 = "-nomerge -noframemerging" fullword ascii
        $a5 = "--no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11" fullword wide
    condition:
        uint16(0) == 0x5A4D  and (all of ($a*)) and filesize < 300000
}

rule apt_Fin7_Carbanak_vncplugin  
{

    meta:
        author = "Yusuf Arslan POLAT"
        description = "Carbanak backdoor's vnc plugin. It is used by Fin7 group"
        version = "1.0"
        date = "2020-07-21"    
        reference = "https://threatintelligence.blog/"
        copyright = "PRODAFT"
        SHA256 = "ecf3679f659c5a1393b4a8b7d7cca615c33c21ab525952f8417c2a828697116a"
   
    strings:
        $a1 = "VncStartServer" fullword ascii
        $a2 = "VncStopServer" fullword ascii
        $a3 = "ReflectiveLoader" fullword ascii
        $a4 = "IDR_VNC_DLL" fullword ascii
    condition:
        uint16(0) == 0x5A4D  and (all of ($a*)) and filesize < 400000
}

rule apt_Fin7_Carbanak_rdpplugin  
{

    meta:
        author = "Yusuf Arslan POLAT"
        description = "Carbanak backdoor's rdp plugin. It is used by Fin7 group"
        version = "1.0"
        date = "2020-07-21"    
        reference = "https://threatintelligence.blog/"
        copyright = "PRODAFT"
        SHA256 = "0d3f1696aae8472145400d6858b1c44ba7532362be5850dae2edbd4a40f36aa5"
   
    strings:
        $a1 = "sdbinst.exe" fullword ascii
        $a2 = "-q -n \"UAC\"" fullword ascii
        $a3 = "-q -u \"%s\"" fullword ascii
        $a4 = "test.txt" fullword ascii
        $a5 = "install" fullword ascii
        $a6 = "uninstall" fullword ascii
    condition:
        uint16(0) == 0x5A4D  and (all of ($a*)) and filesize < 400000
}

rule apt_Fin7_Carbanak_switcherplugin  
{

    meta:
        author = "Yusuf Arslan POLAT"
        description = "Carbanak backdoor's switcher plugin. It is used by Fin7 group"
        version = "1.0"
        date = "2020-07-21"    
        reference = "https://threatintelligence.blog/"
        copyright = "PRODAFT"
        SHA256 = "d470da028679ca8038b062f9f629d89a994c79d1afc4862104611bb36326d0c8"
   
    strings:
        $a1 = "iiGI1E05.tmp" fullword ascii
        $a2 = "oCh4246.tmp" fullword ascii
        $a3 = "inf_start" fullword ascii
        $a4 = "Shell_TrayWnd" fullword ascii
        $a5 = "ReadDirectoryChangesW" fullword ascii
        $a6 = "CreateToolhelp32Snapshot" fullword ascii
    condition:
        uint16(0) == 0x5A4D  and (all of ($a*)) and filesize < 15000
}