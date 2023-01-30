# LockBit Green Indicators of Compromise (IOC)

These IOCs were released as part of PTI team research.

## LockBit Green Hashes

| MD5                              | SHA1                                     | SHA256                                                           |
| :------------------------------- | ---------------------------------------- | ---------------------------------------------------------------- |
| 730f72a73ff216d15473d2789818f00c | ca94159bdb17051a6cce8a5deeee89942c9154b9 | 27b8ee04d9d59da8e07203c0ab1fc671215fb14edb35cb2e3122c1c0df83bff8 |
| aacef4e2151c264dc30963823bd3bb17 | 9492c378a14e9606157145d49e35a9841383121d | 45c317200e27e5c5692c59d06768ca2e7eeb446d6d495084f414d0f261f75315 |
| 37355f4fd63e7abd89bdc841ed98229f | a8d46a042e6095d7671dbac2aeff74c7bb5e792a | b3ea0f4f442da3106c0d4f97cf20e244b84d719232ca90b3b7fc6e59e37e1ca1 |
| ea34ac6bf9e8a70bec84e37afeea458a | fd443460ccd1110b0a77385f2f66a38d3f527966 | fb49b940570cfd241dea27ae768ac420e863d9f26c5d64f0d10aea4dd0bf0ce3 |

## LockBit Green Yara Rule
```
rule LockBit_Green {
    meta:
        author = "PRODAFT"
        description = "LockBit Green detector (x32/x64)"
        date = "2023-01-30"
        rule_version = "v1"
        malware_type = "ransomware"
        tlp = "White"

    strings:
        $ransom_extension = {80 b6 98 68 63 00 78 ba 0f 00 00 00 6a 6a 68 ?? ?? ?? ?? 46 e8 ?? ?? ?? ?? 83 c4 08 68 ?? ?? ?? ?? ff d0 3b f0 72 ??}
        $api_hashing_arithmetic = {42 0F B6 4C 05 AC B8 75  00 00 00 2B C1 8D 0C 80 B8 09 04 02 81 C1 E1 03  F7 E9 03 D1 C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2  7F 2B C8 B8 09 04 02 81 83 C1 7F F7 E9 03 D1 C1  FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F 2B}
        $api_hashing_arithmetic_2 = {8A 44 34 15 B9 4B 00 00  00 0F B6 C0 2B C8 6B C1 1B 99 F7 FF 8D 42 7F 99  F7 FF 88 54 34 15}
        $api_hashing_arithmetic_3 = {8a 44 0d ad 0f b6 c0  83 e8 06 6b c0 19 99 f7 ff 8d 42 7f 99 f7 ff 88 54 0d ad}
        $api_hashing_arithmetic_4 = {42 0F B6 4C 05 E1 B8 39  00 00 00 2B C1 8D 0C 80 B8 09 04 02 81 C1 E1 03  F7 E9 03 D1 C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2  7F 2B C8 B8 09 04 02 81 83 C1 7F F7 E9 03 D1 C1  FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F 2B C8 42 88  4C 05 E1}

    condition:
        any of them and filesize < 260KB
}
```
