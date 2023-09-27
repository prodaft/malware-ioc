# PrivateEncrypter Indicators of Compromise (IOC)

These IOCs were released as part of PTI team research.

Threat actors, including Cuba Ransomware group, Wizard Spider and others, are using a private encrypting service to evade AV detections. The system is designed explicitly for the Cobalt Strike beacons, making conducting reverse engineering on the samples challenging. The encrypter readme file is available ([here](#Readme.out))

## Encrypter
| MD5                              | SHA1                                     | SHA256                                                           |
| :------------------------------- | ---------------------------------------- | ---------------------------------------------------------------- |
| 344128c5c6daa02e092f42fee966b341 | f8f7814faeb20071884a42fc8d2aaee99dddd6ee | 9140cc1dc6843651b8c3b289565cbdffe69bc7845a7b4eec6c2fe4595fd7eb7d |

## Test DLL
| MD5                              | SHA1                                     | SHA256                                                           |
| :------------------------------- | ---------------------------------------- | ---------------------------------------------------------------- |
| e38fba34b88834f40c78e2eb93db4e2d | 184e21974354dfeeec740f6905e2a62953c99d16 | 70bca5a9da2f6a0b714b2ecb5c7a8094b8ffcaaa9247025dd8e115e17226907f | 

## Encrypted Cobalt Strike Beacon
| MD5                              | SHA1                                     | SHA256                                                           |
| :------------------------------- | ---------------------------------------- | ---------------------------------------------------------------- |
| 26dfa9a9b9cdc7907019a35774e4dc6f | 12e6ca9ae9b5bd4b2af300672f386ac80a1873f2 | f6bc54fea699ce639f54c397a3f060b5f5381f367de98470ff3ae82a6e6404a4 |

## Readme.out
```
Running:

ff.exe 11985756
ff_dd.exe
RunDll32 TstDll.dll,AllocConsole 1198576

if you see error
"A fatal error is occured"

this mean:

ff.exe         illegal command line
ff_dd.exe      internet nothing

ff_dd.exe need time for run, ~1 minute

Note:

using cobalt's mimikatz from the rundll or exe process will ruin the crypt
```