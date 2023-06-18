# DCOM DLL Hijacking

We recently discovered the following DCOM classes that are subject to DLL hijacking. If an attacker can write to the associated path, they can move laterally by instantiating the COM object. Some classes have additional DLL hijacking opportunities that are not listed here.

| Class | DLL Path | Process | Architecture |
| --- | --- | --- | --- |
| WordPad Document | C:\\Program Files\\Windows NT\\Accessories\\XmlLite.dll | wordpad.exe | x64 |
| CLSID_ContactReadingPane | C:\\Program Files\\Common Files\\System\\UxTheme.dll | prevhost.exe | x64 |
| User OOBE Create Elevated Object Server | C:\\Windows\\System32\\oobe\\USERENV.dll | dllhost.exe | x64 |
| MSDAINITIALIZE* | C:\\Program Files\\Common Files\\System\\Ole DB\\bcrypt.dll | dllhost.exe | x64 |
| ShapeCollector Class | C:\\Program Files\\Common Files\\Microsoft Shared\\ink\\DUI70.dll | ShapeCollector.exe | x64 |
| Microsoft WBEM Unsecured Apartment | C:\\Windows\\System32\\wbem\\wbemcomn.dll | unsecapp.exe | x64 |
| Microsoft WBEM Active Scripting Event Consumer Provider | C:\\Windows\\System32\\wbem\\wbemcomn.dll | scrcons.exe | x64 |
| Voice Toast Callback* | C:\\Windows\\System32\\WinBioPlugIns\\MFPlat.dll | svchost.exe | x64 |
| Add to Windows Media Player list | C:\\Program Files (x86)\\Windows Media Player\\ATL.dll | setup_wm.exe | x86 |
| Windows Media Player Burn Audio CD Handler | C:\\Program Files (x86)\\Windows Media Player\\PROPSYS.dll | wmplayer.exe | x86 |

\* Windows 11 and Windows Server 2022 only

This repository includes a [Cobalt Strike BOF](bin/dcomhijack.cna) and [Impacket script](bin/dcomhijack.py) to copy the DLL and instantiate the COM object. [Export definitions](dll/exports/) and a [basic DLL template](dll/main.c) are also included.

## Usage

### Building a DLL

A simple DLL template is included for testing. The required export forwards change slightly between versions, sometimes breaking the hijack. A [utility script](scripts/getExports.py) has been included to generate exports definitions for a target DLL. The definition files for Windows Server 2022/11 and 10 are provided in the [exports](dll/exports/) directory. You can edit the first line of the [Makefile](Makefile) to specify the export directory name. If you are looking for a DLL from a specific version of Windows, [Winbindex](https://winbindex.m417z.com/) is a great resource.

### Executing the DLL

Both implementations require you to specify one of the following shortened class names:

* WordPadDocument
* ContactReadingPane
* UserOOBE
* MSDAINITIALIZE
* ShapeCollector
* WBEMUnsecuredApt
* WBEMActiveScript
* VoiceToastCallback
* AddToWMPList
* WMPBurnCD

#### Cobalt Strike BOF

```
upload-dll <class name> <target IP or hostname> [DLL path]
create-object <class name> <target IP or hostname>
```

#### Impacket Script

```
dcomhijack.py -object <class name> [[domain/]username[:password]@]<targetName or address>
```

## Compatibility

The BOF and Impacket script were tested against the following Windows versions/architectures:

* Windows 10 x64
* Windows 11 x64
* Windows Server 2022 x64

## Known Issues

* Some processes exit immediately after the object is instantiated. You may have to create a new process or inject into an existing process to maintain access.
* Some processes stay alive and do not reload the DLL on subsequent instantiations. You may have to kill the process to reload the DLL.

## Credits

* Inital idea from [@domchell](https://twitter.com/domchell) and his [blog post](https://www.mdsec.co.uk/2020/10/i-live-to-move-it-windows-lateral-movement-part-3-dll-hijacking/) on lateral movement with DLL hijacking.
* Impacket script based on [dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
* BOF based on [DCOM Lateral Movement BOF](https://github.com/Yaxser/CobaltStrike-BOF) from [@Yas_o_h](https://twitter.com/Yas_o_h)
