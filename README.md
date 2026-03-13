# Xbox Series: Internal Architecture Research

| Field | Value |
|-------|-------|
| **Date** | March 9-12, 2026 |
| **Hardware** | Xbox Series S (Codename: Lockhart) |
| **OS Build** | `26100.7010.amd64fre.xb_flt_2602ge.260212-1010` |
| **Access Method** | Dev Mode + SSH + REST API + NTFS file share junction |

## Summary

This report documents a static and dynamic analysis of the Xbox Series S internal architecture, conducted entirely through Microsoft's official developer mode infrastructure. No exploits or policy violations were used; all access was within the bounds of the individual developer program.

This contains details from the highest level components used for gameplay, down to the lowest level system driver components. Most of these details are expected to be the same for the Xbox One as well.

---

## Clarifications

> AI was used for consistantly formatting a document bigger than my mental capacity can hold at a time.
>
> AI did not do the research, run commands, nor detail which binaries have which capabilities based on imports
>
> All contents have been checked numerous times. If you think any point of this is unclear, underdocumented, or just a lie you can feel free to [DM me](https://x.com/DanielMcGu11144) for the original research documents or other evidense based on system files. 
>
>For reasons you might assume I will not under any circumstances share direct binaries, disassembly output, or anything considered IP of Microsoft.

```
ERA = GameOS Partition
SRA = SystemOS Partition
HT = Kinect (possibly "Human Tracking")
Arden = Xbox Series X/S GPU Stack
NewBe = Arden shader compiler
```

---

### Key Findings

**XTF toolchain present on all retail consoles (Section 5).** The `J:\` volume on every retail Xbox contains the full Xbox Tools Framework, which I can only assume is Microsoft's developer kit, including the Visual Studio remote debugger and a complete RTSP screen streaming server.

**a Host OS management of drivers exists outside the known SRA/ERA model, see trust model (Sections 4.2, 17.5).** `XVIO.SYS` and `XSraFlt.sys` are loaded directly by the hypervisor before Windows initializes and are absent from all accessible volumes. They cannot be tampered with even under full kernel access which is the primary security boundary.

**HVCI is deliberately disabled (Section 18).** `IsSecureKernelRunning = 0x0` confirms the Secure Kernel (VTL1) is not running. Code integrity is load-time only, leaving a TOCTOU window once binaries are mapped. This is a deliberate performance tradeoff; the security boundary is the hypervisor partition, not in-partition memory protection.

**NTFS junction exposes the full SystemOS filesystem over the network (Section 1.2).** A single `mklink /J` command from the SSH shell maps `C:\` or anything else into the Device Portal file share, making every system binary readable remotely with no additional authentication beyond the dev mode PIN.

**Cross-partition architecture is fully mapped (Sections 4, 14, 26-28).** The ERA game partition communicates with SystemOS exclusively through hypervisor-mediated channels: XVIO ring buffers for I/O, GPA translation for shared memory, HvSocket for IPC, and ALPC port sections for zero-copy framebuffer delivery granted by a parenting "Host OS".

**`Deploy:\` junction bypasses local access restrictions (Section 25).** The Windows Update volume, locally restricted, is accessible in full via the network share path through a junction at `S:\Deployment\SoftwareDistribution\` via a path like `\\XBOX\DevelopmentFiles\S\`.

### Scope and Limitations

All testing was performed on a single retail Xbox Series S unit in developer mode. Results reflect build `26100.7010` (February 12, 2026). Findings may vary across hardware revisions (Series X, Xbox One) and firmware versions. Several kernel-level surfaces were not reachable: live kernel dumps are blocked by the `NoKernelDumps` restriction, and the `xvmctrl.sys` IOCTL surface was not fully enumerated. Open questions are tracked in Section 12.

---

## Methodology

### Tools Used

| Tool | Purpose |
|------|---------|
| Windows Explorer | Xbox network drive (DevToolsUser) |
| SSH (`DevToolsUser` + VS PIN) | Shell access to SystemOS |
| `mklink /J` | NTFS junction creation to expose drives over network share |
| Device Portal (`https://XBOX:11443`) | REST API, file browser, process list, live dumps |
| `dumpbin /IMPORTS`, `dumpbin /EXPORTS` | Static analysis of PE binaries over the network share |
| [PowerShell](https://github.com/PowerShell/PowerShell) | Binary analysis of catalog files over the network share |
| [Python](https://github.com/python/cpython)      | [Script to automate REST API](https://github.com/DanielLMcGuire/xboxtools/blob/master/wdp_rest.py) |
| [Phasor](https://github.com/DanielLMcGuire/Phasor)      | Scripting runtime for use on the Console |
| `reg query` | Registry enumeration from the SSH shell |
| `WdApp.exe` | Package manager and ERA lifecycle control (command surface enumeration) |
| `WdConfig.exe` | Console settings API enumeration |
| ETL trace analysis | Windows Update pipeline via `S:\Deployment\SoftwareDistribution\` junction |
| Live process dumps | `GET /api/debug/dump/usermode/live?pid=<pid>` |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Analysis of COM interfaces / drivers |
| [XboxTools](https://github.com/DanielLMcGuire/xboxtools) | My own collection of utilities for various things |

### Approach

Access was established via the documented Dev Mode SSH interface. The NTFS junction technique (Section 1.2) extended read access from the `D:\DevelopmentFiles` scratch space to the full `C:\` system volume and all additional letter volumes. All analysis was read-only; no system settings were modified (`WdConfig.exe set` was not used). Xbox can run standard x86_64 Windows console binaries (compiled with /MT) directly via the SSH shell, which was used to run analysis tooling locally.

Kernel dumps were not available: the `NoKernelDumps` Device Portal restriction blocks them on retail dev mode. User-mode live process dumps were available and used where relevant.

---

## 1. Remote Access

### 1.1 Shell Access

Xbox Dev Mode supports Visual Studio, what many might not know is that this uses SSH:
- Username: `DevToolsUser`
- Password: the Visual Studio PIN shown in Dev Home

### 1.2 Filesystem Access

The Device Portal at `https://XBOX:11443` exposes an undocumented NTFS file share to `D:\DevelopmentFiles`. From the SSH shell:

```cmd
mklink /J D:\DevelopmentFiles\C C:\
```


This creates a junction point from the developer scratch space to the system C: drive root, exposing the entire SystemOS filesystem as a readable network share at:
```
\\XBOX\DevelopmentFiles\C
```

This allows running tools like `dumpbin` from a PC directly against Xbox system binaries over the network.

---

## 2. OS Identity

| Field              | Value             |
|--------------------|-------------------|
| Product Name       | Xbox Series S     |
| OS Edition         | SystemOS          |
| Windows NT Version | 10.0              |
| Build Number       | 26100             |
| Build String       | `26100.7010.amd64fre.xb_flt_2602ge.260212-1010` |
| Branch             | `xb_flt_2602ge`   |
| Build Date         | February 12, 2026 |
| Architecture       | x64               |
| UEFI Secure Boot | `NotCapable`        |
| Console Codename   | Lockhart          |
| Console Mode       | Default           |
| Sandbox ID         | `XDKS.1`          |

The OS identifies as **SystemOS**, not Windows. The build branch `xb_flt_2602ge` seems to be a distinct Xbox "fork" of the Windows codebase, still very similar to Windows 11. Some Windows system binaries are bit-for-bit identical to their desktop counterparts, built with the same MSVC toolchain, likely originating from the same UUP packages. This is seperate from the unclear "Host OS".

### 2.1 Deliberately Scrubbed Registry Identity

Several `CurrentVersion` fields have been intentionally stripped or frozen:

| Key | Value | Notes |
|-----|-------|-------|
| `CurrentVersion` | `6.3` | Reports internally as Windows 8.1, for compatibility |
| `BuildGUID` | | zeroed/scrubbed |
| `InstallDate` | `0` | no install timestamp |
| `EditionID` | `SystemOS` | Never updated |
| `ReleaseId` | `2009` | Frozen at Windows 10 20H2 era; never incremented |

---

## 3. Volume Layout

The console exposes 13 drive letters, most undocumented:

| Drive | Label | Contents | Notes |
|-------|-------|----------|-------|
| `C:` | System Boot | Windows OS files | Standard SystemOS partition |
| `D:` | *(none)* | `DevelopmentFiles\` | Dev mode scratch space |
| `G:` | *(none)* | `GameDVR_VideoBuffer` (272MB), `GameDVR_AudioBuffer` (16MB), `GameDVR_AudioBuffer_SysLoopback` (3MB) | Raw circular capture buffers, shared memory between ERA and SystemOS |
| `J:` | Sys Tools | XTF toolchain, drivers, QuickActions | See Section 5 |
| `M:` | System OS Misc | Contains the console specific NTFS overlays for libraries and drivers |
| `N:` | *(none)* | `BlackBox\`, `EtwPlus\`, `CMS\`, `errorstrings\`, `usersettings\` | Diagnostics and telemetry volume, see Section 3.2 |
| `Q:` | *(none)* | `Users\DevToolsUser\` | user home directory |
| `S:` | *(none)* | `apps\`, `Clip\`, `Deployment\`, `Prefetch\`, `Microsoft\`, `ProgramData\` | likely Host OS Volume (also contains default apps, and other resources) |
| `T:` | *(none)* | `GameDVR\`, `Update\`, junctions to Harddisk16 | GameDVR metadata + update pipeline |
| `U:` | *(none)* | `ShellState\`, `BackCompatLicenses\`, `UserDataCache\` | Shell and user state |
| `V:` | *(none)* | *(empty)* | Unknown purpose |
| `X:` | SystemAux | `Apps\`, `Catalog000.bin` (2.3MB) | System app binaries: 63 apps including `AdsLauncher`, `Xbox.DiscordComponent`, `Xbox.SingleUserProxy`, `Xbox.NTSCaptivePortal`, `Xbox.Xmap`, `Xbox.XboxIDP`, see Section 3.3 |
| `Y:` | SystemAuxF | `Apps\`, `Catalog000.bin` (6.5MB) | Secondary system app binaries |


Additionally, `\\.\HarddiskVolume10` exists with no drive letter assignment. There is a hidden WER (Windows Error Reporting) volume containing `CrashDumps\`, `ReportArchive\`, `ReportQueue\`, and `Temp\`. At least **18 physical disk device objects exist** (`PhysicalDrive0` through `PhysicalDrive17`), all present as kernel objects but inaccessible at the raw level from userspace. `HarddiskVolume16` and `HarddiskVolume18` exist as real accessible volumes but are blocked from `DevToolsUser`.

### 3.1 Hidden Kernel Device Paths
The following paths exist as kernel device objects but are inaccessible from userspace:
- `\??\Deploy:\` Xbox update/deployment pipeline volume (referenced via junction in `S:\Deployment\`)

### 3.2 N:\ Diagnostics Volume

Several directories on `N:\` are actively hidden by a filesystem filter driver at the kernel level as they appear empty to all userspace tools but are confirmed to be written to at runtime:

| Path | Status | Notes |
|------|--------|-------|
| `N:\EtwPlus\` | **Kernel-hidden** | Contents concealed by filesystem filter driver |
| `N:\BlackBox\` | Accessible | Contains Xbox specific ETL crash report telemetry data |
| `N:\errorstrings\en-US.json` | Accessible | Complete Xbox error string database contains 797 entries, see Section 3.4 |
| `N:\usersettings\18\public\` | Accessible | Full-quality gamerpic stored as extensionless PNGs (1080×1080 RGBA, standard PNG format) |

`N:\usersettings\18\public\` stores both `AppDisplayPic` and `GameDisplayPic` as extensionless files. SHA256 hashing confirms they are byte-for-byte identical, the app display picture and gamerpic are the same file written to two paths.

### 3.3 X:\ SystemAux

`X:\ht\versions\` contains an active Kinect vision stack with **three simultaneous versions** installed side-by-side (1.0.0, 1.0.1, 1.0.2), totalling 119MB. These correspond to `vvtechs.dll` builds versioned 1.67MB->1.70MB->1.85MB respectively.

**Body tracking ML models** (per version directory):

| File | Size | Purpose |
|------|------|---------|
| `exemplardb.xmplr` | 36.7MB | Full body pose exemplar database |
| `FernsModel.bin` | 932KB | Depth keypoint detector (random ferns classifier) |
| `HeadPosition.mshdf` | 262–393KB | Head joint estimator (varies by version) |
| `LSVMGripReleaseRight.gbd` | 7.5KB | Latent SVM grip/release classifier, right hand |

**Face tracking ML models** (system-wide, `C:\Windows\System32\ht\`):

| File | Size | Purpose |
|------|------|---------|
| `FaceDetector.bin` | 3.0MB | Locate faces in frame |
| `FaceRecognition.bin` | 3.4MB | Depth/IR identity recognition |
| `FaceRecognition_Color.bin` | 5.9MB | Color-channel identity recognition |
| `ExpressionRandomForest.model` | 150KB | Emotion classifier |
| `EyeLeftRandomForest.model` | 55KB | Left eye state |
| `EyeRightRandomForest.model` | 65KB | Right eye state |
| `LookingAwayRandomForest.model` | 42KB | Gaze/attention detection |
| `MouthOpenRandomForest.model` | 58KB | Mouth open state |
| `MouthMovedRandomForest.model` | 35KB | Lip movement |
| `FacialHairIRRandomForest.model` | 126KB | Facial hair (IR sensor only) |
| `GlassesIRRandomForest.model` | 206KB | Glasses detection (IR sensor only) |

All face attribute classifiers are **Random Forest** models. Output covers identity, expression, gaze, lip state, and appearance attributes.

The `vvtechs.dll` in the stack exports a single function: `NuiVisionCreateFactory`. It imports `EtwPlus.dll` and `D3D11`, confirming the Kinect vision pipeline runs on the GPU and uses the Xbox-specific telemetry path. This is active on hardware with no physical Kinect attached (see also `KinectSensorEnabled=true` in Section 6, and the full `nuiservice.exe` pipeline in Section 33).

### 3.4 N:\errorstrings\en-US.json Error Code Database

797 Xbox error string entries. Notable codes with security or architectural relevance:

| Error Code | String | Notes |
|------------|-----------------|-------|
| `0x887E0002` | D3D12.X runtime/driver mismatch | Confirms D3D12.X is an Xbox-specific D3D12 variant, not generic D3D12 |
| `0x80A40406` | Enhanced Microsoft telemetry enabled in dev mode | Dev mode explicitly opts the console into elevated telemetry collection |

---

## 4. Hypervisor Architecture

> **Impact:** The hypervisor partition boundary is the primary security boundary on this system. XVIO.SYS and XSraFlt.sys are initialized by Host OS before SystemOS initializes and cannot be observed or tampered with from SystemOS, even under full kernel access.

The Xbox uses a custom Hyper-V based hypervisor running two partitions:
- **SystemOS** the SRA partition
- **ERA partition** the GameOS / Title OS execution environment

### 4.1 Driver Stack

```
User space:     xpal.dll
                    ↓
Kernel:         xpalk.dll 
                    ↓
                xvmctrl.sys (364KB)
                    ↓
Hypervisor:     XVIO.SYS 
```

### 4.2 Key Hypervisor Drivers

| Driver         | Size  | Purpose |
|----------------|-------|---------|
| `xvmctrl.sys`  | 364KB | VM Control, main hypervisor interface, IOCTL surface    |
| `XVIO.SYS`     | unknown | Xbox Virtual I/O, direct hypervisor ABI (not on SystemOS filesystem) |
| `xvioc.sys`    | unknown | XVIO Client, SystemOS-side interface to XVIO |
| `xvbus.sys`    | 73KB | Virtual bus root + HvSocket XVIO provider |
| `hvsocket.sys` | 185KB | Hyper-V socket implementation |
| `VMNP.SYS`     | 106KB | VM Named Pipe, cross-partition impersonation |
| `Xrfs.sys`     | 135KB | Xbox Runtime Filesystem |
| `XRmnt.sys`    | 49KB | Xbox Runtime Mount driver |
| `XRo.sys`      | 95KB | Xbox Runtime Objects/Overlay |

**Critical finding:** `XVIO.SYS` and `xpalk.dll` have **no registry service entries** and are **absent from the SystemOS filesystem**. They are probably loaded at boot time by Host OS before SystemOS starts, outside the local driver model entirely. This is the actual security mechanism; Even with full SystemOS kernel access, these components cannot be tampered with.

### 4.3 XVIO API Surface (reconstructed from imports)

From `xvmctrl.sys`, `xviomonc.sys`, and `srakmd_arden.sys` imports against `XVIO.SYS`:

```
XvioInitialize / XvioCleanup
XvioCreateEvent
XvioPostMessage
XvioGetCurrentPartitionId                           (identifies active partition, from xviomonc)
XvioGetReservedMemory                               (hypervisor carve-out RAM access, from srakmd_arden)
XvioRegisterGpaMdl / XvioUnregisterGpa             (Guest Physical Address mapping)
XvioSfrMapPages / XvioSfrUnmapPages                (Shared Frame Region, cross-partition GPU memory)
XvioSfrCounterGet / XvioSfrPerfCounterSet
XvioSfrReadEvent
XvioSetFocus                                        (switches input focus between partitions)
XvioSetSystemTime
XvioSaveProvidersState / XvioRestoreProvidersState
XvioPerfMonitoringEnabled
XvioCreateRingBuffer / XvioDestroyRingBuffer
XvioGetRingBufferContext
XvioReadRingBuffer / XvioReadRingBufferEx / XvioWriteRingBuffer
XvioAcquireRingBufferRundown / XvioReleaseRingBufferRundown
```

`XvioRegisterGpaMdl` and the SFR functions are the hypervisor memory sharing mechanism, raw RAM and GPU framebuffer pages mapped across the partition boundary.

### 4.4 HvSocket Cross-Partition Services
`hvsocket.sys` exposes services for cross-partition socket communication:
- `HvSocketGetPartitionConnections` / `HvSocketGetPartitionListeners` enumerate active channels
- `HvSocketGetVmIdFromVmbusHandle` VMBus handle resolution
- `HvSocketUpdateServiceTable` registry of all cross-partition services

A GUID-named DLL `[REDACTED]_hvsocket.dll` registers an HvSocket service provider. The GUID is redacted in the case it might be identifiable.

The four wildcard HvSocket endpoint GUIDs have been resolved via SHA1 service SID computation, see Section 20 for full details including the DiagTrack, RpcSs, and EventLog cross-partition channels.

---

## 5. J:\ "Sys Tools" XTF / Dev Volume

> **Impact:** The `J:\` volume is present on every retail Xbox. In developer mode, the full XTF toolchain is accessible with no additional authentication beyond the dev mode PIN. This includes remote debugging, screen streaming, PIX GPU profiling, and console control APIs not intended for end-user access.

The most significant finding of this research. The `J:\` volume (labelled "Sys Tools") contains the **Xbox Tools Framework (XTF)**, Microsoft's internal developer kit toolchain, which is just present on every retail Xbox apparently. Full enumeration: **132 files, 52MB** across the volume.

### 5.1 XTF Extension Registry (`J:\tools\xtfextensions.txt`)

All 20 XTF extensions are registered with COM CLSIDs:

| DLL                        | CLSID            | 
|----------------------------|------------------|
| `XtfApplicationServer.dll` | `{10B16182-...}` |
| `XtfConsoleControl.dll` | `{5B45D0E0-...}` |
| `XtfConnectedStorage.dll` | `{9D610BBD-...}` |
| `XtfDebugMonitor.dll` | `{9141933C-...}` |
| `XtfDebugCaptureServer.dll` | `{F306F5C7-...}` |
| `XtfFileIO.dll` | `{8A8B4D4C-...}` |
| `XtfInput.dll` | `{7CC4D09B-...}` |
| `XtfPix.dll` | `{9BD151A3-...}` |
| `XtfGameStreaming.dll` | `{AA627F22-...}` |
| `XtfDiagInfo.dll` | `{FD21AC23-...}` |
| `XtfStressServer.dll` | `{6B5B0C75-...}` |
| `XtfSymbolProxyServer.dll` | `{69ABF3A1-...}`  |
| `XtfPerf.dll` | `{F82AF734-...}` |
| `XtfRemoteRun.dll` | `{D77FE8B8-...}` |
| `XtfUser.dll` | `{2E302BAA-...}` |
| `XtfAuditioning.dll` | `{B91F5206-...}` |
| `XtfCleanup.dll` | `{9CF818E5-...}` |
| `XtfCredentialsServer.dll` | `{8582A384-...}` |
| `XtfEventServer.dll` | `{749FDEFA-...}` |
| `XtfUpdateT_s.dll` | `{DCDD4E77-...}` |

### 5.2 Visual Studio Remote Debugger (`J:\tools\debugmon\`)

```
msvsmon.exe              
vsdebugeng.dll (1.5MB)
vsdebugeng.impl.dll (1.6MB)
msdia120.dll             
diagnosticsscripthost.dll
vsdebuglaunchnotify.exe
```

Versioned debug payloads for VS 2015 through VS 2022 (`debugmondev14payload` through `debugmondev16payload`). **Three simultaneous Visual Studio remote debugger generations are present and registered: VS2015, VS2017, and VS2019** all coexist on the same retail console filesystem.

### 5.3 Other Notable Tools

| Binary | Purpose |
|---|---|
| `agent-xbox.exe` (1.5MB) | Main XTF agent |
| `xtfrtservice.exe` (1.3MB) | XTF runtime service host |
| `xstudioserviceexe.exe` | Xbox Studio service |
| `xperf.exe` | Xbox performance profiler, present and functional however **ETW kernel tracing is fully blocked regardless of tool** (see Section 5.5) |
| `videoserver.exe` (RTSP) | Standalone RTSP screen streaming server |
| `wdapp.exe`, `wdconfig.exe` | Wave Debugger / configuration tools |
| `wdcapture.exe` | Screenshot/video capture |
| `wdgamestream.exe` | Game streaming control |
| `xboxnetapidiagsystem.exe` | Xbox Live network diagnostics |
| `xbtp.dll` (503KB) | Xbox Broadband Transfer Protocol |
| `xraytool.exe` | Xbox console performance tool (Reveals the fact that Host OS exists) |
| `xstudioclient.dll` | Xbox Studio client library |
| `unattendedsetuphelper.exe` | Full console management toolkit, see Section 5.6 |

### 5.4 QuickActions `.xboxunattend` Format

`J:\QuickActions\` contains automation scripts in `.xboxunattend` format. These are plain Windows batch scripts triggered via Device Portal. Available actions:

- `Capture_Screenshot.xboxunattend` calls `wdcapture.exe screenshot`
- `Capture_Video.xboxunattend`
- `Toggle_ConsoleMode.xboxunattend` cycles hardware emulation modes via `WdConfig.exe`
- `Toggle_HDR.xboxunattend`
- `Toggle_Resolution.xboxunattend`
- `Launch_DevHome.xboxunattend` / `Launch_RetailHome.xboxunattend`
- `Suspend_Title.xboxunattend`

`Toggle_ConsoleMode.xboxunattend` reveals the full list of profiling mode identifiers passed to `WdConfig.exe`: `AnacondaProfiling`, `LockhartProfiling`, and **`Scarlett 40 GB`**.

### 5.5 xperf / WPR

`xperf.exe` and WPR are fully present and functional including a `NeuralProcessing` WPR profile. However, all ETW kernel tracing is blocked by two distinct error codes:

| Error Code | Meaning |
|------------|---------|
| `0x80070005` | `Access denied`, standard Windows ACL rejection |
| `0xc5585011` | `Xbox policy block`, **no user-facing error string exists for this code** (not present in `N:\errorstrings\en-US.json`); it was never expected to reach end users |

ETW provider enumeration shows **zero Xbox-specific providers** in the standard ETW namespace. All Xbox telemetry flows through `EtwPlus.dll` using `Etx`-prefixed functions, a completely separate pipeline from standard Windows ETW (see Section 19.3).

### 5.6 unattendedsetuphelper.exe Console Management Tool

`unattendedsetuphelper.exe` is a console management executable covering:

- Factory reset
- Network-based firmware update
- Toast/notification injection
- Device Portal management

It also serves as the runtime engine for `.xboxunattend` scripting (the QuickActions format documented in Section 5.4).

---

## 6. WdConfig Settings Surface

`J:\tools\WdConfig.exe` (build `10.0.26100.7010`) exposes the full console configuration API. notable settings:

### Debug Category
| Setting | Value | Notes |
|---|---|---|
| `ConsoleType` | `Lockhart` | Hardware identifier |
| `ConsoleMode` | `Default` | `AnacondaProfiling`, `LockhartProfiling`, `Scarlett 40GB` |
| `EraGraphicsDriverMode` | `Title Configured` | Options: `Retail`, `Instrumented`, `Validated`. SRA equivalent is `SraGraphicsDriverMode = Retail`, ERA and SRA use separate driver mode settings |
| `EnableKernelDebugging` | `false` | Prevents ERA crash teardown for kernel debugger attachment |
| `EnablePixMemory` | `false` | Reserves 6048MB extra for PIX on Lockhart Profiling mode |
| `CrashDumpType` | `None` | Options: `Triage`, `Mini`, `Heap` |
| `TitlePerformanceOverlay` | `false` | Real-time GPU/CPU HUD overlay on running titles |
| `ExtraTitleMemory` | `0` | Max 6048MB on Lockhart Profiling mode |
| `LastShutdownReason` | `Console crash` | Persisted across reboots, my console crashed at last shutdown |
| `KinectSensorEnabled` | `true` | **Set to true on hardware with no Kinect attached**, stack is provisioned regardless of hardware presence |

### Network Category
| Setting | Value | Notes |
|---|---|---|
| `UseDebugNicForAllTraffic` | `false` | A separate debug NIC exists, distinct from the reail NIC. |

### Storage Category
| Setting | Value | Notes |
|---|---|---|
| `DevkitUseRetailConnectedStorage` | `false` | If enabled, dev mode would use the retail connected storage partition. Not tested. |
| `RunFromPcDataCacheSizeInGB` | `100` | **100GB reserved by default for Run-From-PC title cache; locked, cannot be changed by the user** |

### Unattended Category
| Setting | Value | Notes |
|---|---|---|
| `AllowUsbUnattendScript` | `true` | `.xboxunattend` scripts on USB run automatically |
| `RunUnattendScriptImmediately` | `false` | If true, USB scripts run on boot without cancellation prompt |

### Security Notes

**Microsoft account email stored in plaintext.** The dev mode WdConfig store contains the linked Microsoft account email address in plaintext. This is likely readable by any process with SRA access.

---

## 7. XCRDAPI.dll Xbox Content Delivery API

`XCRDAPI.dll` is the Xbox platform's content management kernel. It handles DirectStorage, progressive install, DRM, xCloud, and blob storage in a single library.

### 7.1 DirectStorage
```
DStorageGetFactory
DStorageGetMappedControlPage
```
Xbox's DirectStorage implementation is embedded in XCRDAPI, not a separate SDK.

### 7.2 XVD Lifecycle
```
XCrdOpenAdapter / XCrdCloseAdapter
XCrdMount / XCrdMountContentType / XCrdUnmount / XCrdUnmountEx
XCrdCreateXVD / XCrdDeleteXVD / XCrdResizeXVD / XCrdGrowDynamicXvd
XCrdSetEraLaunchMapping              associates XVD with ERA partition pre-launch
XCrdUpdateXvc / XCrdUpdateXvcEx
XCrdDefragXvc / XCrdTrimXvc / XCrdTrimXvd
XCrdRepairXvc
```

### 7.3 Progressive Streaming Install
```
XCrdStreamingStart / XCrdStreamingStop
XCrdStreamingQueryActiveInstanceId
XCrdStreamingQueryInformation / InformationByPath / InformationEx
XCrdStreamingQueryRegionInformation / ByPath
XCrdStreamingQueryRegionSpecifiers / ByPath
XCrdStreamingQueueInsertRegion
XCrdStreamingQueueQueryRegionList / ByPath
XCrdStreamingAdjustStreamingFlags
XCrdStreamingQueryRegionIdByOffset
```
Full priority-queued progressive install pipeline. Regions are addressable chunks of game content.

### 7.4 XCloud Integration
```
XCloudQueryFeatureBits
XCloudSetFeatureBits
```
xCloud streaming feature flags are controlled through the same API as local content.

### 7.5 DRM / Attestation
```
XCrdQueryAttestationBlob
XCrdQueryEncryptedInfo / XCrdQueryUnlockInfo
XCrdIsSideloadedKeyPresent
XCrdEnableSharedPls / XCrdSetExternalPlsMapping
```

### 7.6 Storage Blob System
```
XCrdStorageCreateBlob / DeleteBlob / MoveBlob / CopyBlob
XCrdStorageReadBlob / ReadBlobEx / WriteBlob / WriteBlobEx
XCrdStorageQueryBlobAttributes
XCrdXBlobCreate / Delete / Copy
XCrdFindFirstBlob / FindNextBlob / FindCloseBlob
```

### 7.7 XVD Transfer Pipeline
```
XCrdXvdXferInitialize / Uninitialize
XCrdXvdXferStart / Stop
XCrdXvdXferRead
XCrdXvdXferGetResult
```

### 7.8 Path Systems
```
XCrdXasBuildPath / XasBuildPathEx / XasKeyQueryValue   (XAS App Store paths)
XCrdXdsGetVolumeMapping / XdsSetVolumeMapping           (XDS Delivery Service volumes)
XCrdBuildPath / XCrdParsePath / XCrdUpdatePath
XCrdQueryDevicePath / QueryDevicePathByPath
XCrdSetFlatContentPath
```

---

## 8. xpal.dll Xbox Platform Abstraction Layer (50 exports)

Previously undocumented API for hardware identity, capabilities, and power management.

### Hardware Identity
```
XpalGetConsoleCertificate     hardware certificate
XpalGetConsoleIdCch           console hardware ID
XpalGetConsoleSerialNumberCch serial number
XpalGetSmcFirmwareId          SMC firmware version
XpalGetSouthBridgeType        chipset variant
```

### Generation / SKU Detection
```
XpalIsGen8                    Xbox One
XpalIsGen9                    Series X/S
XpalGetGenerationType
XpalIsHyperV                  hypervisor active
XpalIsExternalDevkit / XpalIsInternalDevkit
XpalGetVmType
XpalGetSystemType / XpalGetServerType / XpalGetConsoleMode
```

### Capability Flags
```
XpalIsCapabilityEnabled
XpalIsCapabilityEnabledByVm
XpalIsFactorySettingEnabled
XpalGetFactorySettings
XpalGetCapabilities
XpalIsFeatureEnabled
```

### Power Management
```
XpalInitiateDump              trigger crash dump on demand
XpalInitiatePowerStateToggle
XpalInitiateSystemShutdown
XpalSetWakeupTimer
XpalQueryPowerToggleSource
XpalIsInForcedCs / XpalIsTransitioningToConnectedStandby
XpalIsSilentBootMode
XpalNotifyForcedCsHeartbeat
XpalIsRebootRequested
XpalRefreshPowerChimeMode
```

### Configuration
```
XpalGetXConfig / XpalSetXConfig    Xbox config store (modern EEPROM equivalent)
XpalSetSystemTime
XpalSetInformation
XpalReportUem                      trigger UEM (Universal Error Message / BSOD equivalent)
```

### ERA / Title VM
```
XpalQueryTitleVmInfo
XpalWaitForTitleVmTermination
XpalBackgroundActivityRequest
```

---

## 9. eracontrol.exe ERA Partition Lifecycle Manager

`C:\Windows\System32\eracontrol.exe` runs as LocalSystem (manual start) and manages the full ERA game partition lifecycle. Full import analysis is in Section 28. Summary of key imports:

- `NtOpenPartition` directly opens the Hyper-V ERA partition handle
- `RtlSetProcessIsCritical` marks itself as critical (system BSODs if it crashes)
- `XCRDAPI.dll` mounts/unmounts game XVDs via `XCrdSetEraLaunchMapping`
- `RIMAddInputObserver` / `RIMRemoveInputObserver` intercepts raw controller input for routing to ERA
- `XblaInitialize` botstraps console Xbox Live auth context
- `LogonUserExExW` creates user logon tokens for the ERA session
- `UMgrOpenProcessHandleForAccess` user manager process handle access
- `PsmQueryBackgroundActivationType` background activation state

Also found in the same directory: `eraproxyapp.exe` (339KB), the SystemOS-side compositor and IPC bridge between ERA and the shell. Full import analysis in Section 29.

---

## 10. BlackBox ETL Traces (N:\BlackBox\)

The `N:\BlackBox\` directory contains live ETW flight recorder traces. From analysis of a captured trace:

**Note:** The Xbox ETL format will only resolve with 'tracerp'

### Internal Source Tree Paths (embedded in debug instrumentation)
```
onecoreuap\xbox\xblauth\lib\authmanagerimpl.cpp
onecoreuap\xbox\xblauth\lib\authmanagertokens.cpp
onecoreuap\xbox\xblauth\lib\xstsauthorizer.cpp
onecoreuap\xbox\xblauth\util\httprequest.cpp
```

### Xbox Live Auth Relying Parties
```
http://xdes.xboxlive.com/          Xbox Dev/Engineering Services
http://xboxlive.com                Standard XBL
http://mp.microsoft.com/           Microsoft Passport (MSA)
http://instance.mgt.xboxlive.com  Instance/session management
```

### Crashes Captured
1. **`XboxUI.exe` BEX64** Dashboard shell hit a stack buffer overrun (`STATUS_STACK_BUFFER_OVERRUN`, `0xc0000409`) in `XboxUI.Data.dll` at offset `0x13eb0`
2. **`MoAppHang`** UWP app hang for package `REDACTED_GUID`

---

## 11. Additional Notable Findings

### WSL Present on Xbox
`LxssManager` and `lxcore` services are present with `LaunchProtected: 0x2` (Protected Process) and `SeTcbPrivilege`. WSL on Xbox runs with OS-level trust, and based on use is almost certainly powering `Xbox.ConsoleXCloudPlayer` (xCloud game streaming client).

### Xbox-Exclusive System32 Binaries
Notable DLLs not present in standard Windows:
- `XCRDAPI.dll` content delivery (documented in Section 7)
- `XBBlackbox.dll` flight recorder (documented in Section 30)
- `XBCastRecv.dll` Xbox Cast / Miracast receiver (documented in Section 30)
- `XVMAudioServer.dll` cross-partition VM audio server
- `Xbox.Shell.Api.dll` / `Xbox.Shell.OneStoreServices.dll` shell API (documented in Section 30)
- `XboxCommandService.dll` command/automation
- `XboxUserSim.dll` UI test automation
- `xboxgipsynthetic.dll` / `xboxsynthetickm.dll` synthetic GIP virtual controller injection (documented in Section 30)
- `AppXDeploymentExtensions.xbox.dll` Xbox-specific AppX deployment
- `xvnapi.dll` Xbox Virtual Network API
- `xbsc_xs.dll` Xbox Series Shader Compiler (documented in Section 16.2)

### Services Present But Not Documented
- `EraControlService` ERA partition lifecycle
- `XvdStreamSvc` (`xnetsharedservice.exe`) XVD streaming / progressive install
- `XUpdMgr` Xbox Update Manager (separate from Windows Update)
- `XSraFlt` Xbox SRA filter driver
- `Manufacturing Broker` factory provisioning service
- `TestSirepSvc` SIREP internal testing protocol
- `GameCoreController` GDK game core controller service
- `ConnectedStorage` Xbox cloud save service
- `VideoManagerService` video output management
- `XBBlackbox` flight recorder service
- `xbdiagservice` Xbox diagnostics service
- `XtfRtService` XTF runtime service

Additional legacy/low-level drivers confirmed present in the service registry (see Section 11.2):
- `Zurich` TV tuner decoder stack (disabled)

### `xvnc` / `xvncbus` Xbox Virtual Network Card

`xvnc.sys` and `xvncbus.sys` are a **virtual NIC stack**, the `xvnc` service enum reveals:

```
ROOT\xvnc\0000             root/loopback virtual NIC
{e720983a-...}\wifi\01
{e720983a-...}\wfd\01      Wi-Fi Direct
{e720983a-...}\wfd_role0\01
```

`xvncbus` is a WDF 1.15 bus driver that enumerates virtual NICs on top of the physical wireless adapter. The ERA partition does not access the network stack directly, it communicates through `NetXVmService`, which owns the `xvnc` virtual NIC layer. The GUID `{e720983a-...}` identifies the Xbox wireless adapter hardware.

### `xviomonc.sys` XVIO Monitor Client

Boot-start driver (`Start: 0x1`) that manages display partition focus. Imports analysis:

```
XVIO.SYS:   XvioInitialize, XvioCleanup, XvioPostMessage,
            XvioSetFocus, XvioGetCurrentPartitionId  - new XVIO export
VMNP.SYS:   NpSetupVmImpersonation
xpalk.dll:  XpalIsCapabilityEnabled
```

`xviomonc` does **not** handle framebuffer data, it is a signalling and focus management driver only. `XvioSetFocus` switches which partition has display/input focus; `XvioGetCurrentPartitionId` identifies the active partition. The actual frame capture is handled by `srakmd_arden.sys`.

`NpSetupVmImpersonation` from `VMNP.SYS` allows the monitor driver to impersonate the ERA partition's security identity when accessing ERA display resources across the partition boundary.

### G:\ GameDVR Buffers
Three files on G:\ are raw circular memory-mapped buffers shared between ERA and SystemOS:
- `GameDVR_VideoBuffer` 272MB rolling video capture
- `GameDVR_AudioBuffer` 16MB game audio
- `GameDVR_AudioBuffer_SysLoopback` 3MB system/UI audio (separate stream)

---

## 11.1 Registry Findings

### Devkit-Only K:\ Drive Reference

`HKLM\SOFTWARE\Microsoft\Durango\XTF` contains a hardcoded path:

```
K:\TDK\Tools\XtfJuno.dll
```

### `HKLM\SYSTEM\ResourcePolicyStore`

| Tier | Memory Budget |
|------|--------------|
| `BackgroundSmall` | 40MB |
| `Background` | (standard background) |
| `Balloon` | 5120MB |

CPU policy tiers:

| Policy | CPU Allocation |
|--------|---------------|
| `Paused` | 1% |
| `SoftCapLow` | 10% |
| `SoftCapFull` | 100% |
| `HardCap0` | 0% - completely frozen |

**BeanHog policy** (maybe the foreground game process budget?):
- Memory: Foreground tier
- CPU: 100%
- `DoNotKill`: true
- Priority: Highest importance

---

## 11.2 Xbox One Legacy Archaeology

Three drivers from the Xbox One era survive in the service registry of the Series S. Two are disabled; one is actively running.

### `Zurich` TV Tuner Decoder Stack

`zurichs.sys` is the remnant of the Xbox One TV tuner feature (the HDMI pass-through / OneGuide tuner that was discontinued). Status: **disabled**, but still registered.

Key finding: `zurichs.sys` imports `XVIO.SYS` ring buffers. The TV tuner was architecturally designed to deliver its decoded video stream via XVIO hypervisor ring buffers. The tuner also used `ZwUpdateWnfStateData` to publish tuner state via the Windows Notification Facility (WNF), the same system-wide state notification bus still active in SystemOS.

### `PetraXC` Kinect Sensor Control Device

A WDF virtual device driver now identified as the **KinectSensorControl device**, the kernel-side hardware abstraction for the Kinect camera sensor. Status: **disabled until device arrives** (WDF demand-start model).

Notable characteristics:
- Built against **WDF 1.11**, which corresponds to Windows 8, placing its origin at the original Xbox One kernel base
- Imports `XVIO.SYS`, meaning it communicates via the hypervisor ring buffer transport
- Presents `\\.\KinectSensorControl` as its device interface, consumed by `KinectMediaSource.dll` in the nuiservice pipeline via `DeviceIoControl` (see Section 33)
- Sits above `ciumd_wddm.dll` (a WDDM user-mode camera driver) in the hardware chain: the camera sensor feeds into `ciumd_wddm.dll`, which feeds into `PetraXC.sys`

The `XC` suffix reads as "Xbox Console" or specifically "Xbox Kinect Controller". The driver is disabled in the service registry until a physical Kinect device arrives, at which point it enumerates as the `KinectSensorControl` device object. This explains why `KinectSensorEnabled=true` in WdConfig is meaningful even on hardware without a physical Kinect: the driver infrastructure is ready and waiting, with `nuiservice.exe` running and polling regardless (see Section 33).

### `pspsra.sys` AMD PSP Bridge to SRA

Status: **actively running** (`Start: 0x0`, boot-start). Access denied at the kernel level, the driver is locked and cannot be inspected further, but its position in the boot stack now has architectural context.

`pspsra.sys` sits directly below the SRA partition in the boot chain as a **bridge between the AMD Platform Security Processor (PSP) and the SRA layer**. The AMD PSP handles fTPM attestation and the console certificate at the bare metal level, and `pspsra.sys` is the bridge that surfaces that trust chain into SRA. This places it in the same trust tier as `XVIO.SYS` and `XSraFlt.sys`, initialized before SystemOS, opaque to it, and unreachable even under full kernel access. The "pspsra" name now reads as "PSP->SRA" directly.

---

## 12. Unresolved Questions

1. **XVIO.SYS location** not on any accessible filesystem; loaded by hypervisor at boot
2. **WSL usage** confirmed present and used but specific role in Xbox OS not fully mapped
3. **`XCrdXpfOp`** unidentified XCRDAPI function (XPF = ?)
4. **`XSraFlt.sys` location** confirmed absent from all accessible filesystems; loaded by Host OS alongside XVIO.SYS
5. **`xvnc` GUID `{REDACTED_GUID}`** wireless adapter GUID, full driver chain not mapped
6. **`S:\Shares\TitleScratch` reparse point target** actively redacted by OS in directory listings; requires `FSCTL_GET_REPARSE_POINT` below cmd.exe layer. Almost certainly `\Device\Xrfs\<partition-guid>` (see Section 26)
7. **`xvmctrl.sys` IOCTL surface** live kernel dump blocked (`NoKernelDumps` restriction on retail dev mode); IOCTL dispatch table not yet enumerated
8. **ERA partition GUID** not exposed through any accessible registry path; would be visible in kernel dump (blocked)
9. **`N:\EtwPlus\` contents** actively hidden by a kernel filesystem filter driver; directory listings return empty despite confirmed write activity. The filter driver identity has not been determined (see Section 3.2)

---

## 13. Virtualized I/O and Remote Access (XVIO/SRA)

Recent analysis of the `xboxcloudstreaming.dll` exports and the `CurrentControlSet\Services` registry reveals a deep kernel-level integration for remote interaction, utilizing a "Synthetic" hardware model rather than standard software emulation.

### 13.1 The XVIO (Virtual I/O) Stack

The XVIO framework appears to be the primary method for injecting hardware-level events into the SystemOS from external or cross-partition sources.

| Service | Category | Function |
| --- | --- | --- |
| `hvsocketxvio` | Transport | Bridge service connecting Hyper-V sockets to the XVIO protocol. |
| `InputXVIOClient` | Coordinator | Manages the mapping of remote input packets to virtual device nodes. |
| `xviokbdbus` / `xviomoubus` | Bus Driver | Enumerates virtual HID devices on a synthetic internal bus. |
| `xviokbd` / `xviomou` | Device Driver | Specific function drivers for virtualized keyboards and mice. |

### 13.2 Synthetic Controller Pipeline

The `xboxcloudstreaming.dll` binary leverages `XboxgipSynthetic.dll` to create what the OS perceives as physically connected local peripherals.

* **Audio Virtualization:** Through `SyntheticController_AddAudioHeadset`, the system can pipe remote network audio into the console's local audio stack as a hardware-bound device.
* **Input Injection (RIM):** The use of the Remote Input Manager (`ext-ms-win-ntuser-rim-l1-1-0.dll`) confirms that xCloud and remote play sessions use the same high-authority injection methods as Windows Remote Desktop, specifically `InjectKeyboardInput` and `InjectPointerInput`.

### 13.3 SRA (System Remote Access) & "Arden" Drivers

The presence of the SRA stack provides a good explanation for the console's low-latency frame grabbing.

> **Note:** The `SraKmdArden` driver is hardware-specific to the Series X/S architecture (Arden). This driver, combined with the `XSraFlt` (Filter Driver), likely allows the system to intercept the display buffer at the kernel level, minimizing the latency overhead usually associated with UWP-based streaming apps.

### 13.4 HvSocket Bridge (GUID `4545ffe2-...`)

The previously unidentified HvSocket GUID has been matched to the `hvsocketxvio` service. This confirms that XVIO is not a standalone protocol but a layer running on top of Hyper-V's internal socket transport.

This suggests that the **ERA (Game) partition** does not talk to the network directly for input; instead:

1. **SystemOS** receives network packets via `XboxNetApiSvc`.
2. **`xboxcloudstreaming.dll`** processes the stream.
3. **`hvsocketxvio`** pipes the raw input data across the partition boundary via **HvSocket**.
4. The Hypervisor/Host layer injects it into the target partition as a hardware event.

---

## 14. M:\ Volume | Overlay Architecture

M:\ (labelled "System OS Misc") functions as a **overlay volume**, a tree containing components that are mounted over the base C:\ image. This architecture allows Microsoft to ship a single OS image and apply specific feature-sets via overlays at mount time.

### 14.1 Volume Structure

```
M:\
├── Catalog000-003.bin     volume-specific code integrity catalogs
└── windows\
    ├── system32\
    │   ├── drivers\       kernel drivers
    │   ├── ht\            Kinect support (see section 33)
    │   └── [~120 DLLs]    userspace components
    ├── SystemApps\        system apps
    ├── DefaultApp\
    ├── Fonts\
    ├── Speech_OneCore\
    ├── textinput\
    └── WebManagement\
```

### 14.2 Filesystem Symlinks

C:\ references M:\ components via NTFS symlinks. Symlinks exist at two levels:

**System32 driver level:**
```
C:\Windows\System32\drivers\srakmd_arden.sys -> M:\windows\system32\drivers\srakmd_arden.sys
```

**Windows directory level**
```
C:\Windows\DefaultApp    -> M:\Windows\DefaultApp
C:\Windows\Fonts         -> M:\Windows\Fonts
C:\Windows\SystemApps    -> M:\Windows\SystemApps
C:\Windows\WebManagement -> M:\Windows\WebManagement
```

The M:\ overlay is more pervasive than a simple driver/DLL replacement, core Windows subsystem directories including the font store, system apps, and web management interface are entirely M:\ resident. This might mean a specific overlay controls not just GPU and capture drivers but the entire system app and UI shell layer to a degree.

A full recursive enumeration of C:\ symlinks pointing to M:\ has not been completed.

### 14.3 Hardware-Specific Drivers (M:\windows\system32\drivers\)

| Driver | Size | Purpose |
|---|---|---|
| `srakmd_arden.sys` | 274KB | SRA capture KMD -> Arden hardware-specific frame grabber |
| `acpi.sys` | 873KB | ACPI -> hardware-specific build (larger than generic) |
| `spaceport.sys` | 1MB | Storage port -> XVD crypto + license checking |
| `spacedump.sys` | 304KB | Storage dump driver |
| `buttonconverter.sys` | 90KB | Power/eject HID -> console event conversion |
| `qwavedrv.sys` | 90KB | QoS/network quality driver |
| `acpiex.sys` | 181KB | ACPI extensions |
| `AcpiDev.sys` | 61KB | ACPI device extensions |
| `acpitime.sys` | 57KB | ACPI timer |

**Finding:** `XSraFlt.sys` is absent from M:\ drivers as well as C:\. It is not stored on any accessible filesystem volume, suggesting it is loaded by Host OS at boot alongside `XVIO.SYS`.

### 14.4 Hardware-Specific Userspace Components (M:\windows\system32\)

Notable DLLs/EXEs unique to M:\:

**GPU / Shader Stack:**
- `umd12ddi_arden.dll` (1.56MB)  D3D12 user-mode driver DDI, Arden hardware
- `umd12ddi_d.dll` (1.5MB)  D3D12 UMD, debug/PIX instrumented build
- `umd12ddi_i.dll` (1.14MB)  D3D12 UMD, inbox/fallback build
- `newbe_xs.dll` (26MB)  "NewBe" Arden GPU shader compiler backend
- `xbsc_xs.dll` (3.9MB)  Xbox Series Shader Compiler frontend
- `dxcompiler_xs.dll` (17.8MB)  Xbox Series HLSL compiler
- `dxbc2dxil_xs.dll` (2.9MB)  DXBC to DXIL bytecode converter
- `pixrtddi.dll` (679KB)  PIX render/debug DDI

**Developer / PIX Toolchain:**
- `VsGraphicsRemoteEngine.exe` (4.75MB) PIX GPU profiler remote engine
- `VsGraphicsCapture.dll` (225KB) PIX frame capture
- `VsGraphicsExperiment.dll` (327KB) PIX experiment framework
- `DXCaptureReplay.dll` (18MB) GPU capture replay engine
- `DXCap.exe` (1.19MB)  GPU capture tool
- `DXToolsMonitor.dll` / `DXToolsOfflineAnalysis.dll` / `DXToolsReporting.dll` PIX analysis stack
- `DXGIDebug.dll` (151KB) DXGI debug layer
- `d3d12SDKLayers.dll` (4.8MB) D3D12 validation/debug layers
- `d3d11_3SDKLayers.dll` (1.19MB) D3D11 debug layers
- `d2d1debug3.dll` (618KB) D2D debug layer
- `VSD3DWARPDebug.dll` (155KB) WARP software rasterizer debug build
- `plmdebug.exe` (204KB) PLM (process lifecycle) debugger

**Streaming / Remote Access:**
- `rdpbase.dll` (1.8MB) RDP base library
- `rdpserverbase.dll` (2.3MB) RDP server base
- `XboxDevService.exe` (3.7MB) Xbox dev service host
- `XboxDevService.ProxyStub.dll`

**Social / Plugin Stack:**
- `DiscordPlugin.dll` (139KB) Discord integration
- `TwitchPlugin.dll` (639KB) Twitch streaming integration

**Other Notable:**
- `XboxSyntheticKM.dll` (36KB)
- `xrmntcl.exe` (90KB) Xbox Runtime Mount client
- `xtfupdateT_s_i.dll` (98KB) ?
- `xtcapi.dll` (57KB) XTC API (Xbox Title Communications?)
- `wusys.dll` (308KB) Windows Update system integration

---

## 15. GPU Stack | Shader Compilation Pipeline

The complete Xbox Series S/X shader compilation pipeline lives on M:\ and is absent from C:\. No shader compilation is possible without the hardware-specific overlay mounted.

### 15.1 `newbe_xs.dll`

26MB DLL. Arden GPU shader compiler backend. Only 6 exports:

```
NB_CompileShader          compile individual shader stage
NB_CompilePipeline        compile full pipeline state object
NB_CreateOptimizer        create register allocator / instruction scheduler
NB_GetRegPressure         register pressure analysis (PIX-facing)
NB_GetShaderStats         hardware shader statistics
NB_CreatePixDwarfApi      generate DWARF debug info for GPU shaders
```

The `.pass` section might suggest an LLVM-style pass pipeline. `NB_CreatePixDwarfApi` generates source-level shader debug info for PIX.

### 15.2 `xbsc_xs.dll`

41 exports covering the full compilation API:

```
XBSC_PipelineCompile / XBSC_GetPipelineCompileOutput
XBSC_CompileRootSignature / XBSC_GetCompiledRootSignature
XBSC_AssembleShader / XBSC_GetAssembledShader
XBSC_DisassembleHwPipeline / XBSC_DisassembleHwPipelineWithCallback
XBSC_DisassembleRawShader / XBSC_GetDisassembly
XBSC_GetRegPressure / XBSC_GetShaderStats / XBSC_DumpShaderStats
XBSC_CompressBuffer / XBSC_DecompressBuffer          (shader cache compression)
XBSC_Serialize* / XBSC_Deserialize*                  (pipeline state serialization)
SCCompileMultiShadersXbox / SCDumpHwShader*           (batch compilation)
SC_ConvertRootSignatureToSCInputs
```

The `_mmddu` and `_MMDDT0` PE sections contain **Microsoft Machine-Dependent Driver Data**,  hardware microarchitecture tables baked into the compiler (instruction latencies, register file topology, execution unit counts for Arden).

### 15.3 `dxcompiler_xs.dll`

17.8MB. Xbox Series fork of the DXC HLSL compiler. 4 exports:

```
DxcCreateInstance / DxcCreateInstance2   standard DXC factory (compatible with public API)
CreateXdxrCompiler / CreateXdxrCompiler2 Xbox DXIR compiler (Xbox-specific IR format)
```

### 15.4 `dxbc2dxil_xs.dll` Bytecode Converter

2.9MB. Single export:
```
SCDxil_ConvertDxbcToDxil   convert DX11 DXBC bytecode to DXIL for DX12 pipeline
```

Enables backward-compatible DX11 shaders to run on the DX12-only Arden pipeline.

### 15.5 Complete Shader Compilation Chain

```
Game/App submits HLSL or legacy DXBC shader
              ↓
    [HLSL path]                    [DXBC legacy path]
dxcompiler_xs.dll                dxbc2dxil_xs.dll
(DxcCreateInstance -> DXIL)       (SCDxil_ConvertDxbcToDxil -> DXIL)
              ↓                             ↓
              └──────────┬──────────────────┘
                         ↓
              xbsc_xs.dll (XBSC_PipelineCompile)
              calls newbe_xs.dll NB_ backend
              uses _MMDDT0 Arden microarch tables
                         ↓
              umd12ddi_arden.dll
              (submits compiled ISA via D3D12 DDI)
              uses xg_xs.dll for texture layout
                         ↓
              srakmd_arden.sys (kernel)
              XvioGetReservedMemory -> hypervisor carve-out RAM
              zero-copy framebuffer -> ERA partition
```

---

## 16. `xg_xs.dll` Xbox Graphics Texture Layout Library

Located on **C:\** (not M:\). Contains 27 exports covering texture tiling, ray tracing BVH layout, and DCC compression.

### 16.1 Export Surface

```
XGComputeBufferLayout
XGComputeTexture1DLayout / 2DLayout / 3DLayout
XGComputeOptimalSwizzleMode / OptimalDepthStencilSwizzleMode
XGComputeTileShape
XGSuggestSwizzleMode
XGValidateDepthStencilSwizzleMode / XGValidateDescriptor
XGCreateTexture1DComputer / 2DComputer / 3DComputer
XGCreateTextureComputer / XGCreateTextureComputerFromDescriptor
XGCreateBVHComputer / XGCreateBVHComputer2       ray tracing BVH layout
XGEncodeDCC / XGDecodeDCC / XGDecodeDCCSurface   AMD Delta Color Compression
XGShuffleTextureBufferForDirectStorage           GPU-side texture tiling for DirectStorage
XGSetHardwareVersion                             configure for Series S vs Series X memory layout
XGInitializeLibrary / XGTerminateLibrary
XGEnableExclusiveLocking / XGEnterExclusiveLock / XGLeaveExclusiveLock
```

### 16.2 Key Findings

**Ray Tracing BVH layout is hardware-specific.** `XGCreateBVHComputer2` exposes a second-generation BVH layout API, suggesting the Arden architecture has a distinct BVH node format that differs from generic DXR.

**AMD DCC compression is exposed.** `XGEncodeDCC` / `XGDecodeDCC` implement AMD's Delta Color Compression, the hardware lossless framebuffer compression used on RDNA GPUs. `XGDecodeDCCSurface` is the API PIX uses when reading back DCC-compressed captured framebuffers.

**DirectStorage tiling.** `XGShuffleTextureBufferForDirectStorage` performs the GPU-side shuffle that transforms on-disk texture layout into Arden hardware tiling format during GPU decompression, enabling zero-copy load-to-VRAM.

**`XGSetHardwareVersion` gates all layout algorithms.** The library contains layout implementations for multiple hardware revisions. Calling `XGSetHardwareVersion` with the Series S vs Series X identifier produces different tiling results reflecting the different memory bus widths and cache geometries.

### 16.3 `.xbld` Build Metadata Section

`xg_xs.dll` contains a `.xbld` PE section absent from all other Xbox binaries, indicating it originates from a separate GDK CI build pipeline rather than the Xbox OS build system. The OS build system zeros timestamps and strips metadata sections; GDK CI does not.

```
_xbld_edition_build         = GXDK, 0x65F41B62
_xbld_edition_full_productbuild = GXDK, 10.0.26100.7010
_xbld_edition_sdktype       = GXDK, 260400
_xbld_edition_name          = GXDK, April 2026 GXDK
_xbld_edition_mscver        = GXDK, 193833145.100
```

The `edition_name` value of **"April 2026 GXDK"** predates the public release of that SDK edition (as of writing it is March 9, 2026), confirming the retail OS ships with GDK components built against the next unreleased SDK cycle. The `sdktype=260400` versioning follows the pattern `YYMMRR` (Year/Month/Revision).

The `edition_build` timestamp `0x65F41B62` decodes to **March 13, 2024**, over a year before the OS build date (February 12, 2026), indicating the texture layout algorithms have been stable and unmodified across at least 5 GDK release cycles.

The `mscver=193833145.100` identifies the compiler as **MSVC 19.38** (Visual Studio 2022 17.8.x).

### 16.4 Build Pipeline Inference (UUP?)

```
GDK CI pipeline builds xg_xs.dll (with .xbld metadata intact)
              ↓
    ┌─────────────────────────┐
    ↓                         ↓
Xbox OS image ingests       April 2026 GDK SDK package
artifact directly           ships same binary to developers
    ↓
Ships on every retail console
```

This means the `xg_xs.dll` on retail consoles is bit-for-bit identical to what developers receive in the GDK. Hash verification against the April 2026 public GDK release (when available) would confirm this.

---

## 17. Trust-by-Catalog Code Integrity Model

### 17.1 PE Container Format

The `Catalog*.bin` files on each volume are **PE32+ executables with subsystem `0x11`** ("Xbox Code Catalog"), an undocumented subsystem not present in any public documentation. Key PE header characteristics:

```
Magic:          PE32+ (64-bit)
Subsystem:      0x11  ("Xbox Code Catalog", obtained from strings inside MSVC link.exe)
Entry point:    0 (never executed)
Code size:      0 (no executable code)
DLL Chars:      IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY  <- critical
                IMAGE_DLLCHARACTERISTICS_NX_COMPAT
Sections:       1 unnamed read-only section (raw payload)
```

`FORCE_INTEGRITY` compels the Windows kernel to verify the Authenticode signature before the image is mapped. The catalog cannot be loaded or trusted without a valid Microsoft signature chain.

### 17.2 Trust Chain

```
Hypervisor/Host OS validates Catalog*.bin PE Authenticode signature at boot (FORCE_INTEGRITY)
              ↓
Catalog payload contains hashes of protected binaries on that volume
              ↓
Code Integrity checks each binary's hash against catalog at load time
              ↓
Individual binaries carry no Authenticode signatures of their own
```

This is a **trust-by-catalog** model. A single Microsoft signature covers tons of files per volume. Individual binaries and likely other filetypes are unsigned; their integrity is guaranteed by membership in the catalog.

**Entry count and sizing:**

| Volume | Catalog | Payload size | Entries (÷32) |
|---|---|---|---|
| C:\ | Catalog000.bin | 5,533,696 bytes | 172,928 |
| C:\ | Catalog001.bin | 253,952 bytes | 7,936 |
| C:\ | Catalog002.bin | 57,344 bytes | 1,792 |
| C:\ | Catalog003.bin | 176,128 bytes | 5,504 |
| M:\ | Catalog000.bin | 5,537,792 bytes | 173,056 |
| M:\ | Catalog001.bin | 258,048 bytes | 8,064 |
| M:\ | Catalog002.bin | 61,440 bytes | 1,920 |
| M:\ | Catalog003.bin | 180,224 bytes | 5,632 |

The payload length of every catalog (inside the PE section) is exactly divisible by 32 with no remainder, and not consistently divisible by 36, 40, or other common record sizes. This strongly suggests the payload is a flat array of **32-byte records**.

**Hash algorithm:** Whole-file SHA-256 and SHA-1 of known binaries were not found in the catalogs, ruling out simple whole-file hashing. The most likely format is **Authenticode page hashes**, the Windows CI standard where each 4KB aligned page of a PE file's mapped sections is hashed individually. This would produce one 32-byte (SHA-256) entry per page per file, explaining the large entry counts (172,928 entries for C:\ alone).

**Ordering:** The payload is not sorted by hash value. The ordering scheme has not been determined, possibilities include ordering by file path hash, by install package, or by page offset within the volume's file set, or even by some NTFS trait.

**No header:** The first 128 bytes of the payload contain no recognizable ASCII magic, no small integer fields that could indicate a count or version, and no structure consistent with a standard header. The hash array begins at byte 0 of the payload with no preamble.

### 17.3 Load-Time-Only Enforcement

Code Integrity enforcement is **load-time only**. Once a binary passes catalog hash verification and pages are mapped into memory, CI has no further involvement. HVCI (Hypervisor-Protected Code Integrity), if active on SystemOS, would close the resulting TOCTOU (Time-of-check to time-of-use) window by making loaded code pages hardware read-only at the hypervisor page table level. **HVCI is confirmed off on SystemOS**, `IsSecureKernelRunning = 0x0` (see Section 18). The TOCTOU window is therefore present.

### 17.5 Host OS Components

Two drivers are confirmed absent from all accessible filesystem volumes and are loaded directly by Host OS before SRA initializes:

- `XVIO.SYS` Xbox Virtual I/O core (no registry service entry, not on any volume)
- `XSraFlt.sys` SRA display capture filter (service entry exists, no corresponding file on any volume)

These components exist entirely outside the catalog trust model. They cannot be tampered with even with full SystemOS kernel access, as they are mapped by bootloader before HostOS (parenting System OS) begins loading.

---

## 18. HVCI Status

> **Impact:** With HVCI off, code integrity is load-time only. Once a binary is mapped into memory, there is no hardware enforcement preventing in-memory modification. The TOCTOU window described in Section 17.3 is therefore open. The intended security boundary remains to be the entirely depend on SystemOS not communicating with ERA (GameOS).

`HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KeyGuard\Status`

```
IsSecureKernelRunning = 0x0
```

The Secure Kernel (VTL1) is not running on SystemOS, confirming HVCI cannot be active. This is a deliberate performance tradeoff, no VTL1 tax on kernel activity in the game loop. The security boundary is the hypervisor partition itself, not in-partition memory protection. The code integrity model (Section 17) is therefore load-time only with no TOCTOU protection.

---

## 19. sevpipe Hypervisor IPC Namespace

A custom Windows named pipe device namespace (`\\.\sevpipe\`) serving as the primary IPC backbone for all Xbox-specific inter-process and cross-partition communication. Not a hypervisor construct at the protocol level, standard Windows named pipe semantics underneath, registered under a custom device namespace to hide it from normal pipe enumeration tools.

### 19.1 Full Pipe Inventory

```
EtxForwarder                  <- telemetry data
EtxForwarderToUploaderControl <- telemetry control
XrfsPipe                      <- cross-partition filesystem
ERASwapChainPipe              <- ERA framebuffer (dynamic)
ERAPresentPipe                <- ERA present signals (dynamic)
XvioAudioPipe                 <- ERA audio (dynamic)
XvioAudioEventPipe            <- ERA audio events (dynamic)
XboxOneAudioStatePipe         <- system audio state
XTF_SYSTEM_TO_TITLE           <- XTF command channel (dynamic)
XTF_TITLE_TO_SYSTEM           <- XTF response channel (dynamic)
CloudStreamingServer          <- xCloud (dynamic)
\SEVPipe\epmapper             <- Xbox RPC endpoint mapper
\SEVPipe\epmapperX            <- extended RPC endpoint mapper
```

Dynamic pipes only exist when ERA is active, an XTF session is running, or xCloud is streaming.

No driver provider for on any volume, confirmed absent from `System32\drivers` across all accessible volumes (C, J, M, S). No registry service entry. Possibly constructed entirely at boot by the Host OS.

### 19.2 Access Control Map

```
EtxForwarder                  <- DevToolsUser WRITE 
EtxForwarderToUploaderControl <- DevToolsUser WRITE 
XrfsPipe                      <- SYSTEM only 
ERASwapChainPipe              <- SYSTEM only 
ERAPresentPipe                <- SYSTEM only 
XvioAudioPipe                 <- SYSTEM only 
XTF_SYSTEM_TO_TITLE           <- SYSTEM only 
```

### 19.3 Telemetry Pipeline

```
Process calls EtxEventWrite()
    ↓
EtwPlus.dll
    ↓ writes to
\\.\pipe\EtxUploader
    ↓
EtwUploader.exe (PID 1808, SYSTEM)
    ↓ forwards to
\\.\sevpipe\EtxForwarder          <- data
\\.\sevpipe\EtxForwarderToUploaderControl  <- control
    ↓
NetworkTransferManagerService.exe (PID 2040, SYSTEM)
    ↓
[unknown endpoint, dynamic library load]
    ↑
DevToolsUser can inject at EtxForwarder and control pipe
```

`EtwPlus.dll` is Xbox-specific (`FileDescription: Xbox ETW Plus API`), version `10.0.26100.7010`. Suspend/resume exports are likely stubs on retail builds, three exports share the same RVA.

### 19.4 videoserver.exe RTSP Screen Capture

Port: 11442 (hardcoded in binary). Dependencies:
```
Windows.Xbox.Graphics.Display.Internal.DisplayManager
Windows.Xbox.System.Internal.GameStreaming.GameStreamingAgent
Windows.Xbox.Media.Capture.ApplicationClipShell
```

**Key finding:** Does not appear to function properly. No method has been found to access the video stream from inside or outside the console.

Hardcoded paths/flags:
```
DisableXboxDevToolsTelemetry     <- env var to suppress its telemetry
VideoServerMaxPacketSize         <- configurable via env var
EnableVideoServer                <- WdConfig flag confirmed here
OSDATA\...\DevkitProperties      <- reads devkit properties at runtime
```

### 19.5 OneSettings / Windows Update Schema

The Xbox carries the full Windows Update targeting schema including `XBOXMOBILE` targeting entries and `WCOS` registry hive paths, confirming the Xbox Series S runs on the Windows Core OS (WCOS) foundation shared with HoloLens and Surface Hub. The OS is a lightly customized Windows 11 24H2, not a purpose-built platform OS.

---

## 20. Hypervisor Partition Topology

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\HvSocket\Addresses`

```
LocalAddress  = {REDACTED_GUID}  SystemOS partition GUID
ParentAddress = {REDACTED_GUID}  null parent
```

SystemOS thinks is the **root partition** (false, Host OS is root). The ERA game partition is a child of SystemOS. The ERA partition GUID is not exposed to SystemOS through any accessible registry path, and might be randomized.

### HvSocket Cross-Partition Wildcard Endpoints

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\HvSocket\WildcardDescriptors`

Four service GUIDs resolved via SHA1 service SID computation:

| GUID | Service | Purpose |
|------|---------|---------|
| `REDACTED_GUID` | DiagTrack | Telemetry pipe 1 |
| `REDACTED_GUID` | DiagTrack | Telemetry pipe 2 |
| `REDACTED_GUID` | RpcSs | Inter-partition RPC |
| `REDACTED_GUID` | EventLog | Cross-partition event forwarding |

DiagTrack, RpcSs, and EventLog are first-class cross-partition citizens. Game telemetry, RPC calls, and events are piped from ERA to SystemOS through dedicated hypervisor socket channels invisible to anything running inside ERA.

---

## 21. Graphics Configuration

`HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers`

```
WddmVersion_Max = WddmVersion_Min = 0x9C4  (WDDM 2.5) pinned, not negotiated
DisableCcdDatabase                = 1
DisableHpdHandling                = 1
DisableUsingMonitorPowerForSimulatedMonitor = 1
DirectFlipMemoryRequirement       = 0x40  (64MB)
PinnedMemoryLimit                 = 0x59  (89MB)
AdapterMPO_3                      = 1    MPO tier 3 enabled
```

WDDM version is pinned rather than negotiated, the display pipeline is owned by firmware and the hypervisor, with WDDM not involved in monitor handling. MPO tier 3 (`AdapterMPO_3`) is how the ERA game framebuffer and SystemOS UI composite without a software blit between partitions: each surface occupies a separate hardware overlay plane.

---

## 22. WdApp.exe Package Manager and App Lifecycle Tool

`J:\tools\WdApp.exe` is a full package manager and application lifecycle manager for the Xbox app platform. Complete command surface:

| Command | Purpose |
|---------|---------|
| `install` | Stream a packaged build from web server, network share, or local path |
| `register` / `unregister` | Register/unregister loose-file app packages |
| `registerdrive` | Register all applications on an entire drive at once |
| `registernetworkshare` | Install from a UNC network share with optional credentials |
| `registerscratch` | Register from the dev scratch drive |
| `registertitlescratch` | Register from the ERA title scratch drive |
| `launch` | Launch by AUMID, exe path, or URI |
| `terminate` / `suspend` | Stop or suspend a running app |
| `uninstall` | Uninstall an app or parts of it |
| `list` | List all registered applications |
| `listdlc` | List installed DLC |
| `move` / `copy` | Move or copy a package |
| `movedrive` / `copydrive` | Move or copy all packages on a drive |
| `applyconfig` | Launch the ERA game OS with specified settings or a `game.config`/`.xvd` |
| `queryconfig` | Print the 4-part version number of the running game OS |
| `queryversioninfo` | Query game OS version for a given package |
| `collectxip` | Collect XIP trace |
| `lastgamedetails` | Retrieve details about the last game that ran |
| `installkey` | Install a key onto the console |
| `installplan` | Install a plan onto the console |
| `overlayfolder` | Manage package overlay folders |

### Notable findings

**`applyconfig [game.config | ERA.xvd]`** direct ERA partition boot control from the command line. Accepts either a `.xvd` XVD disk image or a `game.config` settings file. Run without arguments, it launches the most recently used game OS. On a system with no prior game context this returns `0x87E50002` (ERA facility, no XVD found).

**`/drive=Retail`** the `install` command accepts `Retail`, `Development`, and `Ext1-Ext7` as target drive specifiers, allowing package installation directly to the retail storage partition from the dev shell.

**`/WaitToExit`** on `launch` causes WdApp to own the launched process as parent and capture exit codes. System apps reject this with `0x8D160121` (Xbox PLM facility, wrong lifecycle parent). Launching without `/WaitToExit` succeeds as ShellCoreService retains lifecycle ownership.

**`launch` AUMID encoding** system app AUMIDs require base64 encoding matching the pattern used in `.xboxunattend` QuickActions scripts:
```
WdApp.exe launch <base64(FamilyName!AppId)>
```

---

## 23. Device Portal REST API

The Device Portal web server (`WebManagement.exe`, PID 2344) serves its frontend from `M:\windows\WebManagement\www\default\`. The complete REST API schema is documented in `js\RestDocumentation.json` (40KB).

**Authentication:** HTTP Basic auth over HTTPS port 11443. Credentials are the Device Portal username and PIN set during dev mode activation.

### API Namespaces

| Namespace | Base URI | Key Endpoints |
|-----------|----------|---------------|
| App Deployment | `/api/appx/packagemanager/` | install, uninstall, list packages, content groups |
| Device Manager | `/api/devicemanager/` | full hierarchical device tree |
| Dump Collection | `/api/debug/dump/` | live process dumps, bugcheck dumps, crash control |
| ETW | `/api/etw/` | real-time ETW over WebSocket, provider enumeration |
| File Explorer | `/api/filesystem/` | browse, upload, download, delete, rename |
| Networking | `/api/networking/` | ipconfig |
| OS Information | `/api/os/` | machine name, OS info |
| Performance | `/api/resourcemanager/` | live process list with CPU/memory, system perf stats |
| Power | `/api/power/` | battery, power schemes, sleep study reports |
| Remote Control | `/api/control/` | restart, shutdown |
| Task Manager | `/api/taskmanager/` | start/stop apps, kill processes |
| Bluetooth | `/api/bt/` | enumerate, pair, connect audio devices |
| WiFi | `/api/wifi/` | enumerate interfaces/networks, connect, disconnect |
| WER | `/api/wer/` | enumerate and download Windows Error Reporting reports |
| WPR | `/api/wpr/` | start/stop/download WPR performance traces, custom profiles |

### Restriction flags

Several endpoints carry restriction flags that disable them on retail dev mode consoles:

| Flag | Affected Endpoints |
|------|--------------------|
| `NoKernelDumps` | Live kernel dump, bugcheck dump download |
| `NoUserModeDumps` | Live process dump (by PID) |
| `NoBugcheckDumps` | Bugcheck dump list/download/control |
| `NoWPRBootTracing` | Boot-time WPR trace |
| `NoPowerSchemeAccess` | Power scheme read/write |

User-mode live process dumps (`/api/debug/dump/usermode/live?pid=<pid>`) are `nonRestrictable` and succeed on retail dev mode.

### Device Portal Source Tree

| File | Size | Purpose |
|------|------|---------|
| `RestDocumentation.json` | 40KB | Complete machine-readable REST API schema |
| `workspace-definitions.js` | 26KB | Portal workspace panel layout (secondary API index) |
| `common-xbox.js` | 21KB | Xbox-specific portal additions over base Device Portal |
| `common.js` | 56KB | Base Device Portal framework |
| `toolhost.js` | 7.8KB | Tool hosting layer |
| `rest.js` | 19KB | REST call construction library |
| `d3.js` | 570KB | D3 data visualization |
| `konva.js` | 676KB | Canvas rendering |

---

## 24. Live Process List

Obtained via `GET /api/resourcemanager/processes`. Selected notable processes:

| PID | Image | User | Notes |
|-----|-------|------|-------|
| 156 | *(hidden)* | SYSTEM | 66MB working set, no image name visible |
| 1456 | `xbdiagservice.exe` | SYSTEM | Xbox diagnostics service |
| 1808 | `EtwUploader.exe` | SYSTEM | ETW telemetry uploader |
| 1832 | `StorageManagement.exe` | DefaultAccount | `Xbox.StorageManagement` UWP, `IsRunning: false` (suspended) |
| 1904 | `ApplicationClipService.exe` | SYSTEM | GameDVR clip management, 37MB working set |
| 2032 | `xnetsharedservice.exe` | SYSTEM | Cross-partition networking bridge |
| 2040 | `NetworkTransferManagerService.exe` | SYSTEM | Xbox content download manager |
| 2344 | `WebManagement.exe` | SYSTEM | Device Portal web server |
| 2416 | `XUpdMgr.exe` | SYSTEM | Xbox Update Manager |
| 2436 | `PRProvisioningService.exe` | NETWORK SERVICE | PlayReady provisioning service |
| 2460 | `XNetConfig.exe` | SYSTEM | Network configuration |
| 2468 | `toolsautoexec.exe` | SYSTEM | `.xboxunattend` script autoexec runner |
| 2572 | `sihost.exe` | DefaultAccount | Shell infrastructure host, 60MB working set |
| 2836 | `XboxDevService.exe` | SYSTEM | Xbox developer service host, 37MB |
| 3160 | `xrun.exe` | DefaultAccount | Shell-side game launch coordinator |
| 3256 | `MicrosoftXboxSecurityClip.exe` | SYSTEM | Runtime DRM verification host |
| 3600 | `XboxUI.exe` | DefaultAccount | Dashboard shell UI, 60MB working set |
| 3844 | `xrfssvc.exe` | SYSTEM | XRFS cross-partition filesystem service, 352KB (idle) |
| 3864 | `xrmntcl.exe` | SYSTEM | Xbox Runtime Mount client |
| 3888 | `xtfrtservice.exe` | SYSTEM | XTF runtime service |
| 4320 | `Guide.exe` | DefaultAccount | Xbox Guide (`Xbox.Guide_2602.0.2602.11003`), `IsRunning: true` |
| 4548 | `eracontrol.exe` | SYSTEM | ERA partition lifecycle manager, 991KB working set |
| 4660 | `WWAHost.exe` | DefaultAccount | Dev Home (`Microsoft.Xbox.DevHome_1.0.2601.4001`), `IsRunning: true` |
| 6524 | `CastSrv.exe` | DefaultAccount | Miracast cast service |

**Three instances of `xnetsharedservice.exe`** (PIDs 2032, 2764, 2844) run simultaneously under SYSTEM, suggesting separate network bridge instances for different cross-partition channels.

**`eracontrol.exe` working set of 991KB** with no game running confirms it is purely event-driven, it holds almost no state when idle, waking only on ERA lifecycle events.

---

## 25. Windows Update Pipeline (Deploy:\)

> **Impact:** The `Deploy:\` volume is locally restricted from userspace access, but this restriction is bypassed via the network share path through the `S:\Deployment\SoftwareDistribution\` junction. Update ETL traces, the WU database path, and the SLS endpoint URL (including platform identifier and installed language packs) are fully readable.

`S:\Deployment\SoftwareDistribution\` is a junction to the hidden `Deploy:\` kernel device volume.

### ETL Trace Analysis

Two update sessions were captured:

**Session 1 March 9, 2026 18:25:23**
- WU service started cold, `DataStore.edb` did not exist (created fresh this session)
- Network state: disconnected at startup
- Attempted SLS endpoint: `https://slscr.update.microsoft.com/SLS/{REDACTED_GUID}/x64/10.0.26100.7010/0`
- Failed immediately with `0x8024402C` (no internet). No update check completed.

**Session 2 March 10, 2026 03:59:18**
- WU service started, loaded existing `DataStore.edb`
- Network state: disconnected at startup
- Same SLS request failed with `0x8024402C`
- Network came online at `03:59:24`, 6 seconds after the service had already failed and abandoned the session
- Service idled for 10 minutes, then shut down cleanly at `04:09:19` with exit code `0x240001`
- No update check completed in either session

> **Note:** In both sessions the network was unavailable when the WU service initialized, causing it to abandon the update check. Session 2 came online 6 seconds after the service had already exited the discovery phase, suggesting the update pipeline has no reconnect retry once the initial network check fails.

### SLS Endpoint URL Structure

```
https://slscr.update.microsoft.com/SLS/{SERVICE_GUID}/x64/{BUILD}/0
  ?CH=928          catalog hash / change counter (928 in session 1, 19 in session 2)
  &L=en-US;...     31 installed language packs
  &PT=0xc0         platform type: Xbox
  &WUA=1451.2510.27012.0  Windows Update Agent version
```

`PT=0xc0` is the Xbox platform identifier embedded in every update check. `CH` decreased from 928 to 19 between sessions, consistent with a catalog state counter that resets when the database is recreated.

### Service Configuration GUID

`[REDACTED]` Xbox Windows Update service configuration identifier, present in `SLS\` subdirectory and embedded in every SLS request URL.

### WU Client Source Tree

Internal Azure DevOps build paths leaked via debug instrumentation:
```
C:\__w\1\s\src\Client\comapi\DiscoveryJob.cpp
C:\__w\1\s\src\Client\comapi\XxxJob.cpp
C:\__w\1\s\src\Client\lib\DownloadFile\DownloadSession.cpp
C:\__w\1\s\src\Client\Engine\handler\UHManager\uhmgr.cpp
C:\__w\1\s\src\Client\lib\util\fileutil.cpp
C:\__w\1\s\src\Client\lib\wusyshelper\wusyshelper.cpp
```

`C:\__w\1\s\` is the standard Azure DevOps self-hosted agent workspace path. The Xbox Windows Update client shares source with desktop Windows Update, it is the same codebase compiled for the Xbox platform target.

### Persistent Timer

Timer GUID `REDACTED_GUID` was set in session 1 and survived the reboot into session 2. It is stored outside `DataStore.edb` (probably in the registry) and schedules the next update check independently of the database lifecycle.

---

## 26. Cross-Partition I/O Stack Driver Analysis

### `xbtplinkc.sys` XVIO Transport Link Client

Import analysis reveals the full XVIO ring buffer API surface and the GPA tranlation mechanism:

```
XvioAcquireRingBufferRundown / XvioReleaseRingBufferRundown
XvioSignalFlag
XvioWriteRingBuffer
XvioGetIncomingRingBufferAvailableBytes
XvioReadRingBufferEx
XvioInitialize
XvioGetRingBufferContext
XvioCreateRingBuffer
XvioGetReservedMemory           reserved hypervisor memory carve-out
XvioTranslateXrfsGuestGpa       translate ERA guest physical address for SystemOS access
```

**`XvioTranslateXrfsGuestGpa`** is the cross-partition shared memory primitive. ERA hands SystemOS a Guest Physical Address; SystemOS calls this function to obtain a usable mapping. This is the mechanism behind GameDVR capture, framebuffer compositing, and cross-partition audio.

`xbtplinkc` also imports `XpalIsCapabilityEnabledByVm` from `xpalk.dll` the `ByVm` suffix queries capability state at the hypervisor level, not the OS level, confirming it checks whether the hypervisor itself has enabled the capability before proceeding.

### `xrfs.sys` Xbox Runtime Filesystem

Full NT filesystem driver. Import analysis confirms it implements genuine filesystem semantics: Cache Manager (`Cc*`), MDL I/O, file locks (`FsRtl*`), security descriptor construction, AVL tree generic tables for directory indexing.

Key distinguishing imports:
```
FsRtlRegisterFileSystemFilterCallbacks
IoRegisterFileSystem
RtlCreateSecurityDescriptor / RtlCreateAcl / RtlAddAccessAllowedAce
XpalIsCapabilityEnabled
WppRecorder.sys in-memory ETW trace recorder
```

`xrfs.sys` does not import XVIO directly. Instead, `xbtplinkc.sys` imports `XvioTranslateXrfsGuestGpa`; XRFS is the filesystem layer, XVIO provides the GPA translation underneath it.

### Cross-Partition Filesystem Architecture

```
ERA game process
    ↓
ERA kernel / XVIO guest side
    ↓  [hypervisor shared memory / GPA translation via XvioTranslateXrfsGuestGpa]
SystemOS: xbtplinkc.sys  (ring buffer transport)
    ↓
SystemOS: xrfs.sys       (NT filesystem semantics)
    ↓
S:\Shares\TitleScratch   (junction, target redacted by OS)
    ↓
SystemOS userspace / shell
```

---

## 27. eracontrol.exe

Key Xbox-specific imports:

**`XCRDAPI.dll`** direct XVD mount control:
```
XCrdSetEraLaunchMapping   associates XVD content with ERA partition pre-launch
XCrdMountContentType      mounts content categories into ERA
XCrdUnmount               tears down ERA content mounts
XCrdOpenAdapter / XCrdCloseAdapter
XCrdQueryDevicePath / XCrdBuildPath
XCrdDeleteXVD
XCrdSuspendResumeIoBalancer
XCrdIsCorruptionError
XCrdFreeDevicePathBuffer
```

**`ntdll.dll`**
```
NtOpenPartition
RtlSetProcessIsCritical
RtlWaitForWnfMetaNotification / RtlPublishWnfStateData
NtQueryWnfStateData / NtDeleteWnfStateName
```

**`ext-ms-win-xblauth-console-l1-1-0.dll`** (delay-loaded):
```
XblaInitialize            bootstraps Xbox Live auth identity into ERA partition
```

**`ext-ms-win-ntuser-rim-l1-1-0.dll`** (delay-loaded):
```
RIMAddInputObserver / RIMRemoveInputObserver  intercepts raw controller input for ERA routing
```

**`SspiCli.dll`**:
```
LogonUserExExW            creates user logon tokens for the ERA session
```

**`ext-ms-win-session-usermgr-l1-1-0.dll`** (delay-loaded):
```
UMgrOpenProcessHandleForAccess
```

**`RPCRT4.dll`**:
```
RpcServerInqCallAttributesW / I_RpcBindingInqLocalClientPID  RPC caller identity verification
```

---

## 28. eraproxyapp.exe

`eraproxyapp.exe` is the SystemOS-side compositor and IPC bridge between the ERA partition and the shell. 339KB, substantially larger than `eracontrol.exe` (249KB).

**Framebuffer compositing:**
```
d3d11.dll:  D3D11CreateDevice
dcomp.dll:  DCompositionCreateDevice
AVRT.dll:   AvSetMmThreadCharacteristicsW / AvSetMmThreadPriority / AvRevertMmThreadCharacteristics
```
eraproxyapp creates a D3D11 device and a DirectComposition device for compositing the ERA framebuffer into the SystemOS shell. AVRT multimedia thread priority ensures low-latency frame delivery.

**Cross-partition IPC via ALPC:**
```
ntdll: NtAlpcConnectPort / NtAlpcAcceptConnectPort
       NtAlpcSendWaitReceivePort
       NtAlpcCreatePortSection / NtAlpcCreateSectionView
       NtAlpcDeletePortSection / NtAlpcDeleteSectionView
       NtAlpcDisconnectPort / NtAlpcCancelMessage
```
ALPC port sections provide zero-copy shared memory. The ERA game framebuffer is not copied, it is shared via ALPC section views mapped simultaneously into both address spaces.

**Private namespace (secure IPC channel):**
```
CreatePrivateNamespaceW / OpenPrivateNamespaceW
CreateBoundaryDescriptorW / AddSIDToBoundaryDescriptor / DeleteBoundaryDescriptor
ClosePrivateNamespace
bcrypt: BCryptGenRandom / BCryptHashData / BCryptCreateHash / BCryptFinishHash
```
eraproxyapp establishes a private object namespace with a SID-based boundary descriptor, a named object namespace visible only to ERA and SystemOS. BCrypt provides random key material for the boundary.

**Title identity and audio:**
```
XboxLiveTitleId.dll:  GetCurrentXboxLiveInfo identifies the running title
xamapi.dll:           XamApiDisableLayoutScaling
ConsoleGlobalization.dll: GetConsoleGlobalizationInfo
api-ms-win-audiocore-spatial-config-l1-1-0.dll: Create_SpatialAudioDevicePropertyReader
```

**Named pipes:**
```
CreateNamedPipeW / ConnectNamedPipe / DisconnectNamedPipe
```

---

## 29. Additional DLL Analysis

### `XblAuthConsoleExt.dll` Hardware Identity and Authentication (46 exports)

Console identity:
```
XblaGetConsoleCert / XblaGetConsoleId / XblaGetConsoleSerialNumber
XblaGetDevkitType      retail vs devkit detection
XblaGetXblSandbox      Xbox Live environment (retail/preview/dev)
```

Title identity:
```
XblaGetXboxLiveTitleId
XblaGetTitleAttestation / XblaGetTitleConsoleGeneration
```

Cryptography:
```
XblaSignDigest         sign with console private key
XblaGetAttestation / XblaGetTpmPcrAttestation fTPM PCR boot chain measurements
XblaProcessChallenge / XblaProcessSpToken
```

`XblaGetTpmPcrAttestation` confirms the console performs full boot chain attestation. Microsoft can cryptographically verify the exact state of the boot sequence when a console authenticates to Xbox Live.

### `xamapi.dll` Xbox Application Manager Compatibility Shim (24 exports)

Overrides standard Win32 APIs for ERA apps running in the SystemOS context:

```
ClipCursorOverride / GetClipCursorOverride
GetCursorPosOverride / SetCursorPosOverride
GetMonitorInfoWOverride / GetSystemMetricsOverride
XamApiDisableLayoutScaling / XamApiSetLayoutScaleOverride
AdjustDeviceIdMappingForKeyEventBefore / After
UserContextExtInitialize / SetToken / Cleanup
```

This is how SystemOS presents a convincing Windows PC environment to components that expect standard Win32 display and input APIs.

### `xboxsynthetickm.dll` Synthetic Input Injection (M:\, 12 exports)

Located on the hardware overlay volume M:\ (treated as hardware-tier, not application-tier):

```
SyntheticInput_CreateKeyboard / CreateMouse / CreateMouseAbsolute
SyntheticInput_InjectKeyboardInput / InjectMouseInput
SyntheticInput_ReadKeyboardOutput
```

This is how xCloud converts network packets into local input events. The console cannot distinguish synthetic input from physical input at the hardware level.

### `xboxcloudstreaming.dll` xCloud Streaming Engine (2 exports)

```
GetCloudStreamManager
ShutdownCloudStreamManager
```

### `XboxLiveTitleId.dll` Runtime Game Detection (12 exports)

```
GetCurrentXboxLiveTitleId / GetCurrentXboxLiveInfo
GetProcessXboxLiveInfo / GetPackageXboxLiveInfo
AuthenticateSystemXboxLiveTitle
```

### `XBBlackbox.dll` Flight Recorder

Single export: `BlackboxServiceMain`

### `XBCastRecv.dll` Miracast Receiver (22 exports)

```
GetWiFiDirectDeviceCategoryForCurrentPlatform
IsMiracastReceiverStartAllowedWithoutApp
GetEdidForCurrentDisplayDevice
```

### `Xbox.Shell.Api.dll` Shell Integration (44 exports)

```
CheckGamingPrivilegeSilently / WithUI
ShowProfileCardUI / ShowGameInviteUI
PlaySystemSound
AreWebAppsEnabled
```

### Controller Stack Codename "Pendragon"

`XAccessoriesGip.dll` reveals the internal codename for the GIP (Game Input Protocol) stack:
```
PendragonGIP_SendGIPMessage
PendragonGIP_SetMessageCallback
PendragonGIP_Start / Stop
```

The Pendragon codename has survived from Xbox One ERA through Series S.

---

## 30. Complete System Architecture Summary

### Overall Architecture

```
Hypervisor (lowest layer, hardware virtualization)
    ↓
Host OS (Root Partition) hidden from SystemOS, management OS
├── 108MB fixed RAM carve-out
├── 5 core system processes
├── **XVIO.SYS**             Xbox Virtual I/O core (ring buffers, GPA translation)
├── **XSraFlt.sys**          GPU security filter (display capture interception)
├── **sevpipe driver**       secure IPC namespace root
├── **xvncbus.sys/xvnc.sys** virtual NIC root
├── **xrfs.sys**             NTFS Filesystem driver
└── Hardware device ownership (GPU, network, storage)
    ↓ (creates child VMs with virtualized hardware)
SRA SystemOS Partition (Windows 11 24H2 / WCOS, child partition)
├── Total RAM: 6400MB (dynamically allocated)
├── 89-95 processes
├── sevpipe IPC backbone (client views)
├── ERA lifecycle management (eracontrol.exe)
├── Telemetry pipeline (EtwUploader->NetworkTransferManager)
├── XTF toolchain (J:\tools\, always present on retail)
├── Device Portal web server (:11443)
└── Virtualized hardware views (GPU, NIC, storage via Host OS)
    ↓ (manages as child)
ERA GameOS Partition
├── Game title process
├── XVIO client view
└── All hardware access proxied: ERA->SystemOS->Host OS
```

### Driver Initializations

```
Host OS Boot (invisible to research):
1. Host OS loads from its own protected storage partition
2. Normal Windows driver loading within Host OS:
   - XVIO.SYS (registers as \Device\Xvio)
   - XSraFlt.sys (filters GPU commands)
   - sevpipe driver (creates \\.\sevpipe namespace)
   - xvncbus.sys/xvnc.sys (virtual NIC root)
3. Host OS creates SystemOS VM with virtualized hardware, and symlinks images
4. SystemOS never sees Host OS drivers or filesystem

SystemOS View (what research accessed):
1. Sees virtualized devices provided by Host OS
2. XVIO appears as a service, not a driver (xvmctrl.sys interface)
3. sevpipe appears as a namespace but server runs in Host OS
4. Cannot enumerate or access Host OS drivers/files
```

### ERA Launch Sequence

```
1. eracontrol.exe: NtOpenPartition - open ERA hypervisor partition handle
2. eracontrol.exe: XCRDAPI XCrdSetEraLaunchMapping - associate XVD with partition
3. eracontrol.exe: XCRDAPI XCrdMountContentType - mount game content into ERA
4. eracontrol.exe: XblaInitialize - provision Xbox Live identity into ERA
5. eracontrol.exe: LogonUserExExW - create ERA session user token
6. eracontrol.exe: RIMAddInputObserver - begin routing controller input to ERA
7. eraproxyapp.exe: ALPC port sections - establish zero-copy framebuffer channel
8. eraproxyapp.exe: CreatePrivateNamespaceW - establish secure IPC namespace
9. eraproxyapp.exe: D3D11 + DComp - prepare framebuffer compositor
10. ERA partition boots game
```

### Call flow 

```
ERA Game Process needs GPU memory:
    ↓
ERA: XVIO guest call->SystemOS
    ↓
SystemOS: xvmctrl.sys->xvioc.sys->Host OS via hypercall
    ↓
Host OS: XVIO.SYS validates request
    ↓
Host OS: Programs actual GPU MMU
    ↓
Host OS: Returns GPA mapping token to SystemOS
    ↓
SystemOS: Forwards to ERA
```

### Full Stack Map

| Layer | Components |
|-------|------------|
| **Content** | `XCRDAPI.dll` (XVD mount/unmount/streaming) |
| **Identity** | `XblAuthConsoleExt.dll`, `XboxLiveTitleId.dll`, `pspsra.sys` |
| **DRM**      | `MicrosoftXboxSecurityClip.exe`, `XCRDAPI.dll` |
| **ERA Control** | `eracontrol.exe` (`NtOpenPartition`, XCRDAPI, XblaInitialize) |
| **ERA Proxy** | `eraproxyapp.exe` (ALPC, D3D11, DComp, private namespace) |
| **Input (local)** | `xviokbd.sys`, `xviomou.sys`, `XAccessoriesGip.dll` (Pendragon) |
| **Input (remote)** | `xboxcloudstreaming.dll`, `xboxsynthetickm.dll` |
| **Input Focus** | `xviomonc.sys`, `VMNP.SYS` (impersonation) |
| **Host OS** | `xvmctrl.sys`, `XVIO.SYS` (not on filesystem) |
| **Cross-partition FS** | `xrfs.sys`, `xbtplinkc.sys`, `xrmntcl.exe`, `xrfssvc.exe` |
| **Display** | `eraproxyapp.exe`, `xamapi.dll` (Win32 overrides), MPO tier 3 |
| **GPU** | `umd12ddi_arden.dll`, `newbe_xs.dll`, `xbsc_xs.dll`, `xg_xs.dll` |
| **Audio** | `XVMAudioServer.dll`, `XAudio2_8/9.dll`, spatial audio config |
| **Networking** | `xvnc.sys`/`xvncbus.sys` (virtual NIC), `NetXVmService` |
| **Diagnostics** | `XBBlackbox.dll`, `xbdiagservice.exe`, `EtwUploader.exe`, `EtwPlus.dll` (Etx pipeline) |
| **Update** | `XUpdMgr.exe`, WU client (`wuauengcore.dll`), `Deploy:\` volume |
| **Shell** | `Xbox.Shell.Api.dll`, `XboxUI.exe`, `Guide.exe`, `sihost.exe` |
| **Streaming** | `xboxcloudstreaming.dll`, `XBCastRecv.dll` (Miracast) |
| **Dev Tools** | `WebManagement.exe` (Device Portal), XTF stack (132 files), `WdApp.exe`, `unattendedsetuphelper.exe` |
| **Compatibility** | `xamapi.dll` (Win32 shim), `dxbc2dxil_xs.dll` (DX11->DX12) |
| **Vision / Kinect** | `nuiservice.exe` (3.8MB, SYSTEM, always-on orchestrator), `KinectMediaSource.dll` (frame ingestion, `alignment.bin` 10.7MB, `alignment_color.bin` 5.7MB), `vvtechs.dll` (`NuiVisionCreateFactory`, body track), `speechwov.dll` (wake word/speech track), face Random Forest models (`FaceDetector.bin`, `FaceRecognition.bin`, `ExpressionRandomForest.model`, +8 others), 3 active versions (`X:\ht\versions\`) |
| **Ads** | `AdsLauncher` (system app), `Windows.Xbox.System.Internal.AdsContract` (WinRT) |
| **Legacy (disabled)** | `Zurich` (TV tuner, XVIO-linked), `PetraXC` / `KinectSensorControl` (WDF 1.11, disabled until Kinect device arrives, feeds `KinectMediaSource.dll` via `\\.\KinectSensorControl`) |

---

## 31. WinRT Contract Registry

The `HDRGameCalibration` WinMD surprisingly contains *seemingly* the **ENTIRE** Xbox WinRT contract registry, 100+ contracts defining every first-party WinRT API surface available on the platform.

### Notable Contracts

| Contract | Version | Notes |
|----------|---------|-------|
| `Windows.Kinect.KinectContract` | v1 | Kinect is likely supported for title backwards compatibility |
| `Windows.Xbox.TestAutomationContract` | | Test automation surface ships on **retail** hardware |
| `Windows.Xbox.System.Internal.AdsContract` | | Ads system is an internal WinRT contract |
| `Windows.Xbox.System.Internal.CopyOnLan.CopyOnLanContract` | | LAN game copying, local network title transfer |
| `Windows.System.Internal.XboxLive.Auth.AuthContract` | v2 | Internal Xbox Live auth surface (separate from public XBL APIs) |

### Implications

**Kinect as a maintained contract.** `Windows.Kinect.KinectContract v1` is present as a non-deprecated first-class contract, consistent with the active stack (`C:\Windows\System32\ht`) and `KinectSensorEnabled=true` in WdConfig. Kinect vision is actively maintained infrastructure even on hardware without a physical Kinect. The full orchestration pipeline (`nuiservice.exe`, `KinectMediaSource.dll`, three inference tracks, output routing) is documented in Section 33.

**Ads are internal infrastructure.** `AdsContract` being an `Internal` contract, not a public SDK API, means ad delivery is built into the OS at the same level as auth and storage, not a third-party SDK integration.

**Test automation on retail.** `Windows.Xbox.TestAutomationContract` ships on retail units, consistent with `Windows.Xbox.TestAutomationContract` being accessible to developer mode tooling.

---

## 32. UserMgr2

`UserMgr2` is the interactive user account that owns the active logged-in session. `NTUSER.DAT` is locked (UserMgr2 is live). Key findings from the profile:

### Profile Structure

| Path | Contents |
|------|----------|
| `ntuser.ini` | 3 newlines |
| `AccountPictures\UserImage.jpg` | Single 1080x1080 Microsoft account photo, separate from the gamerpic system (see Section 3.2) |
| `AppData\Local\Packages\` | Only sideloaded dev app configs present, **Xbox system apps do not use standard UWP `LocalPackages` storage paths** |

### Privilege Note

Device Portal junctions resolve using `UserMgr2` permissions rather than `DevToolsUser` permissions (see Section 1.2 and Unresolved Question 12). `UserMgr2` has a higher privilege level than `DevToolsUser`, `UserMgr2` is the interactive session owner while `DevToolsUser` is a restricted developer access account.

---

## 33. nuiservice.exe Kinect Vision Pipeline

`nuiservice.exe` (3.8MB, running as SYSTEM, always-on) is the orchestration process for the full Kinect/NUI perception stack. It hosts three parallel inference tracks: body, face, and audio; each running as a separate processing pipeline, scheduled cooperatively via a fiber graph and fed frames through an IOCP pump backed by a D3D11 GPU inference device.

### Architecture

```
nuiservice.exe
├── D3D11CreateDevice          <- GPU inference device
├── IOCP frame pump            <- async frame dispatch
└── Fiber graph                <- cooperative ML inference scheduling
```

### Input: KinectMediaSource.dll

Frame ingestion is handled by `KinectMediaSource.dll`:

```
KinectMediaSource.dll
├── MFCreate2DMediaBuffer          <- allocates 2D image frames (Media Foundation)
├── alignment.bin     [10.7MB]     <- depth -> 3D coordinate transform LUT
├── alignment_color.bin  [5.7MB]  <- depth/color registration
├── DeviceIoControl->\\.\KinectSensorControl   <- talks to PetraXC.sys
└── CoCreateInstance {9178b0a6}    <- self-registration CLSID
```

`alignment.bin` (10.7MB) and `alignment_color.bin` (5.7MB) are pre-computed lookup tables for converting raw depth sensor data into 3D world-space coordinates and for registering depth pixels to color pixels respectively. These are hardware-calibration artifacts specific to the Kinect camera geometry.

### Body Tracking

Models loaded from `X:\ht\versions\{1.0.0|1.0.1|1.0.2}\` via `vvtechs.dll` (`NuiVisionCreateFactory`):

- **Input:** depth frames from `KinectMediaSource.dll`
- **Output:** skeleton joints, head position, hand state (grip/release)
- Three version directories are present simultaneously; the active version is selected at runtime

### Face

Models loaded from `C:\Windows\System32\ht\` (see Section 3.3 for full model inventory):

- **Input:** depth, IR, and color frames
- **Output:** identity (who), expression (emotion), gaze (attention direction), lip state (open/moved), appearance attributes (glasses, facial hair)
- Identity output feeds directly into `LogonUserExExW` for face-based auto sign-in (see Output Routing below)

### Audio

Handled by `speechwov.dll`:

```
speechwov.dll
├── SpeechWov_Create / UpdateAcousticModels
├── SpeechWov_ProcessRecognition
└── Output->wake word events, speech recognition events
```

`speechwov.dll` is a wake-word and speech recognition engine. `UpdateAcousticModels` indicates the acoustic model can be updated at runtime (language pack or microphone calibration changes). This is the "Hey Cortana" / voice command infrastructure at the system level.

### Output Routing

nuiservice.exe distributes inference results through multiple channels:

| Channel | API | Purpose |
|---------|-----|---------|
| System-wide broadcast | `RtlPublishWnfStateData` | Publishes body/face/audio state to all WNF subscribers |
| Face sign-in | `LogonUserExExW` | Triggers face-based automatic user sign-in |
| Per-app named pipe | Named pipe server + `GetNamedPipeClientProcessId` | Gated per-process output; verifies caller identity before delivering data |
| Per-caller RPC | RPC server + `RpcServerInqCallAttributesW` | Per-caller authenticated access to inference results |
| Persistent identity | State Repository (`SRDictionaryToPropertySet`) | Persists recognized identity across sessions |
| Capability gate | `RtlCapabilityCheck` | All access to inference output gated by NT capability check |

`RtlCapabilityCheck` is the access control mechanism: a process must hold the appropriate NT capability to receive any NUI data. This gates game title access, shell access, and developer access separately.

### Consumers (via WNF subscription)

| Consumer | Notes |
|----------|-------|
| Xbox Shell | Expression-aware UI adaptation |
| `Guide.exe` | Auto sign-in trigger |
| `XboxUI.exe` | Attention/gaze-aware UI |
| Game titles | Via `NuiVision` WinRT contract (`Windows.Kinect.KinectContract v1`, retail) |
| xCloud | streaming client receives NUI state |

The WinRT contract `Windows.Kinect.KinectContract v1` (see Section 31) is the retail-facing surface for game title access to this pipeline. xCloud receiving NUI state via WSL is notable: it means the streaming client on the console side can use local biometric data (e.g. player presence, attention) even in a cloud-game session.

```
Camera Sensor Hardware
└── ciumd_wddm.dll  <- WDDM user-mode camera driver
    └── PetraXC.sys (KinectSensorControl)  <- WDF 1.11, disabled until device arrives
        └── \\.\KinectSensorControl

nuiservice.exe  [always running, SYSTEM]
└── KinectMediaSource.dll->DeviceIoControl->\\.\KinectSensorControl
    ├── Track 1: vvtechs.dll  (body)
    ├── Track 2: FaceDetector/FaceRecognition + RF models  (face)
    └── Track 3: speechwov.dll  (audio)
        └──->WNF / LogonUserExExW / named pipe / RPC / State Repository
```

---

*Research conducted on a retail Xbox Series S in developer mode. All access was through Microsoft's provided developer mode infrastructure. No system settings were modified.*
