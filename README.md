<div align="center">
  <img width="125px" src="assets/Havoc.png" />
  <h1>Havoc</h1>
  <br/>

  <p><i>Havoc is a modern and malleable post-exploitation command and control framework, created by <a href="https://twitter.com/C5pider">@C5pider</a>.</i></p>
  <br />

  <img src="assets/Screenshots/FullSessionGraph.jpeg" width="90%" /><br />
  <img src="assets/Screenshots/MultiUserAgentControl.png" width="90%" /><br />
  
</div>

### Quick Start

> Please see the [Wiki](https://github.com/HavocFramework/Havoc/wiki) for complete documentation.

Havoc works well on Debian 10/11, Ubuntu 20.04/22.04, Kali Linux, and **macOS** (Apple Silicon and Intel). You'll need a modern version of Qt5 and Python 3 to avoid build issues.

See the [Installation](#installation) section below for macOS-specific instructions.

If you run into issues, check the [Known Issues](https://github.com/HavocFramework/Havoc/wiki#known-issues) page as well as the open/closed [Issues](https://github.com/HavocFramework/Havoc/issues) list.

---

### Features

#### Client

> Cross-platform UI written in C++ and Qt5 — runs on Linux, macOS (Intel & Apple Silicon), and Windows

- Modern, dark theme based on [Dracula](https://draculatheme.com/)
- **Android client** — native Kotlin/Compose app to control the teamserver from any Android device
  - Connect to teamserver, manage sessions, run commands, manage listeners, generate payloads
  - Full session console with all Demon commands available on mobile

#### Teamserver

> Written in Golang

- Multiplayer
- Payload generation (exe/shellcode/dll)
- HTTP/HTTPS listeners
- Customizable C2 profiles
- External C2
- **Cross-platform build support** — macOS and Linux teamserver builds via Homebrew MinGW
- **Linux & macOS agent builder** — compiles DemonPosix using `zig cc` with musl (no cross-compiler needed)
- **Android APK builder** — builds the DemonAndroid APK via Gradle with C2 config baked in

#### Demon (Windows)

> Havoc's flagship Windows agent written in C and ASM

- Sleep Obfuscation via [Ekko](https://github.com/Cracked5pider/Ekko), Ziliean or [FOLIAGE](https://github.com/SecIdiot/FOLIAGE)
- x64 return address spoofing
- Indirect Syscalls for Nt* APIs
- SMB support
- Token vault
- Variety of built-in post-exploitation commands
- Patching Amsi/Etw via Hardware breakpoints
- Proxy library loading
- Stack duplication during sleep

#### DemonPosix (Linux & macOS)

> POSIX agent written in C — targets Linux (x64/arm64) and macOS (Intel/Apple Silicon)

- **HTTP/HTTPS transport** via libcurl (macOS) or raw POSIX sockets / `zig cc` + musl (Linux cross-build)
- **Fully static Linux binaries** — zero runtime dependencies, runs on any distribution
- **File system commands** — ls, cd, pwd, cat, mkdir, rm, cp, mv, upload, download
- **Process management** — list processes, kill by PID
- **Shell execution** — arbitrary command execution via `sh -c`
- **Process injection** — `ptrace` + remote `mmap` on Linux; `task_for_pid` + Mach VM on macOS
- **Persistence** — cron, systemd user service (Linux), LaunchAgent plist (macOS), bashrc/zshrc
- **Pivoting** — UNIX domain socket pivot channel (equivalent to Windows SMB named pipe)
- **Sleep obfuscation** — `mprotect`-based memory protection during sleep (Linux)
- **Anti-debug / sandbox checks** — TracerPID detection, VM fingerprinting, process masquerade via `prctl`
- **AES-256 CBC** — pure-C implementation, no OpenSSL dependency
- **Identical wire format** — same binary C2 protocol as the Windows Demon; same teamserver handles all agents

**Build targets:**

| Format | Architecture | Notes |
|--------|-------------|-------|
| Linux Exe | x64, arm64 | Static ELF via `zig cc -target x86_64-linux-musl` |
| Linux SO | x64, arm64 | Shared library for LD_PRELOAD injection |
| macOS Exe | x64, arm64 | Mach-O binary via system clang |
| macOS Dylib | x64, arm64 | Dynamic library |
| Android Exe | arm64, x64 | Static ELF runs on Android without NDK |
| Android SO | arm64, x64 | Shared library for Android injection |
| Android APK | arm64 | Standalone APK via DemonAndroid Gradle build |
| Android APK Inject | arm64 | Agent injected into an existing victim APK |

#### DemonAndroid (Android APK)

> Native Kotlin agent compiled as an installable APK

- **ForegroundService** beacon loop — survives app closure, runs continuously in background
- **Persistence** — `BOOT_COMPLETED` receiver restarts the service after every reboot
- **HTTP/HTTPS transport** — OkHttp with self-signed cert bypass
- **Identical Havoc wire protocol** — AES-256 CBC, same binary framing, same teamserver
- **Commands** — shell, ls, cd, pwd, cat, mkdir, rm, upload, download, process list, whoami, sleep, exit
- **Disguise** — configurable APK package name and app label (e.g. `com.android.systemsync` / "System Sync")
- **Notification** — minimal "Syncing" notification (no app icon in recents, no history)
- C2 host/port/URI/SSL baked in at build time via Gradle `-P` properties

**Session table shows:** `Android 14 (API 34)` in the OS column

#### Android APK Injector

> Repackages an existing victim APK (any app) with the DemonAndroid agent embedded inside

The APK injector lets you take any legitimate APK — a game, a utility, a social media app — and inject the agent into it. The resulting APK looks and behaves exactly like the original app while running the agent silently in the background.

**How it works:**

1. **Build a debug stub** — compiles DemonAndroid with your C2 config (`assembleDebug` to keep class names unobfuscated)
2. **Decompile both APKs** — `apktool d` on both the stub and the victim, producing smali source
3. **Merge smali** — copies the agent's smali dirs into the victim as new `smali_classesN` DEX slots (appended, never overwriting victim code)
4. **Patch `AndroidManifest.xml`** — injects required permissions (`INTERNET`, `FOREGROUND_SERVICE`, `RECEIVE_BOOT_COMPLETED`) and declares `AgentService` + `BootReceiver` components. The original binary manifest is removed so apktool recompiles from the patched text version
5. **Hook entry point** — injects a static `AgentBoot.start(Context)` call into the victim's `onCreate()` so the service starts the moment the app is opened. Uses `invoke-static/range` (format3rc) to avoid Dalvik's v15 register cap. Fallback chain: Application class → Launcher Activity → any Activity
6. **Recompile + sign** — `apktool b` rebuilds the APK; `apksigner` signs it with a generated debug keystore

**Usage — from the Payload dialog:**

1. Select agent type `DemonPosix`, format `Android APK Inject`
2. Set `PackageName` (the internal agent package, e.g. `com.demon.agent`)
3. Click **Browse** next to "Source APK" and select the victim APK
4. Click **Generate** — the teamserver runs the full pipeline and delivers `injected.apk`
5. Install with `adb install injected.apk` (you may need `--allow-test-keys` for some devices)

**Compatibility:**

- Works with any APK that has a standard `AndroidManifest.xml` (virtually all apps)
- Tested on APKs with up to 19 DEX files (multi-dex); no theoretical limit
- Hook fallback chain handles apps with no custom Application class
- `invoke-static/range` handles Application classes with large local register counts (> v15)

**Dependencies** (see [Installation](#installation) for full setup instructions):

```
apktool    — APK decompile/recompile
apksigner  — APK signing (bundled with Android SDK build-tools)
Java 17+   — required by apktool
```

<div align="center">
  <img src="assets/Screenshots/SessionConsoleHelp.png" width="90%" /><br />
</div>

#### Extensibility

- [External C2](https://github.com/HavocFramework/Havoc/wiki#external-c2)
- Custom Agent Support
  - [Talon](https://github.com/HavocFramework/Talon)
- [Python API](https://github.com/HavocFramework/havoc-py)
- [Modules](https://github.com/HavocFramework/Modules)

---

### Installation

#### Linux (Debian/Ubuntu/Kali)

```bash
# Core dependencies
sudo apt install -y golang-go nasm mingw-w64 python3-dev libqt5websockets5-dev \
  qtbase5-dev qt5-qmake cmake

# Optional — for cross-compiling Linux/Android ELF agents (DemonPosix):
# (zig is available via snap or from https://ziglang.org/download/)
snap install zig --classic --beta

# Optional — for Android APK builder (DemonAndroid):
# Install Android SDK (e.g. via Android Studio or command-line tools)
# Then:
sdkmanager "build-tools;34.0.0" "platforms;android-34"
# Java 17 is required by Gradle 8:
sudo apt install -y openjdk-17-jdk

# Optional — for Android APK Injector (requires the above + apktool):
sudo apt install -y apktool

# Clone and build
git clone https://github.com/HavocFramework/Havoc
cd Havoc
make         # builds both teamserver and client
```

#### macOS (Apple Silicon & Intel)

```bash
# Core dependencies
brew install qt@5 golang nasm mingw-w64 cmake python3

# Optional — for cross-compiling Linux/Android ELF agents (DemonPosix):
brew install zig

# Optional — for Android APK builder (DemonAndroid):
brew install --cask android-commandlinetools
brew install openjdk@17
sdkmanager "build-tools;34.0.0" "platforms;android-34"

# Optional — for Android APK Injector (requires the above + apktool):
brew install apktool
# apksigner is bundled with build-tools;34.0.0 installed above

# Clone and build
git clone https://github.com/HavocFramework/Havoc
cd Havoc
make ts-build      # teamserver only
make client-build  # GUI client only
make               # both
```

> The macOS build uses Homebrew's `mingw-w64` for cross-compiling the Windows Demon agent.
> The profile at `profiles/havoc.yaotl` is pre-configured for Homebrew paths.

**Dependency summary by feature:**

| Feature | Required tools |
|---------|---------------|
| Windows Demon | `nasm`, `mingw-w64` |
| DemonPosix (Linux/macOS) | `zig` |
| DemonAndroid APK build | Android SDK, `build-tools;34.0.0`, `platforms;android-34`, Java 17 |
| **Android APK Injector** | All of the above + `apktool` |

#### Android Client (Operator App)

The Android operator client lives in `android/`. Open it in Android Studio, build and run on your device.

Requirements: Android Studio Hedgehog+, Android SDK 34, minSdk 26.

---

### Agent Platform Support

| Agent | Targets | Transport | Notes |
|-------|---------|-----------|-------|
| Demon | Windows x64/x86 | HTTP/HTTPS, SMB | Original flagship agent |
| DemonPosix | Linux x64/arm64, macOS x64/arm64 | HTTP/HTTPS | Static musl build via `zig cc`; libcurl on macOS |
| DemonAndroid | Android arm64/x64 | HTTP/HTTPS | Standalone APK; ForegroundService; persists on reboot |
| DemonAndroid (Injected) | Android arm64/x64 | HTTP/HTTPS | Agent embedded in any existing APK via smali injection |

---

### Community

You can join the official [Havoc Discord](https://discord.gg/z3PF3NRDE5) to chat with the community!

### Note

Please do not open any issues regarding detection.

The Havoc Framework hasn't been developed to be evasive. Rather it has been designed to be as malleable & modular as possible. Giving the operator the capability to add custom features or modules that evades their targets detection system.
