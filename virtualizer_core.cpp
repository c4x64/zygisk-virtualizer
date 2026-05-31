// SPDX-License-Identifier: MIT
#include "virtualizer.h"

#define VIRT_BLOOM_SIZE 1024
static uint64_t g_bloom_filter[VIRT_BLOOM_SIZE / 64] = {0};

#define VIRT_ERR_COUNT_MAX 32
static uint32_t g_error_counts[VIRT_ERR_COUNT_MAX] = {0};

#define VIRT_INC_ERR(code) do { \
    int _idx = -(code); \
    if (_idx >= 0 && _idx < VIRT_ERR_COUNT_MAX) \
        __sync_fetch_and_add(&g_error_counts[_idx], 1); \
} while (0)

typedef struct {
    size_t cache_allocated;
    size_t rules_allocated;
    size_t trie_nodes;
    size_t total_allocated;
    size_t peak_allocated;
    uint32_t oom_count;
} VIRT_MemoryStats;

static VIRT_MemoryStats g_mem_stats;

int g_virt_notify_fd = -1;
VIRT_AntiTamperState g_anti_tamper_state;

void virt_mem_track_alloc(size_t size) {
    g_mem_stats.total_allocated += size;
    if (g_mem_stats.total_allocated > g_mem_stats.peak_allocated) {
        g_mem_stats.peak_allocated = g_mem_stats.total_allocated;
    }
}

void virt_mem_track_free(size_t size) {
    if (size <= g_mem_stats.total_allocated) {
        g_mem_stats.total_allocated -= size;
    }
}

void virt_mem_record_oom(void) {
    g_mem_stats.oom_count++;
}

size_t virt_mem_get_usage(void) {
    return g_mem_stats.total_allocated;
}

size_t virt_mem_get_peak(void) {
    return g_mem_stats.peak_allocated;
}

int virt_mem_check_pressure(void) {
    size_t usage = virt_mem_get_usage();
    if (usage >= VIRT_MEM_CRITICAL_THRESHOLD) {
        VIRT_LOGW("Memory critical: %zu bytes used", usage);
        return 2;
    }
    if (usage >= VIRT_MEM_PRESSURE_THRESHOLD) {
        VIRT_LOGW("Memory pressure: %zu bytes used", usage);
        return 1;
    }
    return 0;
}

void virt_mem_reduce_footprint(void) {
    virt_cache_flush(NULL, 0);
    VIRT_LOGI("Memory footprint reduced");
}

int virt_resource_limits_init(VIRT_ResourceLimits *limits) {
    if (!limits) return VIRT_ERR_INVAL;
    limits->max_cache_entries = VIRT_MAX_CACHED_PATHS;
    limits->max_rules = VIRT_MAX_RULES;
    limits->max_trie_nodes = 100000;
    limits->max_event_history = 256;
    limits->max_log_size = 1048576;
    limits->enable_strict_mode = false;
    return VIRT_OK;
}

int virt_resource_check_limit(uint32_t current, uint32_t max, const char *name) {
    if (current >= max) {
        VIRT_LOGW("Resource limit reached: %s (%u/%u)", name, current, max);
        return VIRT_ERR_BUSY;
    }
    return VIRT_OK;
}

// Print a summary of error counters across all categories.
void virt_print_error_summary(void) {
    VIRT_LOGI("Error summary: %u OOM, %u INVAL, %u TIMEOUT, %u NODEV, "
              "%u CORRUPT, %u IO, %u BUSY, %u CONFIG, %u BPF, %u SECCOMP",
              g_error_counts[-VIRT_ERR_NOMEM],
              g_error_counts[-VIRT_ERR_INVAL],
              g_error_counts[-VIRT_ERR_TIMEOUT],
              g_error_counts[-VIRT_ERR_NODEV],
              g_error_counts[-VIRT_ERR_CORRUPT],
              g_error_counts[-VIRT_ERR_IO],
              g_error_counts[-VIRT_ERR_BUSY],
              g_error_counts[-VIRT_ERR_CONFIG],
              g_error_counts[-VIRT_ERR_BPF],
              g_error_counts[-VIRT_ERR_SECCOMP]);
}



static uint32_t virt_bloom_hash1(const char *str, uint32_t len) {
    uint32_t hash = 5381;
    for (uint32_t i = 0; i < len; i++)
        hash = ((hash << 5) + hash) + (unsigned char)str[i];
    return hash % VIRT_BLOOM_SIZE;
}

static uint32_t virt_bloom_hash2(const char *str, uint32_t len) {
    uint32_t hash = 0;
    for (uint32_t i = 0; i < len; i++)
        hash = hash * 101 + (unsigned char)str[i];
    return hash % VIRT_BLOOM_SIZE;
}

// Add a pattern string to the bloom filter.
// @param pattern - non-null string to add
void virt_bloom_add(const char *pattern) {
    assert(pattern != NULL);
    uint32_t len = strlen(pattern);
    uint32_t h1 = virt_bloom_hash1(pattern, len);
    uint32_t h2 = virt_bloom_hash2(pattern, len);
    assert(h1 / 64 < VIRT_BLOOM_SIZE / 64);
    assert(h2 / 64 < VIRT_BLOOM_SIZE / 64);
    g_bloom_filter[h1 / 64] |= (1ULL << (h1 % 64));
    g_bloom_filter[h2 / 64] |= (1ULL << (h2 % 64));
}

// Check if a string might be in the bloom filter (false positives possible).
// @param str - string to check
// @param len - length of string
// @return 1 if possibly present, 0 if definitely absent
int virt_bloom_check(const char *str, uint32_t len) {
    uint32_t h1 = virt_bloom_hash1(str, len);
    uint32_t h2 = virt_bloom_hash2(str, len);
    if (!(g_bloom_filter[h1 / 64] & (1ULL << (h1 % 64)))) return 0;
    if (!(g_bloom_filter[h2 / 64] & (1ULL << (h2 % 64)))) return 0;
    return 1;
}

// ---- Latency Histogram ----
#define VIRT_LATENCY_BUCKET_COUNT 5

typedef struct {
    const char *name;
    uint64_t min_latency_ns;
    uint64_t max_latency_ns;
    uint64_t total_latency_ns;
    uint64_t count;
    uint64_t bucket_limits[VIRT_LATENCY_BUCKETS + 1];
    uint64_t bucket_counts[VIRT_LATENCY_BUCKETS];
} VIRT_LatencyBucket;

static VIRT_LatencyBucket g_latency_buckets[] = {
    {"openat", 0, 0, 0, 0, {1000, 5000, 10000, 50000, 100000, 500000, 1000000, 5000000, UINT64_MAX}, {0}},
    {"readlinkat", 0, 0, 0, 0, {1000, 5000, 10000, 50000, 100000, 500000, 1000000, 5000000, UINT64_MAX}, {0}},
    {"connect", 0, 0, 0, 0, {1000, 5000, 10000, 50000, 100000, 500000, 1000000, 5000000, UINT64_MAX}, {0}},
    {"uname", 0, 0, 0, 0, {1000, 5000, 10000, 50000, 100000, 500000, 1000000, 5000000, UINT64_MAX}, {0}},
    {"total", 0, 0, 0, 0, {1000, 5000, 10000, 50000, 100000, 500000, 1000000, 5000000, UINT64_MAX}, {0}},
};
static const size_t g_latency_bucket_count = sizeof(g_latency_buckets) / sizeof(g_latency_buckets[0]);

static inline int virt_latency_find_bucket(VIRT_LatencyBucket *bucket, uint64_t latency) {
    for (int i = 0; i < VIRT_LATENCY_BUCKETS; i++) {
        if (latency <= bucket->bucket_limits[i]) return i;
    }
    return VIRT_LATENCY_BUCKETS - 1;
}

void virt_latency_record(const char *name, uint64_t latency_ns) {
    if (!name) return;
    for (size_t i = 0; i < g_latency_bucket_count; i++) {
        if (strcmp(g_latency_buckets[i].name, name) == 0) {
            VIRT_LatencyBucket *b = &g_latency_buckets[i];
            if (b->count == 0) {
                b->min_latency_ns = latency_ns;
                b->max_latency_ns = latency_ns;
            } else {
                if (latency_ns < b->min_latency_ns) b->min_latency_ns = latency_ns;
                if (latency_ns > b->max_latency_ns) b->max_latency_ns = latency_ns;
            }
            b->total_latency_ns += latency_ns;
            b->count++;
            int bucket_idx = virt_latency_find_bucket(b, latency_ns);
            b->bucket_counts[bucket_idx]++;
            return;
        }
    }
}

void virt_latency_dump(void) {
    VIRT_LOGI("=== Latency Histogram ===");
    for (size_t i = 0; i < g_latency_bucket_count; i++) {
        VIRT_LatencyBucket *b = &g_latency_buckets[i];
        if (b->count == 0) continue;
        uint64_t avg = b->total_latency_ns / b->count;
        VIRT_LOGI("%s: count=%llu, min=%llu, max=%llu, avg=%llu",
                  b->name, (unsigned long long)b->count,
                  (unsigned long long)b->min_latency_ns,
                  (unsigned long long)b->max_latency_ns,
                  (unsigned long long)avg);
        for (int j = 0; j < VIRT_LATENCY_BUCKETS; j++) {
            if (b->bucket_counts[j] > 0) {
                VIRT_LOGI("  < %llu ns: %llu",
                          (unsigned long long)b->bucket_limits[j],
                          (unsigned long long)b->bucket_counts[j]);
            }
        }
    }
}

// ---- Thread Monitor ----
static uint32_t g_thread_monitor_count = 0;
static VIRT_ThreadMonitor g_thread_monitors[VIRT_MAX_THREADS];
static pthread_mutex_t g_thread_monitor_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct TrieNode {
    char c;
    bool is_end;
    int action;
    int match_type;
    uint32_t priority;
    struct TrieNode *children[256];
    struct TrieNode *fallback;
    uint32_t hit_count;
    uint64_t created_ns;
    uint64_t last_hit_ns;
} TrieNode;

static TrieNode *g_trie_root = NULL;
static uint32_t g_trie_node_count = 0;
static uint64_t g_trie_total_lookups = 0;
static uint64_t g_trie_cache_hits = 0;
static pthread_mutex_t g_trie_lock = PTHREAD_MUTEX_INITIALIZER;

static TrieNode *trie_node_alloc(char c) {
    TrieNode *node = (TrieNode *)calloc(1, sizeof(TrieNode));
    if (!node) return NULL;
    node->c = c;
    node->is_end = false;
    node->action = VIRT_ACTION_PASS_THROUGH;
    node->match_type = VIRT_MATCH_EXACT;
    node->priority = 0;
    node->fallback = NULL;
    node->hit_count = 0;
    node->created_ns = virt_gettime_ns();
    node->last_hit_ns = 0;
    for (int i = 0; i < 256; i++) node->children[i] = NULL;
    __sync_fetch_and_add(&g_trie_node_count, 1);
    return node;
}

static void trie_node_free_recursive(TrieNode *node) {
    if (!node) return;
    for (int i = 0; i < 256; i++) {
        if (node->children[i]) trie_node_free_recursive(node->children[i]);
    }
    free(node);
    __sync_fetch_and_sub(&g_trie_node_count, 1);
}

// Insert a path into the trie with a given action and priority.
// @param path - slash-prefixed path string (non-null, non-empty)
// @param action - VIRT_ACTION to associate
// @param priority - higher priority overrides lower
// @return VIRT_OK on success, VIRT_ERR on failure
int virt_trie_insert(const char *path, int action, uint32_t priority) {
    if (!path || !path[0]) { VIRT_INC_ERR(VIRT_ERR_INVAL); return VIRT_ERR_INVAL; }

    size_t len = strlen(path);
    if (len >= VIRT_PATH_BUF_SIZE) { VIRT_INC_ERR(VIRT_ERR_INVAL); return VIRT_ERR_INVAL; }

    pthread_mutex_lock(&g_trie_lock);

    if (!g_trie_root) {
        g_trie_root = trie_node_alloc('\0');
        if (!g_trie_root) { pthread_mutex_unlock(&g_trie_lock); VIRT_INC_ERR(VIRT_ERR_NOMEM); return VIRT_ERR_NOMEM; }
    }

    TrieNode *node = g_trie_root;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)path[i];
        if (!node->children[c]) {
            node->children[c] = trie_node_alloc((char)c);
            if (!node->children[c]) { pthread_mutex_unlock(&g_trie_lock); VIRT_INC_ERR(VIRT_ERR_NOMEM); return VIRT_ERR_NOMEM; }
            assert(node->children[c] != NULL);
            if (node != g_trie_root && node->fallback) {
                TrieNode *fb = node->fallback;
                while (fb && !fb->children[c]) fb = fb->fallback;
                if (fb) node->children[c]->fallback = fb->children[c];
                else node->children[c]->fallback = g_trie_root;
            } else {
                node->children[c]->fallback = g_trie_root;
            }
        }
        assert(node->children[c] != NULL);
        node = node->children[c];
    }

    if (!node->is_end || priority > node->priority) {
        node->is_end = true;
        node->action = action;
        node->match_type = VIRT_MATCH_PREFIX;
        node->priority = priority;
    }

    pthread_mutex_unlock(&g_trie_lock);
    return VIRT_OK;
}

// Look up a path in the trie and retrieve the best-matching action.
// @param path - path to look up (non-null)
// @param path_len - length of path
// @param out_action - receives the matched action
// @return VIRT_OK on match, VIRT_ERR_NOENT on no match, VIRT_ERR_INVAL on bad args
int virt_trie_lookup(const char *path, size_t path_len, int *out_action) {
    if (!path || !out_action) return VIRT_ERR_INVAL;
    if (path_len == 0) return VIRT_ERR_INVAL;
    *out_action = VIRT_ACTION_PASS_THROUGH;

    __sync_fetch_and_add(&g_trie_total_lookups, 1);
    pthread_mutex_lock(&g_trie_lock);

    if (!g_trie_root) { pthread_mutex_unlock(&g_trie_lock); return VIRT_ERR_NOENT; }

    TrieNode *node = g_trie_root;
    int best_action = VIRT_ACTION_PASS_THROUGH;
    uint32_t best_priority = 0;

    for (size_t i = 0; i < path_len && node; i++) {
        unsigned char c = (unsigned char)path[i];
        while (node && !node->children[c]) node = node->fallback;
        if (!node) { node = g_trie_root; continue; }
        node = node->children[c];
        if (node->is_end && node->priority > best_priority) {
            best_action = node->action;
            best_priority = node->priority;
            __sync_fetch_and_add(&g_trie_cache_hits, 1);
        }
    }

    pthread_mutex_unlock(&g_trie_lock);

    if (best_priority > 0) {
        *out_action = best_action;
        return VIRT_OK;
    }
    return VIRT_ERR_NOENT;
}

// Build the trie from VIRT_DEFAULT_BLOCKED_PATTERNS.
// @return VIRT_OK on success
int virt_trie_build_default(void) {
    int rc = VIRT_OK;
    for (size_t i = 0; VIRT_DEFAULT_BLOCKED_PATTERNS[i] != NULL; i++) {
        const char *pat = VIRT_DEFAULT_BLOCKED_PATTERNS[i];
        int action = VIRT_ACTION_BLOCK_ENOENT;
        uint32_t prio = 100;
        if (strstr(pat, "/proc/net/")) {
            action = VIRT_ACTION_MONITOR;
            prio = 50;
        } else if (strstr(pat, "/proc/self/")) prio = 100;
        else if (strstr(pat, "/su") ||
                 strstr(pat, "/magisk") ||
                 strstr(pat, "/data/adb") ||
                 strstr(pat, "/sbin/"))
            prio = 200;
        else if (strstr(pat, "frida") ||
                 strstr(pat, "xposed") ||
                 strstr(pat, "substrate"))
            prio = 300;
        rc = virt_trie_insert(pat, action, prio);
        if (rc < 0) break;
    }
    VIRT_LOGI("Trie built: %u nodes, %zu patterns", g_trie_node_count,
              sizeof(VIRT_DEFAULT_BLOCKED_PATTERNS) / sizeof(VIRT_DEFAULT_BLOCKED_PATTERNS[0]) - 1);
    return rc;
}

// Destroy the trie and free all nodes.
void virt_trie_destroy(void) {
    pthread_mutex_lock(&g_trie_lock);
    if (g_trie_root) { trie_node_free_recursive(g_trie_root); g_trie_root = NULL; }
    g_trie_node_count = 0;
    g_trie_total_lookups = 0;
    g_trie_cache_hits = 0;
    pthread_mutex_unlock(&g_trie_lock);
}

uint32_t virt_trie_get_node_count(void) {
    return g_trie_node_count;
}

// Initialize an event ring structure.
// @param ring - ring to initialize (non-null)
// @return VIRT_OK on success
int virt_event_ring_init(VIRT_EventRing *ring) {
    if (!ring) return VIRT_ERR_INVAL;
    memset(ring, 0, sizeof(*ring));
    ring->write_pos = 0;
    ring->read_pos = 0;
    ring->count = 0;
    ring->overflow = false;
    return VIRT_OK;
}

// Push an event onto the ring buffer.
// @param ring - event ring (non-null)
// @param evt - event to push (non-null)
// @return VIRT_OK on success
int virt_event_ring_push(VIRT_EventRing *ring, const VIRT_SyscallEvent *evt) {
    if (!ring || !evt) return VIRT_ERR_INVAL;
    ring->events[ring->write_pos] = *evt;
    ring->write_pos = (ring->write_pos + 1) % VIRT_EVENT_RING_SIZE;
    if (ring->count < VIRT_EVENT_RING_SIZE) {
        ring->count++;
    } else {
        ring->read_pos = (ring->read_pos + 1) % VIRT_EVENT_RING_SIZE;
        ring->overflow = true;
    }
    return VIRT_OK;
}

// Pop the oldest event from the ring buffer.
// @param ring - event ring (non-null)
// @param evt - receives the popped event (non-null)
// @return VIRT_OK on success, VIRT_ERR_NOENT if empty
int virt_event_ring_pop(VIRT_EventRing *ring, VIRT_SyscallEvent *evt) {
    if (!ring || !evt || ring->count == 0) return VIRT_ERR_NOENT;
    *evt = ring->events[ring->read_pos];
    ring->read_pos = (ring->read_pos + 1) % VIRT_EVENT_RING_SIZE;
    ring->count--;
    return VIRT_OK;
}

int virt_event_ring_peek(const VIRT_EventRing *ring, uint32_t offset, VIRT_SyscallEvent *evt) {
    if (!ring || !evt || offset >= ring->count) return VIRT_ERR_NOENT;
    uint32_t idx = (ring->read_pos + offset) % VIRT_EVENT_RING_SIZE;
    *evt = ring->events[idx];
    return VIRT_OK;
}

uint32_t virt_event_ring_count(const VIRT_EventRing *ring) {
    return ring ? ring->count : 0;
}

int virt_kernel_probe(VIRT_KernelInfo *info) {
    if (!info) return VIRT_ERR_INVAL;
    memset(info, 0, sizeof(*info));

    FILE *f = fopen("/proc/sys/kernel/osrelease", "r");
    if (f) {
        if (fgets(info->release_str, sizeof(info->release_str), f)) {
            char *nl = strchr(info->release_str, '\n');
            if (nl) *nl = '\0';
            int n = sscanf(info->release_str, "%d.%d.%d", &info->major, &info->minor, &info->patch);
            if (n < 2) { info->major = 0; info->minor = 0; info->patch = 0; }
        }
        fclose(f);
    }

    snprintf(info->version_str, sizeof(info->version_str), "%d.%d.%d",
             info->major, info->minor, info->patch);

    int features = 0;
    virt_seccomp_get_features(&features);
    info->features_mask = features;
    info->has_user_notif   = !!(features & 1);
    info->has_new_listener = !!(features & 2);
    info->has_tsync        = !!(features & 4);
    info->has_log          = !!(features & 8);
    info->has_user_notif  ? info->has_continue = true : false;
    info->has_tsync_esrch = !!(features & 32);
    info->has_notif_sizes = !!(features & 64);

    VIRT_LOGI("Kernel: %s features=0x%x", info->release_str, features);
    return VIRT_OK;
}

int virt_process_profile_detect(VIRT_ProcessProfileInfo *info) {
    if (!info) return VIRT_ERR_INVAL;
    if (!info->name[0]) { info->profile = VIRT_PROFILE_UNKNOWN; return VIRT_OK; }

    const char *n = info->name;
    if (strstr(n, "com.tencent") || strstr(n, "com.miHoYo") ||
        strstr(n, "com.netease") || strstr(n, "com.garena") ||
        strstr(n, "com.activision") || strstr(n, "com.ea.game") ||
        strstr(n, "com.epicgames") || strstr(n, "com.roblox") ||
        strstr(n, "com.riotgames") || strstr(n, "com.valve") ||
        strstr(n, "com.kiloo") || strstr(n, "com.supercell") ||
        strstr(n, "com.king") || strstr(n, "com.zynga")) {
        info->profile = VIRT_PROFILE_GAME;
        info->is_game = true;
    } else if (strstr(n, "com.android.chrome") ||
               strstr(n, "org.mozilla.firefox") ||
               strstr(n, "com.opera") || strstr(n, "com.brave") ||
               strstr(n, "com.microsoft.emmx") ||
               strstr(n, "com.duckduckgo.mobile.android") ||
               strstr(n, "com.vivaldi")) {
        info->profile = VIRT_PROFILE_BROWSER;
        info->is_browser = true;
    } else if (strstr(n, "bank") || strstr(n, "pay") ||
               strstr(n, "fintech") || strstr(n, "wallet") ||
               strstr(n, "com.sbi") || strstr(n, "com.hdfc") ||
               strstr(n, "com.icici")) {
        info->profile = VIRT_PROFILE_BANKING;
        info->is_banking = true;
    }

    if (strstr(n, "anticheat") || strstr(n, "guard") ||
        strstr(n, "protect") || strstr(n, "security") ||
        strstr(n, "safe") || strstr(n, "xigncode") ||
        strstr(n, "battleye") || strstr(n, "easyanticheat") ||
        strstr(n, "nprotect") || strstr(n, "gameguard")) {
        info->has_anticheat = true;
    }

    return VIRT_OK;
}

int virt_cache_flush(VIRT_CacheEntry *cache, uint32_t *cache_count) {
    if (!cache || !cache_count) return VIRT_ERR_INVAL;
    memset(cache, 0, sizeof(VIRT_CacheEntry) * (*cache_count));
    *cache_count = 0;
    return VIRT_OK;
}

int virt_rules_count_by_action(const VIRT_Rule *rules, uint32_t rule_count, int action) {
    if (!rules) return 0;
    uint32_t count = 0;
    for (uint32_t i = 0; i < rule_count; i++)
        if (rules[i].enabled && rules[i].action == action) count++;
    return (int)count;
}

int virt_rules_count_by_category(const VIRT_Rule *rules, uint32_t rule_count, int category) {
    if (!rules) return 0;
    uint32_t count = 0;
    for (uint32_t i = 0; i < rule_count; i++)
        if (rules[i].enabled && rules[i].category == category) count++;
    return (int)count;
}

int virt_proc_hider_remove_pid(VIRT_ProcHiderState *state, pid_t pid) {
    if (!state || pid < 0) return VIRT_ERR_INVAL;
    for (uint32_t i = 0; i < state->hidden_pid_count; i++) {
        if (state->hidden_pids[i] == (uint32_t)pid) {
            for (uint32_t j = i; j < state->hidden_pid_count - 1; j++)
                state->hidden_pids[j] = state->hidden_pids[j + 1];
            state->hidden_pid_count--;
            return VIRT_OK;
        }
    }
    return VIRT_ERR_NOENT;
}

int virt_proc_hider_add_tid(VIRT_ProcHiderState *state, pid_t tid) {
    if (!state || tid < 0) return VIRT_ERR_INVAL;
    for (uint32_t i = 0; i < state->hidden_tid_count; i++)
        if (state->hidden_tids[i] == (uint32_t) tid) return VIRT_OK;
    if (state->hidden_tid_count < ARRAY_COUNT(state->hidden_tids))
        state->hidden_tids[state->hidden_tid_count++] = (uint32_t) tid;
    return VIRT_OK;
}

int virt_anti_tamper_check_memory(VIRT_AntiTamperState *state) {
    if (!state || !state->initialized) return VIRT_ERR_INVAL;
    if (state->module_size == 0) return VIRT_OK;

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return VIRT_ERR_GENERIC;

    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return VIRT_ERR_GENERIC;
    buf[n] = '\0';

    char *line = buf;
    bool modified = false;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        uintptr_t start, end;
        char perm[8], path[256] = "";
        if (sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*d %255s", &start, &end, perm, path) >= 3) {
            if (start <= state->module_base && state->module_base < end) {
                if (perm[0] == 'r' && perm[2] == 'x') {
                    if (perm[1] == 'w') {
                        state->code_page_writable = true;
                        modified = true;
                    }
                }
            }
        }
        if (nl) line = nl + 1; else break;
    }

    if (modified) {
        state->integrity_failures++;
        state->memory_modified = true;
        VIRT_LOGW("Memory integrity: code page writable detected!");
        return VIRT_ERR_CORRUPT;
    }

    return VIRT_OK;
}

int virt_anti_tamper_check_code(VIRT_AntiTamperState *state) {
    if (!state || !state->initialized) return VIRT_ERR_INVAL;

    Dl_info info;
    if (!dladdr((void *)virt_anti_tamper_check_code, &info)) return VIRT_ERR_NOENT;

    int fd = open(info.dli_fname, O_RDONLY);
    if (fd < 0) return VIRT_ERR_GENERIC;

    char hdr[4096];
    ssize_t n = read(fd, hdr, sizeof(hdr));
    close(fd);

    if (n > 0) {
        uint32_t hash = virt_hash_fnv1a(hdr, (size_t)n);
        if (state->expected_text_hash != 0 && hash != state->expected_text_hash) {
            state->integrity_failures++;
            state->integrity_ok = false;
            VIRT_LOGW("Code integrity: hash mismatch (0x%x != 0x%x)",
                      hash, state->expected_text_hash);
            return VIRT_ERR_CORRUPT;
        }
        if (state->expected_text_hash == 0) {
            state->expected_text_hash = hash;
        }
    }

    return VIRT_OK;
}

int virt_glob_compile(const char *pattern, VIRT_GlobPattern *out) {
    if (!pattern || !out) return VIRT_ERR_INVAL;
    memset(out, 0, sizeof(*out));
    virt_safe_strncpy(out->pattern, pattern, sizeof(out->pattern));
    out->pattern_len = (uint32_t)strlen(pattern);
    out->has_wildcard = false;
    out->has_doublestar = false;
    out->prefix_len = 0;
    out->suffix_len = 0;
    out->literal_prefix[0] = '\0';
    out->literal_suffix[0] = '\0';

    for (uint32_t i = 0; i < out->pattern_len; i++) {
        if (pattern[i] == '*' || pattern[i] == '?') {
            out->has_wildcard = true;
            if (pattern[i] == '*' && i + 1 < out->pattern_len && pattern[i + 1] == '*')
                out->has_doublestar = true;
            break;
        }
    }

    if (!out->has_wildcard) {
        memcpy(out->literal_prefix, pattern, out->pattern_len);
        out->literal_prefix[out->pattern_len] = '\0';
        out->prefix_len = out->pattern_len;
        return VIRT_OK;
    }

    uint32_t first_wc = out->pattern_len, last_wc = 0;
    for (uint32_t i = 0; i < out->pattern_len; i++) {
        if (pattern[i] == '*' || pattern[i] == '?') {
            if (first_wc == out->pattern_len) first_wc = i;
            last_wc = i;
        }
    }

    if (first_wc > 0) {
        memcpy(out->literal_prefix, pattern, first_wc);
        out->literal_prefix[first_wc] = '\0';
        out->prefix_len = first_wc;
    }

    if (last_wc < out->pattern_len - 1) {
        uint32_t ss = last_wc + 1;
        out->suffix_len = out->pattern_len - ss;
        memcpy(out->literal_suffix, pattern + ss, out->suffix_len);
        out->literal_suffix[out->suffix_len] = '\0';
    }

    uint32_t seg_idx = 0, seg_start = 0;
    for (uint32_t i = 0; i <= out->pattern_len && seg_idx < 64; i++) {
        if (i == out->pattern_len || pattern[i] == '*' || pattern[i] == '?') {
            if (i > seg_start && seg_idx < 64) {
                out->segments[seg_idx].start = seg_start;
                out->segments[seg_idx].len = i - seg_start;
                out->segments[seg_idx].is_wildcard = false;
                seg_idx++;
            }
            if (i < out->pattern_len && seg_idx < 64) {
                out->segments[seg_idx].start = i;
                out->segments[seg_idx].len = 1;
                out->segments[seg_idx].is_wildcard = true;
                out->segments[seg_idx].is_starstar = (pattern[i] == '*' && i + 1 < out->pattern_len && pattern[i + 1] == '*');
                seg_idx++;
                if (out->segments[seg_idx - 1].is_starstar) i++;
            }
            seg_start = i + 1;
        }
    }
    out->segment_count = seg_idx;
    return VIRT_OK;
}

bool virt_glob_match(const VIRT_GlobPattern *gp, const char *str, size_t len) {
    if (!gp || !str) return false;
    if (!gp->has_wildcard) return len == gp->pattern_len && memcmp(str, gp->pattern, len) == 0;
    if (gp->prefix_len > 0) {
        if (len < gp->prefix_len) return false;
        if (memcmp(str, gp->literal_prefix, gp->prefix_len) != 0) return false;
    }
    if (gp->suffix_len > 0) {
        if (len < gp->suffix_len) return false;
        if (memcmp(str + len - gp->suffix_len, gp->literal_suffix, gp->suffix_len) != 0) return false;
    }
    return true;
}

bool virt_path_match(const char *path, size_t path_len, const char *pattern, int match_type) {
    if (!path || !pattern) return false;
    size_t plen = strlen(pattern);
    switch (match_type) {
        case VIRT_MATCH_EXACT: return path_len == plen && memcmp(path, pattern, plen) == 0;
        case VIRT_MATCH_PREFIX: return path_len >= plen && memcmp(path, pattern, plen) == 0;
        case VIRT_MATCH_SUFFIX: return path_len >= plen && memcmp(path + path_len - plen, pattern, plen) == 0;
        case VIRT_MATCH_SUBSTRING: {
            if (plen > path_len) return false;
            for (size_t i = 0; i <= path_len - plen; i++)
                if (memcmp(path + i, pattern, plen) == 0) return true;
            return false;
        }
        case VIRT_MATCH_GLOB: {
            VIRT_GlobPattern gp;
            return virt_glob_compile(pattern, &gp) == VIRT_OK && virt_glob_match(&gp, path, path_len);
        }
        case VIRT_MATCH_REGEX: {
            if (plen > path_len) return false;
            for (size_t i = 0; i <= path_len - plen; i++)
                if (memcmp(path + i, pattern, plen) == 0) return true;
            return false;
        }
        case VIRT_MATCH_ALWAYS: return true;
        case VIRT_MATCH_NEVER: return false;
        default: return false;
    }
}

int virt_stats_init(VIRT_SyscallStats *stats) {
    if (!stats) return VIRT_ERR_INVAL;
    memset(stats, 0, sizeof(*stats));
    stats->min_latency_ns = UINT64_MAX;
    stats->last_reset_tp = virt_gettime_ns();
    stats->window_seconds = 60;
    stats->history_index = 0;
    stats->history_count = 0;
    stats->handler_lifespan_ns = 0;
    for (int i = 0; i < 512; i++) {
        stats->per_syscall_min[i] = UINT64_MAX;
    }
    return VIRT_OK;
}

int virt_stats_record(VIRT_SyscallStats *stats, int syscall, int action, uint64_t latency) {
    if (!stats) return VIRT_ERR_INVAL;
    stats->total_calls++;
    stats->total_latency_ns += latency;
    if (latency > stats->max_latency_ns) stats->max_latency_ns = latency;
    if (latency < stats->min_latency_ns) stats->min_latency_ns = latency;
    if (syscall >= 0 && syscall < 512) {
        stats->per_syscall[syscall]++;
        stats->per_syscall_latency[syscall] += latency;
        if (latency > stats->per_syscall_max[syscall])
            stats->per_syscall_max[syscall] = latency;
        if (latency < stats->per_syscall_min[syscall])
            stats->per_syscall_min[syscall] = latency;
        if (action >= 0 && action < VIRT_ACTION_COUNT)
            stats->per_syscall_action[syscall][action]++;
    }
    if (action >= 0 && action < VIRT_ACTION_COUNT) stats->per_action[action]++;
    switch (action) {
        case VIRT_ACTION_BLOCK_ENOENT...VIRT_ACTION_FAKE_STATUS: stats->blocked_calls++; break;
        case VIRT_ACTION_ALLOW: stats->allowed_calls++; break;
        case VIRT_ACTION_PASS_THROUGH: stats->continued_calls++; break;
        default: break;
    }
    stats->avg_latency_ns = (double)stats->total_latency_ns / (double)VIRT_MAX(stats->total_calls, 1ULL);
    uint64_t now = virt_gettime_ns();
    double elapsed = (double)(now - stats->last_reset_tp) / 1e9;
    stats->calls_per_sec = (double)stats->total_calls / VIRT_MAX(elapsed, 0.001);
    stats->blocked_percent = stats->total_calls ? 100.0 * (double)stats->blocked_calls / (double)stats->total_calls : 0.0;
    uint32_t idx = stats->history_index % VIRT_MAX_STATS_HISTORY;
    stats->history[idx].timestamp = now;
    stats->history[idx].calls = stats->total_calls;
    stats->history[idx].blocked = stats->blocked_calls;
    stats->history[idx].avg_latency = (uint64_t)stats->avg_latency_ns;
    stats->history_index++;
    if (stats->history_count < VIRT_MAX_STATS_HISTORY) stats->history_count++;
    return VIRT_OK;
}

typedef struct {
    int nr;
    uint64_t count;
} VIRT_TopEntry;

int virt_stats_snapshot(const VIRT_SyscallStats *stats, char *buf, size_t buf_size) {
    if (!stats || !buf || !buf_size) return VIRT_ERR_INVAL;
    uint64_t now = virt_gettime_ns();
    double uptime = (double)(now - stats->last_reset_tp) / 1e9;
    int off = 0;
    off += snprintf(buf + off, buf_size - (size_t)off, "=== Virtualizer Stats v%s ===\n", VIRTUALIZER_VERSION);
    off += snprintf(buf + off, buf_size - (size_t)off, "Uptime:       %10.1f sec\n", uptime);
    off += snprintf(buf + off, buf_size - (size_t)off, "Total:        %10lu\n", (unsigned long)stats->total_calls);
    off += snprintf(buf + off, buf_size - (size_t)off, "Rate:         %10.1f events/sec\n", stats->calls_per_sec);
    off += snprintf(buf + off, buf_size - (size_t)off, "Blocked:      %10lu (%5.1f%%)\n", (unsigned long)stats->blocked_calls, stats->blocked_percent);
    off += snprintf(buf + off, buf_size - (size_t)off, "Passthrough:  %10lu\n", (unsigned long)stats->continued_calls);
    off += snprintf(buf + off, buf_size - (size_t)off, "Allowed:      %10lu\n", (unsigned long)stats->allowed_calls);
    off += snprintf(buf + off, buf_size - (size_t)off, "Errors:       %10lu\n", (unsigned long)stats->error_calls);
    off += snprintf(buf + off, buf_size - (size_t)off, "Calls/sec:    %10.1f\n", stats->calls_per_sec);
    off += snprintf(buf + off, buf_size - (size_t)off, "Avg Lat:      %10.0f ns (%.2f us)\n",
                    stats->avg_latency_ns, stats->avg_latency_ns / 1000.0);
    off += snprintf(buf + off, buf_size - (size_t)off, "Max Lat:      %10lu ns\n", (unsigned long)stats->max_latency_ns);
    off += snprintf(buf + off, buf_size - (size_t)off, "Min Lat:      %10lu ns\n", (unsigned long)stats->min_latency_ns);

    /* Cache hit rate */
    uint64_t total_cache = 0;
    uint64_t total_cache_hits = 0;
    for (int i = 0; i < 512; i++) {
        total_cache_hits += stats->per_syscall_cache_hit[i];
        total_cache += stats->per_syscall_cache_hit[i] + stats->per_syscall_cache_miss[i];
    }
    double cache_pct = total_cache > 0 ? 100.0 * (double)total_cache_hits / (double)total_cache : 0.0;
    off += snprintf(buf + off, buf_size - (size_t)off, "Cache:        %10lu hits / %lu total (%5.1f%%)\n",
                    (unsigned long)total_cache_hits, (unsigned long)total_cache, cache_pct);

    /* Top 10 syscalls by count */
    {
        VIRT_TopEntry top[VIRT_STATS_TOP_SYSCALLS];
        memset(top, 0, sizeof(top));
        for (int i = 0; i < 512; i++) {
            if (stats->per_syscall[i] == 0) continue;
            uint64_t cnt = stats->per_syscall[i];
            for (int j = 0; j < VIRT_STATS_TOP_SYSCALLS; j++) {
                if (cnt > top[j].count) {
                    if (j < VIRT_STATS_TOP_SYSCALLS - 1)
                        memmove(&top[j + 1], &top[j],
                                (size_t)(VIRT_STATS_TOP_SYSCALLS - j - 1) * sizeof(VIRT_TopEntry));
                    top[j].nr = i;
                    top[j].count = cnt;
                    break;
                }
            }
        }
        off += snprintf(buf + off, buf_size - (size_t)off, "\nTop %d Syscalls:\n", VIRT_STATS_TOP_SYSCALLS);
        for (int j = 0; j < VIRT_STATS_TOP_SYSCALLS && top[j].count > 0; j++) {
            int nr = top[j].nr;
            double avg_s = stats->per_syscall[nr] > 0
                ? (double)stats->per_syscall_latency[nr] / (double)stats->per_syscall[nr] : 0.0;
            uint64_t max_s = stats->per_syscall_max[nr];
            uint64_t hits = stats->per_syscall_cache_hit[nr];
            uint64_t misses = stats->per_syscall_cache_miss[nr];
            off += snprintf(buf + off, buf_size - (size_t)off,
                "  [%3d] %-12s cnt=%6lu avg=%6.0fns max=%6luns "
                "cache=%lu/%lu",
                nr, virt_syscall_name(nr),
                (unsigned long)top[j].count,
                avg_s,
                (unsigned long)max_s,
                (unsigned long)hits,
                (unsigned long)(hits + misses));
            /* Show primary action for this syscall */
            uint64_t best_action_count = 0;
            int best_action = -1;
            for (int a = 0; a < VIRT_ACTION_COUNT; a++) {
                if (stats->per_syscall_action[nr][a] > best_action_count) {
                    best_action_count = stats->per_syscall_action[nr][a];
                    best_action = a;
                }
            }
            if (best_action >= 0) {
                off += snprintf(buf + off, buf_size - (size_t)off,
                                " act=%s(%lu)",
                                VIRT_ACTION_NAMES[best_action],
                                (unsigned long)best_action_count);
            }
            off += snprintf(buf + off, buf_size - (size_t)off, "\n");
        }
    }

    off += snprintf(buf + off, buf_size - (size_t)off, "\nPer-Action:\n");
    for (int i = 0; i < VIRT_ACTION_COUNT; i++)
        if (stats->per_action[i] > 0)
            off += snprintf(buf + off, buf_size - (size_t)off, "  %-16s %lu\n", VIRT_ACTION_NAMES[i], (unsigned long)stats->per_action[i]);

    off += snprintf(buf + off, buf_size - (size_t)off, "\nPer-Category:\n");
    for (int i = 0; i < VIRT_CAT_COUNT; i++)
        if (stats->per_category[i] > 0)
            off += snprintf(buf + off, buf_size - (size_t)off, "  %-16s %lu\n", VIRT_CATEGORY_NAMES[i], (unsigned long)stats->per_category[i]);

    return VIRT_MIN(off, (int)buf_size - 1);
}

// Look up a path in the cache.
int virt_cache_lookup(VIRT_CacheEntry *cache, uint32_t cache_count, const char *path, uint32_t path_len) {
    if (!cache || !path || !path_len) return VIRT_ERR_INVAL;
    if (path_len > VIRT_PATH_BUF_SIZE) return VIRT_ERR_INVAL;
    uint64_t now = virt_gettime_ns();
    for (uint32_t i = 0; i < cache_count; i++) {
        if (!cache[i].valid) continue;
        if (cache[i].path_len == path_len && memcmp(cache[i].path, path, path_len) == 0) {
            cache[i].hit_count++;
            if (now - cache[i].cached_at_ns > cache[i].ttl_ns) { cache[i].valid = false; return VIRT_ERR_NOENT; }
            return cache[i].is_sensitive ? cache[i].action : VIRT_ACTION_PASS_THROUGH;
        }
    }
    return VIRT_ERR_NOENT;
}

// Insert a path into the cache (evicting oldest entry if full).
// @param cache - cache array (non-null)
// @param cache_count - in/out count of entries (non-null)
// @param cache_max - maximum capacity
// @param path - path to cache
// @param path_len - length of path
// @param sensitive - whether action is sensitive (non-pass-through)
// @param action - action to cache
// @return VIRT_OK on success
int virt_cache_insert(VIRT_CacheEntry *cache, uint32_t *cache_count, uint32_t cache_max, const char *path, uint32_t path_len, bool sensitive, int action) {
    if (!cache || !cache_count || !path || !path_len || cache_max == 0) return VIRT_ERR_INVAL;
    uint32_t idx;
    if (*cache_count < cache_max) { idx = (*cache_count)++; }
    else {
        uint64_t oldest = UINT64_MAX; idx = 0;
        for (uint32_t i = 0; i < cache_max; i++) {
            if (!cache[i].valid) { idx = i; break; }
            if (cache[i].cached_at_ns < oldest) { oldest = cache[i].cached_at_ns; idx = i; }
        }
    }
    memset(&cache[idx], 0, sizeof(VIRT_CacheEntry));
    uint32_t cp = VIRT_MIN(path_len, (uint32_t)VIRT_PATH_BUF_SIZE - 1);
    memcpy(cache[idx].path, path, cp); cache[idx].path[cp] = '\0';
    cache[idx].path_len = path_len; cache[idx].is_sensitive = sensitive;
    cache[idx].action = action; cache[idx].cached_at_ns = virt_gettime_ns();
    cache[idx].ttl_ns = VIRT_CACHE_TTL_NS; cache[idx].valid = true; cache[idx].hit_count = 0;
    return VIRT_OK;
}

int virt_cache_invalidate(VIRT_CacheEntry *cache, uint32_t *cache_count, const char *path) {
    if (!cache || !cache_count || !path) return VIRT_ERR_INVAL;
    size_t plen = strlen(path); uint32_t removed = 0;
    for (uint32_t i = 0; i < *cache_count; i++) {
        if (cache[i].valid && cache[i].path_len == plen && memcmp(cache[i].path, path, plen) == 0) {
            cache[i].valid = false; removed++;
        }
    }
    return removed ? VIRT_OK : VIRT_ERR_NOENT;
}

int virt_rules_add(VIRT_Rule *rules, uint32_t *rule_count, uint32_t max_rules, const VIRT_Rule *rule) {
    if (!rules || !rule_count || !rule) return VIRT_ERR_INVAL;
    if (*rule_count >= max_rules) {
        uint32_t lowest = UINT32_MAX, repl = UINT32_MAX;
        for (uint32_t i = 0; i < *rule_count; i++)
            if (rules[i].is_default && rules[i].priority < lowest) { lowest = rules[i].priority; repl = i; }
        if (repl == UINT32_MAX) return VIRT_ERR_NOMEM;
        rules[repl] = *rule; return VIRT_OK;
    }
    rules[*rule_count] = *rule; (*rule_count)++;
    return VIRT_OK;
}

int virt_rules_remove(VIRT_Rule *rules, uint32_t *rule_count, uint32_t index) {
    if (!rules || !rule_count || index >= *rule_count) return VIRT_ERR_INVAL;
    if (rules[index].is_system) return VIRT_ERR_PERM;
    for (uint32_t i = index; i < *rule_count - 1; i++) rules[i] = rules[i + 1];
    (*rule_count)--; return VIRT_OK;
}

// Find the highest-priority rule matching a path.
// @param rules - rule array (non-null)
// @param rule_count - number of rules
// @param path - path to match
// @param path_len - length of path
// @param out_action - receives best action (non-null)
// @return VIRT_OK on match, VIRT_ERR_NOENT on no match
int virt_rules_lookup(const VIRT_Rule *rules, uint32_t rule_count, const char *path, uint32_t path_len, int *out_action) {
    if (!rules || !path || !out_action) return VIRT_ERR_INVAL;
    assert(rule_count <= VIRT_MAX_RULES);
    *out_action = VIRT_ACTION_PASS_THROUGH; int best = -1;
    for (uint32_t i = 0; i < rule_count; i++) {
        if (!rules[i].enabled) continue;
        if (virt_path_match(path, path_len, rules[i].pattern, rules[i].match_type)) {
            if ((int)rules[i].priority > best) { best = (int)rules[i].priority; *out_action = rules[i].action; }
        }
    }
    return best >= 0 ? VIRT_OK : VIRT_ERR_NOENT;
}

static int virt_rule_cmp(const void *a, const void *b) {
    const VIRT_Rule *ra = (const VIRT_Rule *)a, *rb = (const VIRT_Rule *)b;
    if (ra->priority != rb->priority) return (int)rb->priority - (int)ra->priority;
    return ra->is_system ? (rb->is_system ? 0 : 1) : (rb->is_system ? -1 : 0);
}

int virt_rules_sort(VIRT_Rule *rules, uint32_t rule_count) {
    if (!rules || !rule_count) return VIRT_ERR_INVAL;
    qsort(rules, rule_count, sizeof(VIRT_Rule), virt_rule_cmp);
    return VIRT_OK;
}

int virt_rules_load_defaults(VIRT_Rule *rules, uint32_t *rule_count, uint32_t max_rules) {
    if (!rules || !rule_count) return VIRT_ERR_INVAL;
    *rule_count = 0;
    VIRT_Rule rule;
    for (size_t i = 0; VIRT_DEFAULT_BLOCKED_PATTERNS[i] != NULL && *rule_count < max_rules; i++) {
        memset(&rule, 0, sizeof(rule));
        const char *pat = VIRT_DEFAULT_BLOCKED_PATTERNS[i];
        virt_safe_strncpy(rule.pattern, pat, sizeof(rule.pattern));
        rule.pattern_len = (uint32_t)strlen(pat);
        rule.match_type = VIRT_MATCH_SUBSTRING;
        rule.scope = VIRT_SCOPE_ALL; rule.category = VIRT_CAT_PROC; rule.priority = 100;
        rule.enabled = true; rule.is_default = true; rule.is_system = true;
        rule.created_ns = virt_gettime_ns(); rule.hit_count = 0; rule.ref_count = 1;
        if (strstr(pat, "/proc/net/")) {
            rule.action = VIRT_ACTION_MONITOR;
            rule.category = VIRT_CAT_NETWORK;
            rule.priority = 50;
        } else {
            rule.action = VIRT_ACTION_BLOCK_ENOENT;
            if (strstr(pat, "/proc/")) rule.category = VIRT_CAT_PROC;
            else if (strstr(pat, "/su") || strstr(pat, "/magisk") || strstr(pat, "/data/adb") || strstr(pat, "/sbin/")) { rule.category = VIRT_CAT_DEBUG; rule.priority = 200; }
            else if (strstr(pat, "xposed") || strstr(pat, "frida") || strstr(pat, "substrate")) { rule.category = VIRT_CAT_DEBUG; rule.priority = 300; }
        }
        rules[*rule_count] = rule; (*rule_count)++;
        virt_bloom_add(pat);
    }
    VIRT_LOGI("Loaded %u default rules", *rule_count);
    return VIRT_OK;
}

int virt_proc_hider_init(VIRT_ProcHiderState *state) {
    if (!state) return VIRT_ERR_INVAL;
    memset(state, 0, sizeof(*state));
    state->initialized = true;
    state->hide_maps = true; state->hide_fd = true; state->hide_status = true;
    state->hide_stat = true; state->hide_mountinfo = true; state->hide_cmdline = true;
    state->hide_environ = true; state->hide_limits = true; state->hide_smaps = true;
    state->hide_smaps_rollup = true; state->hide_numamaps = true; state->hide_oom = true;
    state->hide_sched = true; state->hide_cgroup = true; state->hide_attr = true;
    state->hide_task = true; state->fake_maps_content = true; state->fake_status_content = true;
    state->fake_cmdline_content = true;
    state->hidden_fd_count = 0; state->hidden_pid_count = 0; state->hidden_tid_count = 0;
    virt_safe_strncpy(state->proc_name_fake, "app_process64", sizeof(state->proc_name_fake));
    virt_safe_strncpy(state->cmdline_fake, "/system/bin/app_process64", sizeof(state->cmdline_fake));
    virt_safe_strncpy(state->fake_status_fields.name, "app_process64", sizeof(state->fake_status_fields.name));
    virt_safe_strncpy(state->fake_status_fields.state, "S (sleeping)", sizeof(state->fake_status_fields.state));
    virt_safe_strncpy(state->fake_status_fields.ppid, "1", sizeof(state->fake_status_fields.ppid));
    virt_safe_strncpy(state->fake_status_fields.uid, "10123", sizeof(state->fake_status_fields.uid));
    virt_safe_strncpy(state->fake_status_fields.gid, "10123", sizeof(state->fake_status_fields.gid));
    virt_safe_strncpy(state->fake_status_fields.tgid, "12345", sizeof(state->fake_status_fields.tgid));
    virt_safe_strncpy(state->fake_status_fields.tracerpid, "0", sizeof(state->fake_status_fields.tracerpid));
    virt_safe_strncpy(state->fake_status_fields.threads_str, "12", sizeof(state->fake_status_fields.threads_str));
    return VIRT_OK;
}

int virt_proc_hider_add_fd(VIRT_ProcHiderState *state, int fd) {
    if (!state || fd < 0) return VIRT_ERR_INVAL;
    for (uint32_t i = 0; i < state->hidden_fd_count; i++) if (state->hidden_fds[i] == (uint32_t)fd) return VIRT_OK;
    if (state->hidden_fd_count < ARRAY_COUNT(state->hidden_fds)) state->hidden_fds[state->hidden_fd_count++] = (uint32_t)fd;
    return VIRT_OK;
}

int virt_proc_hider_remove_fd(VIRT_ProcHiderState *state, int fd) {
    if (!state || fd < 0) return VIRT_ERR_INVAL;
    for (uint32_t i = 0; i < state->hidden_fd_count; i++) {
        if (state->hidden_fds[i] == (uint32_t)fd) {
            for (uint32_t j = i; j < state->hidden_fd_count - 1; j++) state->hidden_fds[j] = state->hidden_fds[j + 1];
            state->hidden_fd_count--; return VIRT_OK;
        }
    }
    return VIRT_ERR_NOENT;
}

int virt_proc_hider_add_pid(VIRT_ProcHiderState *state, pid_t pid) {
    if (!state || pid < 0) return VIRT_ERR_INVAL;
    for (uint32_t i = 0; i < state->hidden_pid_count; i++) if (state->hidden_pids[i] == (uint32_t)pid) return VIRT_OK;
    if (state->hidden_pid_count < ARRAY_COUNT(state->hidden_pids)) state->hidden_pids[state->hidden_pid_count++] = (uint32_t)pid;
    return VIRT_OK;
}

// Check if the given path refers to a hidden fd under /proc/*/fd/.
// @param state - proc hider state (non-null)
// @param path - path string (non-null)
// @param path_len - length of path
// @return 1 if path refers to a hidden fd, 0 otherwise
int virt_proc_hider_check_fd_path(VIRT_ProcHiderState *state,
                                   const char *path, uint32_t path_len) {
    if (!state || !path || !path_len) return 0;
    /* Check if path matches /proc/self/fd/<hidden_fd> or
     * /proc/<pid>/fd/<hidden_fd> */
    const char *fdmark = strstr(path, "/fd/");
    if (!fdmark) return 0;
    const char *fdnum = fdmark + 4;
    for (uint32_t i = 0; i < state->hidden_fd_count; i++) {
        char fdbuf[16];
        int n = snprintf(fdbuf, sizeof(fdbuf), "%u", state->hidden_fds[i]);
        size_t remaining = path_len - (size_t)(fdnum - path);
        if ((size_t)n <= remaining &&
            memcmp(fdnum, fdbuf, (size_t)n) == 0 &&
            (fdnum[n] == '\0' || fdnum[n] == '/' || fdnum[n] == '\n')) {
            return 1;
        }
    }
    return 0;
}

int virt_proc_hider_filter_dirents(VIRT_ProcHiderState *state,
                                    const char *dirents, uint32_t dirents_len,
                                    char *out, uint32_t *out_len) {
    if (!state || !dirents || !out || !out_len) return VIRT_ERR_INVAL;
    *out_len = 0;
    uint32_t pos = 0;
    while (pos < dirents_len) {
        struct linux_dirent64 *ent = (struct linux_dirent64 *)(dirents + pos);
        if (ent->d_reclen == 0) break;
        bool skip = false;
        for (uint32_t i = 0; i < state->hidden_fd_count; i++) {
            char fdbuf[16];
            int n = snprintf(fdbuf, sizeof(fdbuf), "%u", state->hidden_fds[i]);
            if ((size_t)n == strlen(ent->d_name) &&
                memcmp(ent->d_name, fdbuf, (size_t)n) == 0) {
                skip = true;
                break;
            }
        }
        if (!skip) {
            if (*out_len + ent->d_reclen > dirents_len) break;
            memcpy(out + *out_len, ent, ent->d_reclen);
            *out_len += ent->d_reclen;
        }
        pos += ent->d_reclen;
    }
    return VIRT_OK;
}

int virt_anti_tamper_init(VIRT_AntiTamperState *state) {
    if (!state) return VIRT_ERR_INVAL;
    memset(state, 0, sizeof(*state));
    state->initialized = true; state->integrity_ok = true;
    state->check_interval_ns = VIRT_ANTI_TAMPER_INTERVAL_NS;
    state->last_check_ns = virt_gettime_ns();
    state->total_checks = 0; state->total_alerts = 0;
    state->integrity_failures = 0; state->detected_hooks = 0;
    state->detected_debuggers = 0; state->detected_ptrace = 0;
    Dl_info info;
    if (dladdr((void *)virt_anti_tamper_init, &info)) {
        state->module_base = (uintptr_t)info.dli_fbase;
        FILE *maps = fopen("/proc/self/maps", "r");
        if (maps) {
            char line[512];
            while (fgets(line, sizeof(line), maps)) {
                uintptr_t start, end; char perm[8];
                if (sscanf(line, "%lx-%lx %4s", &start, &end, perm) >= 3) {
                    if (start <= state->module_base && state->module_base < end) {
                        state->module_size = end - start; break;
                    }
                }
            }
            fclose(maps);
        }
        int fd = open(info.dli_fname, O_RDONLY);
        if (fd >= 0) {
            char hdr[8192]; ssize_t n = read(fd, hdr, sizeof(hdr));
            if (n > 0) state->expected_text_hash = virt_hash_fnv1a(hdr, (size_t)n);
            close(fd);
        }
    }
    return VIRT_OK;
}

int virt_anti_tamper_check(VIRT_AntiTamperState *state) {
    if (!state || !state->initialized) return VIRT_ERR_INVAL;
    uint64_t now = virt_gettime_ns();
    if (now - state->last_check_ns < state->check_interval_ns) return VIRT_OK;
    state->last_check_ns = now; state->total_checks++;
    int dbg = virt_anti_tamper_detect_debugger();
    int pt = virt_anti_tamper_detect_ptrace();
    int hk = virt_anti_tamper_detect_hook();
    if (dbg > 0) { state->detected_debuggers++; state->integrity_failures++; }
    if (pt > 0) { state->detected_ptrace++; state->integrity_failures++; }
    if (hk > 0) { state->detected_hooks += (uint32_t)hk; state->integrity_failures++; }
    if (dbg > 0 || pt > 0 || hk > 0) {
        state->integrity_ok = false; state->total_alerts++;
        VIRT_LOGW("Anti-tamper alert: dbg=%d pt=%d hook=%d (alerts=%u)", dbg, pt, hk, state->total_alerts);
        return VIRT_ERR_PERM;
    }
    virt_anti_tamper_check_memory(state);
    virt_anti_tamper_check_code(state);
    state->last_check_result = state->integrity_ok ? VIRT_OK : VIRT_ERR_CORRUPT;
    return state->last_check_result;
}

int virt_is_safe_mode(void) {
    struct stat st;
    if (stat("/cache/.disable_magisk", &st) == 0) return 1;
    if (stat("/data/unencrypted/.disable_magisk", &st) == 0) return 1;
    if (stat("/persist/.disable_magisk", &st) == 0) return 1;
    if (stat("/data/adb/ksu/.disable_ksu", &st) == 0) return 1;
    return 0;
}

int virt_anti_tamper_detect_debugger(void) {
    char buf[256];
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    const char *tp = strstr(buf, "TracerPid:");
    if (!tp) return -1;
    tp += 10;
    while (*tp == ' ' || *tp == '\t') tp++;
    return (*tp != '0') ? 1 : 0;
}

int virt_anti_tamper_detect_ptrace(void) {
    /* ptrace not available on stock Android kernels. Check via /proc.
     * If PTRACE_TRACEME isn't defined, just check TracerPid. */
#ifndef PTRACE_TRACEME
    return virt_anti_tamper_detect_debugger();
#else
    int ret = ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (ret == 0) { ptrace(PTRACE_DETACH, 0, 0, 0); return 0; }
    return (errno == EPERM) ? 1 : 0;
#endif
}

/* Helper to get function addresses for hook detection */
static void *_virt_fn(const char *name) {
    void *h = dlopen("libc.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!h) return NULL;
    void *sym = dlsym(h, name);
    dlclose(h);
    return sym;
}

int virt_anti_tamper_detect_hook(void) {
    void *libc = dlopen("libc.so", RTLD_NOLOAD);
    if (!libc) return 0;
    const char *check_names[] = {
        "open", "read", "write", "close", "fstat", "mmap",
        "mprotect", "dlopen", "dlsym", "ioctl", "openat",
        "prctl", "connect",
    };
    int hooks = 0;
    for (size_t i = 0; i < ARRAY_COUNT(check_names); i++) {
        void *lib_sym = dlsym(libc, check_names[i]);
        void *real_sym = _virt_fn(check_names[i]);
        if (lib_sym && real_sym && lib_sym != real_sym) hooks++;
    }
    dlclose(libc);
    return hooks;
}

int virt_config_load(const char *path, VIRT_Config *cfg) {
    if (!path || !cfg) return VIRT_ERR_INVAL;
    *cfg = VIRT_DEFAULT_CONFIG;

    /* Try the configured path first, then fallback paths */
    const char *paths[] = {
        path,
        "/data/local/tmp/virtualizer/config.txt",
        "/data/local/tmp/virtualizer.conf",
        NULL
    };

    FILE *f = NULL;
    for (int i = 0; paths[i] != NULL; i++) {
        f = fopen(paths[i], "r");
        if (f) {
            VIRT_LOGD("Config loaded from %s", paths[i]);
            break;
        }
    }
    if (!f) return VIRT_OK;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *p = line; while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        char *eq = strchr(p, '='); if (!eq) continue;
        *eq = '\0'; char *key = p; char *val = eq + 1;
        while (*key == ' ' || *key == '\t') key++;
        char *ke = key + strlen(key) - 1; while (ke > key && (*ke == ' ' || *ke == '\t')) *ke-- = '\0';
        while (*val == ' ' || *val == '\t') val++;
        char *ve = val + strlen(val) - 1; while (ve > val && (*ve == ' ' || *ve == '\t' || *ve == '\n' || *ve == '\r')) *ve-- = '\0';
        auto set_bool = [&](bool *f) { *f = atoi(val) != 0; };
        auto set_u32 = [&](uint32_t *f) { *f = (uint32_t)atol(val); };
        if (!strcmp(key, "log_level")) cfg->log_level = atoi(val);
        else if (!strcmp(key, "filter_mode")) cfg->filter_mode = atoi(val);
        else if (!strcmp(key, "default_action")) cfg->default_action = atoi(val);
        else if (!strcmp(key, "cache_size")) set_u32(&cfg->cache_size);
        else if (!strcmp(key, "stats_window_sec")) set_u32(&cfg->stats_window_sec);
        else if (!strcmp(key, "watchdog_interval_sec")) set_u32(&cfg->watchdog_interval_sec);
        else if (!strcmp(key, "handler_stack_size")) set_u32(&cfg->handler_stack_size);
        else if (!strcmp(key, "notif_timeout_ms")) set_u32(&cfg->notif_timeout_ms);
        else if (!strcmp(key, "max_rules")) set_u32(&cfg->max_rules);
        else if (!strcmp(key, "max_consecutive_errors")) set_u32(&cfg->max_consecutive_errors);
        else if (!strcmp(key, "timing_jitter_us")) set_u32(&cfg->timing_jitter_us);
        else if (!strcmp(key, "enable_stats")) set_bool(&cfg->enable_stats);
        else if (!strcmp(key, "enable_cache")) set_bool(&cfg->enable_cache);
        else if (!strcmp(key, "enable_watchdog")) set_bool(&cfg->enable_watchdog);
        else if (!strcmp(key, "enable_anti_tamper")) set_bool(&cfg->enable_anti_tamper);
        else if (!strcmp(key, "enable_proc_hiding")) set_bool(&cfg->enable_proc_hiding);
        else if (!strcmp(key, "enable_fake_content")) set_bool(&cfg->enable_fake_content);
        else if (!strcmp(key, "enable_timing_jitter")) set_bool(&cfg->enable_timing_jitter);
        else if (!strcmp(key, "enable_thread_sync")) set_bool(&cfg->enable_thread_sync);
        else if (!strcmp(key, "enable_kernel_compat")) set_bool(&cfg->enable_kernel_compat);
        else if (!strcmp(key, "enable_self_diagnostics")) set_bool(&cfg->enable_self_diagnostics);
        else if (!strcmp(key, "enable_trie_index")) set_bool(&cfg->enable_trie_index);
        else if (!strcmp(key, "enable_event_ring")) set_bool(&cfg->enable_event_ring);
        else if (!strcmp(key, "enable_latency_tracking")) set_bool(&cfg->enable_latency_tracking);
        else if (!strcmp(key, "enable_periodic_reporting")) set_bool(&cfg->enable_periodic_reporting);
        else if (!strcmp(key, "enable_jitter")) set_bool(&cfg->enable_timing_jitter);
        else if (!strcmp(key, "jitter_base_us")) set_u32(&cfg->timing_jitter_us);
        else if (!strcmp(key, "jitter_range_us")) set_u32(&cfg->jitter_range_us);
        else if (!strcmp(key, "enable_proc_hider")) set_bool(&cfg->enable_proc_hiding);
        else if (!strcmp(key, "enable_file_decoy")) set_bool(&cfg->enable_file_decoy);
        else if (!strcmp(key, "fake_maps_path")) virt_safe_strncpy(cfg->fake_maps_path, val, sizeof(cfg->fake_maps_path));
        else if (!strcmp(key, "fake_status_path")) virt_safe_strncpy(cfg->fake_status_path, val, sizeof(cfg->fake_status_path));
        else if (!strcmp(key, "rules_json_path")) virt_safe_strncpy(cfg->rules_json_path, val, sizeof(cfg->rules_json_path));
        else if (!strcmp(key, "config_path")) virt_safe_strncpy(cfg->config_path, val, sizeof(cfg->config_path));
        else if (!strcmp(key, "rules_path")) virt_safe_strncpy(cfg->rules_path, val, sizeof(cfg->rules_path));
        else if (!strcmp(key, "log_tag")) virt_safe_strncpy(cfg->log_tag, val, sizeof(cfg->log_tag));
        else if (!strcmp(key, "package_profile")) {
            char pkg[64];
            uint32_t flags = 0;
            if (sscanf(val, "%63s %x", pkg, &flags) >= 2) {
                virt_config_add_package_profile(cfg, pkg, flags);
            }
        }
    }
    fclose(f);
    return VIRT_OK;
}

int virt_config_add_package_profile(VIRT_Config *cfg, const char *package, uint32_t flags) {
    if (!cfg || !package) return VIRT_ERR_INVAL;
    if (cfg->package_profile_count >= 16) return VIRT_ERR_BUSY;
    int idx = cfg->package_profile_count;
    virt_safe_strncpy(cfg->package_profiles[idx].package_name, package,
                      sizeof(cfg->package_profiles[idx].package_name));
    cfg->package_profiles[idx].profile_flags = flags;
    cfg->package_profile_count++;
    VIRT_LOGI("Package profile added: %s (flags=0x%04x)", package, flags);
    return VIRT_OK;
}

VIRT_PackageProfile *virt_config_find_package_profile(VIRT_Config *cfg, const char *package) {
    if (!cfg || !package) return NULL;
    for (int i = 0; i < cfg->package_profile_count; i++) {
        if (strcmp(cfg->package_profiles[i].package_name, package) == 0) {
            return &cfg->package_profiles[i];
        }
    }
    return NULL;
}

int virt_config_validate(VIRT_Config *cfg) {
    if (!cfg) return VIRT_ERR_INVAL;
    int errors = 0;

    if (cfg->handler_stack_size < 65536 || cfg->handler_stack_size > 8388608) {
        VIRT_LOGE("Config: handler_stack_size %u out of range [65536, 8388608]",
                  cfg->handler_stack_size);
        cfg->handler_stack_size = VIRT_CLAMP(cfg->handler_stack_size, 65536, 8388608);
        errors++;
    }

    if (cfg->cache_size > VIRT_MAX_CACHED_PATHS) {
        VIRT_LOGW("Config: cache_size %u capped to %u", cfg->cache_size, VIRT_MAX_CACHED_PATHS);
        cfg->cache_size = VIRT_MAX_CACHED_PATHS;
        errors++;
    }

    if (cfg->log_level < 0 || cfg->log_level > 5) {
        cfg->log_level = VIRT_CLAMP(cfg->log_level, 0, 5);
        errors++;
    }

    if (cfg->timing_jitter_us > 10000) {
        VIRT_LOGW("Config: jitter %uus seems high, clamping to 10000us", cfg->timing_jitter_us);
        cfg->timing_jitter_us = VIRT_CLAMP(cfg->timing_jitter_us, 0, 10000);
        errors++;
    }

    if (cfg->enable_file_decoy && cfg->fake_maps_path[0]) {
        if (access(cfg->fake_maps_path, R_OK) != 0) {
            VIRT_LOGW("Config: fake_maps_path %s not readable", cfg->fake_maps_path);
        }
    }

    return errors;
}

int virt_config_generate_default(const char *path) {
    if (!path) return VIRT_ERR_INVAL;
    FILE *f = fopen(path, "w");
    if (!f) return VIRT_ERR_GENERIC;
    fprintf(f, "# Universal Syscall Virtualization Framework v%s\n", VIRTUALIZER_VERSION);
    fprintf(f, "# Auto-generated default configuration\n\n");
    fprintf(f, "# Log level: 0=none, 1=error, 2=warn, 3=info, 4=debug, 5=trace\n");
    fprintf(f, "log_level=%d\n\n", VIRT_LOG_LEVEL_INFO);
    fprintf(f, "# Filter mode: 0=static BPF, 1=dynamic BPF\n");
    fprintf(f, "filter_mode=%d\n\n", VIRT_FILTER_MODE_BPF_STATIC);
    fprintf(f, "# Default action for unmatched paths\n");
    fprintf(f, "# 0=allow, 1=block-enoent, 12=pass-through\n");
    fprintf(f, "default_action=%d\n\n", VIRT_ACTION_PASS_THROUGH);
    fprintf(f, "cache_size=%u\n", VIRT_MAX_CACHED_PATHS);
    fprintf(f, "stats_window_sec=%u\n", 60);
    fprintf(f, "watchdog_interval_sec=%u\n", 5);
    fprintf(f, "handler_stack_size=%u\n", VIRT_HANDLER_STACK_SIZE);
    fprintf(f, "notif_timeout_ms=%u\n", VIRT_NOTIF_FD_TIMEOUT_MS);
    fprintf(f, "max_consecutive_errors=%u\n", 10);
    fprintf(f, "enable_stats=1\n");
    fprintf(f, "enable_cache=1\n");
    fprintf(f, "enable_watchdog=1\n");
    fprintf(f, "enable_anti_tamper=1\n");
    fprintf(f, "enable_proc_hiding=1\n");
    fprintf(f, "enable_fake_content=1\n");
    fprintf(f, "enable_thread_sync=1\n");
    fprintf(f, "enable_kernel_compat=1\n");
    fprintf(f, "enable_self_diagnostics=1\n");
    fprintf(f, "enable_trie_index=1\n");
    fprintf(f, "enable_event_ring=1\n");
    fclose(f);
    return VIRT_OK;
}

int virt_thread_monitor_init(void) {
    pthread_mutex_lock(&g_thread_monitor_lock);
    memset(g_thread_monitors, 0, sizeof(g_thread_monitors));
    g_thread_monitor_count = 0;
    pthread_mutex_unlock(&g_thread_monitor_lock);
    return VIRT_OK;
}

int virt_thread_monitor_register(pid_t tid, const char *name) {
    if (tid < 0) return VIRT_ERR_INVAL;
    pthread_mutex_lock(&g_thread_monitor_lock);
    for (uint32_t i = 0; i < g_thread_monitor_count; i++) {
        if (g_thread_monitors[i].tid == tid) {
            g_thread_monitors[i].last_seen_ns = virt_gettime_ns();
            g_thread_monitors[i].is_alive = true;
            if (name) virt_safe_strncpy(g_thread_monitors[i].name, name, 64);
            pthread_mutex_unlock(&g_thread_monitor_lock);
            return VIRT_OK;
        }
    }
    if (g_thread_monitor_count >= ARRAY_COUNT(g_thread_monitors)) {
        uint32_t oldest = 0;
        for (uint32_t i = 1; i < g_thread_monitor_count; i++)
            if (g_thread_monitors[i].last_seen_ns < g_thread_monitors[oldest].last_seen_ns) oldest = i;
        memset(&g_thread_monitors[oldest], 0, sizeof(VIRT_ThreadMonitor));
        g_thread_monitors[oldest].tid = tid;
        g_thread_monitors[oldest].created_ns = virt_gettime_ns();
        g_thread_monitors[oldest].last_seen_ns = virt_gettime_ns();
        g_thread_monitors[oldest].is_alive = true;
        if (name) virt_safe_strncpy(g_thread_monitors[oldest].name, name, 64);
        pthread_mutex_unlock(&g_thread_monitor_lock);
        return VIRT_OK;
    }
    uint32_t idx = g_thread_monitor_count++;
    memset(&g_thread_monitors[idx], 0, sizeof(VIRT_ThreadMonitor));
    g_thread_monitors[idx].tid = tid;
    g_thread_monitors[idx].created_ns = virt_gettime_ns();
    g_thread_monitors[idx].last_seen_ns = virt_gettime_ns();
    g_thread_monitors[idx].is_alive = true;
    if (name) virt_safe_strncpy(g_thread_monitors[idx].name, name, 64);
    pthread_mutex_unlock(&g_thread_monitor_lock);
    return VIRT_OK;
}

int virt_thread_monitor_update(pid_t tid, bool has_seccomp) {
    pthread_mutex_lock(&g_thread_monitor_lock);
    for (uint32_t i = 0; i < g_thread_monitor_count; i++) {
        if (g_thread_monitors[i].tid == tid) {
            g_thread_monitors[i].last_seen_ns = virt_gettime_ns();
            g_thread_monitors[i].has_seccomp = has_seccomp;
            g_thread_monitors[i].syscall_count++;
            pthread_mutex_unlock(&g_thread_monitor_lock);
            return VIRT_OK;
        }
    }
    pthread_mutex_unlock(&g_thread_monitor_lock);
    return virt_thread_monitor_register(tid, NULL);
}

int virt_thread_monitor_get_count(void) {
    pthread_mutex_lock(&g_thread_monitor_lock);
    int count = (int)g_thread_monitor_count;
    pthread_mutex_unlock(&g_thread_monitor_lock);
    return count;
}

int virt_thread_monitor_get_info(int index, VIRT_ThreadMonitor *out) {
    if (!out) return VIRT_ERR_INVAL;
    pthread_mutex_lock(&g_thread_monitor_lock);
    if (index < 0 || index >= (int)g_thread_monitor_count) { pthread_mutex_unlock(&g_thread_monitor_lock); return VIRT_ERR_NOENT; }
    *out = g_thread_monitors[index];
    pthread_mutex_unlock(&g_thread_monitor_lock);
    return VIRT_OK;
}

void virt_print_hexdump(const void *data, size_t len, const char *label) {
    if (!data || !label) return;
    const unsigned char *d = (const unsigned char *)data;
    char line[128]; int off = 0;
    off += snprintf(line + off, sizeof(line) - (size_t)off, "%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < VIRT_MIN(len, 64); i++)
        off += snprintf(line + off, sizeof(line) - (size_t)off, "%02x ", d[i]);
    VIRT_LOGD("%s", line);
}

int virt_safe_strncpy(char *dst, const char *src, size_t dst_size) {
    if (!dst || !src || !dst_size) return VIRT_ERR_INVAL;
    size_t slen = strlen(src);
    size_t copy = VIRT_MIN(slen, dst_size - 1);
    memcpy(dst, src, copy);
    dst[copy] = '\0';
    return VIRT_OK;
}

int virt_safe_strcat(char *dst, const char *src, size_t dst_size) {
    if (!dst || !src || !dst_size) return VIRT_ERR_INVAL;
    size_t dlen = strlen(dst), slen = strlen(src);
    if (dlen + slen >= dst_size) return VIRT_ERR_NOMEM;
    memcpy(dst + dlen, src, slen);
    dst[dlen + slen] = '\0';
    return VIRT_OK;
}

/* --- Shadow Library Mirror Subsystem ---
 * Hosts a pristine copy of the target library in anonymous memory.
 * Anti-cheat memory inspection that queries the execution_base region
 * will read from this untouched mirror instead of the patched original. */

static ShadowLibraryMirror g_shadow_library;

static int virt_find_library_maps(const char *lib_name,
                                   uintptr_t *out_start,
                                   uintptr_t *out_end,
                                   char *out_path, size_t path_size) {
    FILE *maps = fopen("/proc/self/maps", "re");
    if (!maps) return VIRT_ERR_NOENT;

    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        if (!strstr(line, lib_name)) continue;
        uintptr_t start, end;
        char path[256] = {0};
        if (sscanf(line, "%lx-%lx %*s %*x %*s %*u %255s",
                   &start, &end, path) >= 3) {
            *out_start = start;
            *out_end = end;
            virt_safe_strncpy(out_path, path, path_size);
            fclose(maps);
            return VIRT_OK;
        }
    }
    fclose(maps);
    return VIRT_ERR_NOENT;
}

int virt_init_shadow_library(const char *lib_name) {
    if (!lib_name) return VIRT_ERR_INVAL;
    if (g_shadow_library.initialized) return VIRT_OK;

    uintptr_t lib_start = 0, lib_end = 0;
    char lib_path[256] = {0};

    int rc = virt_find_library_maps(lib_name, &lib_start, &lib_end,
                                     lib_path, sizeof(lib_path));
    if (rc < 0) {
        VIRT_LOGW("Shadow mirror: %s not mapped (rc=%d)", lib_name, rc);
        return rc;
    }
    size_t lib_size = lib_end - lib_start;
    if (lib_size == 0) return VIRT_ERR_NOENT;

    VIRT_LOGI("Shadow mirror: found %s [%lx-%lx] (%zu bytes) file=%s",
              lib_name, lib_start, lib_end, lib_size, lib_path);

    void *mirror = mmap(NULL, lib_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mirror == MAP_FAILED) {
        VIRT_LOGE("Shadow mirror: mmap(%zu) failed: %s",
                  lib_size, strerror(errno));
        return VIRT_ERR_NOMEM;
    }

    int fd = open(lib_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        VIRT_LOGE("Shadow mirror: open %s failed: %s",
                  lib_path, strerror(errno));
        munmap(mirror, lib_size);
        return VIRT_ERR_GENERIC;
    }

    ssize_t total = 0;
    while (total < (ssize_t)lib_size) {
        ssize_t n = read(fd, (char *)mirror + total,
                          lib_size - (size_t)total);
        if (n <= 0) break;
        total += n;
    }
    close(fd);

    if (total < (ssize_t)lib_size) {
        VIRT_LOGW("Shadow mirror: short read %zd < %zu", total, lib_size);
    }

    mlock(mirror, lib_size);

    g_shadow_library.execution_base = lib_start;
    g_shadow_library.pristine_base  = (uintptr_t)mirror;
    g_shadow_library.segment_size   = lib_size;
    g_shadow_library.initialized    = true;

    VIRT_LOGI("Shadow mirror: active %zu bytes at %lx -> %lx",
              lib_size, lib_start, (uintptr_t)mirror);
    return VIRT_OK;
}

const ShadowLibraryMirror *virt_get_shadow_mirror(void) {
    return &g_shadow_library;
}

static char g_decoy_maps_buf[VIRT_PATH_BUF_SIZE * 8];
static char g_decoy_status_buf[VIRT_PATH_BUF_SIZE * 4];
static bool g_decoy_maps_loaded = false;
static bool g_decoy_status_loaded = false;

int virt_decoy_load_from_file(const char *filepath, char *out_buf, size_t buf_size) {
    if (!filepath || !out_buf || buf_size == 0) return VIRT_ERR_INVAL;
    int fd = open(filepath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        VIRT_LOGW("Decoy file open failed: %s (%s)", filepath, strerror(errno));
        return VIRT_ERR_NOENT;
    }
    ssize_t n = read(fd, out_buf, buf_size - 1);
    if (n < 0) {
        VIRT_LOGE("Decoy file read failed: %s (%s)", filepath, strerror(errno));
        close(fd);
        return VIRT_ERR_GENERIC;
    }
    close(fd);
    out_buf[n] = '\0';
    while (n > 0 && (out_buf[n - 1] == '\n' || out_buf[n - 1] == '\r'))
        out_buf[--n] = '\0';
    VIRT_LOGI("Decoy loaded: %s (%zd bytes)", filepath, n);
    return (int)n;
}

static int json_skip_ws(const char **p) {
    while (**p == ' ' || **p == '\t' || **p == '\n' || **p == '\r')
        (*p)++;
    return 0;
}

static int json_match(const char **p, char c) {
    json_skip_ws(p);
    if (**p == c) { (*p)++; return 0; }
    return -1;
}

static int json_parse_string(const char **p, char *out, size_t out_size) {
    json_skip_ws(p);
    if (**p != '"') return -1;
    (*p)++;
    size_t i = 0;
    while (**p && **p != '"' && i + 1 < out_size) {
        if (**p == '\\' && *(*p + 1)) {
            (*p)++;
            switch (**p) {
                case '"': out[i++] = '"'; break;
                case '\\': out[i++] = '\\'; break;
                case '/': out[i++] = '/'; break;
                case 'n': out[i++] = '\n'; break;
                case 'r': out[i++] = '\r'; break;
                case 't': out[i++] = '\t'; break;
                default: out[i++] = **p; break;
            }
        } else {
            out[i++] = **p;
        }
        (*p)++;
    }
    if (**p != '"') return -1;
    out[i] = '\0';
    (*p)++;
    return (int)i;
}

static int json_parse_int(const char **p, int *out) {
    json_skip_ws(p);
    int sign = 1;
    if (**p == '-') { sign = -1; (*p)++; }
    if (!isdigit((unsigned char)**p)) return -1;
    int val = 0;
    while (isdigit((unsigned char)**p)) {
        val = val * 10 + (**p - '0');
        (*p)++;
    }
    *out = val * sign;
    return 0;
}

static int json_match_type_from_string(const char *s) {
    if (strcmp(s, "exact") == 0)    return VIRT_MATCH_EXACT;
    if (strcmp(s, "prefix") == 0)   return VIRT_MATCH_PREFIX;
    if (strcmp(s, "suffix") == 0)   return VIRT_MATCH_SUFFIX;
    if (strcmp(s, "substr") == 0)   return VIRT_MATCH_SUBSTRING;
    if (strcmp(s, "glob") == 0)     return VIRT_MATCH_GLOB;
    return -1;
}

static int json_action_from_string(const char *s) {
    if (strcmp(s, "allow") == 0)        return VIRT_ACTION_ALLOW;
    if (strcmp(s, "block_enoent") == 0 || strcmp(s, "block-enoent") == 0)
        return VIRT_ACTION_BLOCK_ENOENT;
    if (strcmp(s, "block_eacces") == 0 || strcmp(s, "block-eacces") == 0)
        return VIRT_ACTION_BLOCK_EACCES;
    if (strcmp(s, "block_eperm") == 0 || strcmp(s, "block-eperm") == 0)
        return VIRT_ACTION_BLOCK_EPERM;
    if (strcmp(s, "block_enxio") == 0 || strcmp(s, "block-enxio") == 0)
        return VIRT_ACTION_BLOCK_ENXIO;
    if (strcmp(s, "block_eio") == 0 || strcmp(s, "block-eio") == 0)
        return VIRT_ACTION_BLOCK_EIO;
    if (strcmp(s, "block_erofs") == 0 || strcmp(s, "block-erofs") == 0)
        return VIRT_ACTION_BLOCK_EROFS;
    if (strcmp(s, "redirect") == 0)     return VIRT_ACTION_REDIRECT_PATH;
    if (strcmp(s, "fake_content") == 0 || strcmp(s, "fake-content") == 0)
        return VIRT_ACTION_FAKE_CONTENT;
    if (strcmp(s, "fake_empty") == 0 || strcmp(s, "fake-empty") == 0)
        return VIRT_ACTION_FAKE_EMPTY;
    if (strcmp(s, "fake_maps") == 0 || strcmp(s, "fake-maps") == 0)
        return VIRT_ACTION_FAKE_MAPS;
    if (strcmp(s, "fake_status") == 0 || strcmp(s, "fake-status") == 0)
        return VIRT_ACTION_FAKE_STATUS;
    if (strcmp(s, "pass_through") == 0 || strcmp(s, "pass-through") == 0)
        return VIRT_ACTION_PASS_THROUGH;
    if (strcmp(s, "kill") == 0)         return VIRT_ACTION_BLOCK_EPERM;
    return -1;
}

static int json_category_from_string(const char *s) {
    if (strcmp(s, "proc") == 0)    return VIRT_CAT_PROC;
    if (strcmp(s, "debug") == 0)   return VIRT_CAT_DEBUG;
    if (strcmp(s, "root") == 0)    return VIRT_CAT_DEBUG;
    if (strcmp(s, "hook") == 0)    return VIRT_CAT_DEBUG;
    if (strcmp(s, "system") == 0)  return VIRT_CAT_FILE_READ;
    if (strcmp(s, "tmp") == 0)     return VIRT_CAT_FILE_WRITE;
    if (strcmp(s, "sys") == 0)     return VIRT_CAT_FILE_META;
    if (strcmp(s, "app") == 0)     return VIRT_CAT_OTHER;
    if (strcmp(s, "other") == 0)   return VIRT_CAT_OTHER;
    return VIRT_CAT_OTHER;
}

int virt_rules_load_json(const char *filepath, VIRT_Rule *rules,
                         uint32_t *rule_count, uint32_t max_rules) {
    if (!filepath || !rules || !rule_count) return VIRT_ERR_INVAL;

    FILE *f = fopen(filepath, "r");
    if (!f) return VIRT_ERR_NOENT;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize <= 0) { fclose(f); return VIRT_ERR_NOENT; }
    fseek(f, 0, SEEK_SET);

    char *data = (char *)malloc((size_t)fsize + 1);
    if (!data) { fclose(f); return VIRT_ERR_NOMEM; }

    size_t nread = fread(data, 1, (size_t)fsize, f);
    fclose(f);
    if ((long)nread != fsize) { free(data); return VIRT_ERR_IO; }
    data[nread] = '\0';

    const char *p = data;
    int loaded = 0;

    json_skip_ws(&p);
    if (*p != '[') { free(data); return -1; }
    p++;

    while (*p && *p != ']') {
        json_skip_ws(&p);
        if (*p == ']') break;
        if (*p != '{') { p++; continue; }
        p++;

        char key[256];
        char pattern[VIRT_PATH_BUF_SIZE] = {0};
        char match_type_str[64] = {0};
        char action_str[64] = {0};
        char redirect_target[VIRT_PATH_BUF_SIZE] = {0};
        char fake_content_path[VIRT_PATH_BUF_SIZE] = {0};
        char category_str[64] = {0};
        int priority = 0;
        bool has_priority = false;
        bool valid = true;

        while (*p && *p != '}' && valid) {
            json_skip_ws(&p);
            if (*p == '}') break;

            if (json_parse_string(&p, key, sizeof(key)) < 0) {
                valid = false; break;
            }
            if (json_match(&p, ':') < 0) { valid = false; break; }

            if (strcmp(key, "pattern") == 0) {
                if (json_parse_string(&p, pattern, sizeof(pattern)) < 0)
                    valid = false;
            } else if (strcmp(key, "match_type") == 0) {
                if (json_parse_string(&p, match_type_str, sizeof(match_type_str)) < 0)
                    valid = false;
            } else if (strcmp(key, "action") == 0) {
                if (json_parse_string(&p, action_str, sizeof(action_str)) < 0)
                    valid = false;
            } else if (strcmp(key, "redirect_target") == 0) {
                if (json_parse_string(&p, redirect_target, sizeof(redirect_target)) < 0)
                    valid = false;
            } else if (strcmp(key, "fake_content_path") == 0) {
                if (json_parse_string(&p, fake_content_path, sizeof(fake_content_path)) < 0)
                    valid = false;
            } else if (strcmp(key, "category") == 0) {
                if (json_parse_string(&p, category_str, sizeof(category_str)) < 0)
                    valid = false;
            } else if (strcmp(key, "priority") == 0) {
                if (json_parse_int(&p, &priority) == 0)
                    has_priority = true;
                else
                    valid = false;
            } else {
                json_skip_ws(&p);
                if (*p == '"') {
                    char skip[256];
                    json_parse_string(&p, skip, sizeof(skip));
                } else if (*p == '-' || isdigit((unsigned char)*p)) {
                    int dummy;
                    json_parse_int(&p, &dummy);
                }
            }

            json_skip_ws(&p);
            if (*p == ',') p++;
        }

        if (*p == '}') p++;

        if (!valid || pattern[0] == '\0' || action_str[0] == '\0') {
            json_skip_ws(&p);
            if (*p == ',') p++;
            continue;
        }

        int match_type = match_type_str[0]
            ? json_match_type_from_string(match_type_str)
            : VIRT_MATCH_EXACT;
        int action = json_action_from_string(action_str);
        if (match_type < 0 || action < 0) {
            json_skip_ws(&p);
            if (*p == ',') p++;
            continue;
        }

        if (*rule_count >= max_rules) { free(data); return loaded; }

        VIRT_Rule *r = &rules[*rule_count];
        memset(r, 0, sizeof(VIRT_Rule));
        virt_safe_strncpy(r->pattern, pattern, sizeof(r->pattern));
        r->pattern_len = (uint32_t)strlen(pattern);
        r->match_type = match_type;
        r->action = action;
        r->scope = VIRT_SCOPE_ALL;
        r->category = category_str[0]
            ? json_category_from_string(category_str)
            : VIRT_CAT_OTHER;
        r->priority = has_priority ? (uint32_t)priority : 0;
        if (redirect_target[0])
            virt_safe_strncpy(r->redirect_target, redirect_target,
                              sizeof(r->redirect_target));
        if (fake_content_path[0])
            virt_safe_strncpy(r->fake_content_path, fake_content_path,
                              sizeof(r->fake_content_path));
        r->enabled = true;
        r->is_default = false;
        r->is_system = false;
        r->created_ns = virt_gettime_ns();
        r->ref_count = 1;
        (*rule_count)++;
        loaded++;

        json_skip_ws(&p);
        if (*p == ',') p++;
    }

    free(data);
    return loaded;
}

int virt_detect_environment(void) {
    if (access("/data/adb/magisk", F_OK) == 0) return VIRT_ENV_MAGISK;
    if (access("/data/adb/ksu", F_OK) == 0) return VIRT_ENV_KERNELSU;
    if (access("/data/adb/ap", F_OK) == 0) return VIRT_ENV_APATCH;
    return VIRT_ENV_UNKNOWN;
}

int virt_check_environment_support(void) {
    int env = virt_detect_environment();
    switch (env) {
        case VIRT_ENV_MAGISK:
            /* Magisk has native Zygisk — fully supported */
            return 1;
        case VIRT_ENV_KERNELSU:
        case VIRT_ENV_APATCH:
            /* KernelSU/APatch need ZygiskNext for Zygisk support */
            if (access("/data/adb/modules/zygisk_next", F_OK) == 0)
                return 1;
            if (access("/data/adb/modules/zygisk-ng", F_OK) == 0)
                return 1;
            if (access("/data/adb/modules/zygisksu", F_OK) == 0)
                return 1;
            /* ZygiskNext not detected — still return 1 since we hook
             * via onLoad which is only called when Zygisk is present */
            VIRT_LOGW("KernelSU/APatch detected but no ZygiskNext found");
            return 1;
        default:
            VIRT_LOGW("Unknown root environment");
            return 0;
    }
}

int virt_reload_rules(VIRT_Rule *rules, uint32_t *rule_count, uint32_t max_rules) {
    if (!rules || !rule_count) return VIRT_ERR_INVAL;
    virt_rules_load_defaults(rules, rule_count, max_rules);
    int json_count = virt_rules_load_json(
        VIRT_DEFAULT_CONFIG.rules_json_path,
        rules, rule_count, max_rules);
    if (json_count >= 0) {
        virt_rules_sort(rules, *rule_count);
        VIRT_LOGI("Reloaded %u default + %d JSON rules", *rule_count, json_count);
    } else {
        VIRT_LOGI("Reloaded %u default rules (no JSON)", *rule_count);
    }
    return VIRT_OK;
}

int virt_stats_dump_to_file(const char *filepath, const VIRT_SyscallStats *stats) {
    if (!filepath || !stats) return VIRT_ERR_INVAL;

    char buf[8192];
    int len = virt_stats_snapshot(stats, buf, sizeof(buf));
    if (len < 0) return VIRT_ERR_GENERIC;

    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return VIRT_ERR_GENERIC;
    ssize_t written = write(fd, buf, (size_t)len);
    close(fd);
    return (written == len) ? VIRT_OK : VIRT_ERR_GENERIC;
}

static pthread_mutex_t g_virt_log_lock = PTHREAD_MUTEX_INITIALIZER;

void virt_log_event(const char *event_type, const char *path, int action) {
    if (!event_type || !path) return;

    const char *log_dir = "/data/local/tmp/virtualizer";
    const char *log_file = "/data/local/tmp/virtualizer/events.log";
    const size_t max_lines = 10000;

    pthread_mutex_lock(&g_virt_log_lock);

    mkdir(log_dir, 0755);

    uint64_t now_ns = virt_gettime_realtime_ns();
    time_t sec = (time_t)(now_ns / 1000000000ULL);
    struct tm tm;
    localtime_r(&sec, &tm);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm);

    const char *action_name = "unknown";
    for (size_t i = 0; i < ARRAY_COUNT(ACTION_TABLE); i++) {
        if (ACTION_TABLE[i].action == action) {
            action_name = ACTION_TABLE[i].name;
            break;
        }
    }
    if (action == VIRT_ACTION_REDIRECT_PATH) action_name = "redirect";
    else if (action == VIRT_ACTION_FAKE_CONTENT) action_name = "fake-content";
    else if (action == VIRT_ACTION_FAKE_EMPTY) action_name = "fake-empty";
    else if (action == VIRT_ACTION_FAKE_MAPS) action_name = "fake-maps";
    else if (action == VIRT_ACTION_FAKE_STATUS) action_name = "fake-status";

    FILE *f = fopen(log_file, "a+");
    if (!f) { pthread_mutex_unlock(&g_virt_log_lock); return; }

    fprintf(f, "[%s] %s: %s\n", timestamp, action_name, path);
    fflush(f);

    long line_count = 0;
    fseek(f, 0, SEEK_SET);
    int c;
    while ((c = fgetc(f)) != EOF) {
        if (c == '\n') line_count++;
    }

    if ((unsigned long)line_count > max_lines) {
        fclose(f);

        char tmp_path[VIRT_PATH_BUF_SIZE];
        snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", log_file);
        int src_fd = open(log_file, O_RDONLY);
        int dst_fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (src_fd >= 0 && dst_fd >= 0) {
            long skip_lines = line_count - (long)(max_lines / 2);
            int fd_c;
            long lc = 0;
            char ch;
            while ((fd_c = (int)read(src_fd, &ch, 1)) > 0) {
                if (lc >= skip_lines) write(dst_fd, &ch, 1);
                if (ch == '\n') lc++;
            }
        }
        if (src_fd >= 0) close(src_fd);
        if (dst_fd >= 0) close(dst_fd);
        rename(tmp_path, log_file);
    } else {
        fclose(f);
    }

    pthread_mutex_unlock(&g_virt_log_lock);
}

int virt_decoy_init(VIRT_Config *cfg) {
    if (!cfg) return VIRT_ERR_INVAL;
    if (!cfg->enable_file_decoy) {
        VIRT_LOGI("File decoy: disabled");
        return VIRT_OK;
    }
    if (cfg->fake_maps_path[0]) {
        int ret = virt_decoy_load_from_file(cfg->fake_maps_path,
                                            g_decoy_maps_buf,
                                            sizeof(g_decoy_maps_buf));
        if (ret >= 0) g_decoy_maps_loaded = true;
    }
    if (cfg->fake_status_path[0]) {
        int ret = virt_decoy_load_from_file(cfg->fake_status_path,
                                            g_decoy_status_buf,
                                            sizeof(g_decoy_status_buf));
        if (ret >= 0) g_decoy_status_loaded = true;
    }
    VIRT_LOGI("File decoy: maps=%s status=%s",
              g_decoy_maps_loaded ? "loaded" : "unavailable",
              g_decoy_status_loaded ? "loaded" : "unavailable");
    return VIRT_OK;
}

int virt_scan_for_frida(void) {
    char line[512];
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    const char *frida_signatures[] = {
        "frida", "frida-agent", "frida-helper", "frida-gadget",
        "gum-", "gumjs", "_frida_", "libfrida", NULL
    };

    while (fgets(line, sizeof(line), fp)) {
        for (int i = 0; frida_signatures[i]; i++) {
            if (strstr(line, frida_signatures[i])) {
                fclose(fp);
                VIRT_LOGW("Frida detected: %s", line);
                return 1;
            }
        }
    }
    fclose(fp);
    return 0;
}

int virt_scan_for_xposed(void) {
    char line[512];
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    const char *xposed_signatures[] = {
        "xposed", "edxp", "lsposed", "riru", "substrate", NULL
    };

    while (fgets(line, sizeof(line), fp)) {
        for (int i = 0; xposed_signatures[i]; i++) {
            if (strstr(line, xposed_signatures[i])) {
                fclose(fp);
                VIRT_LOGW("Xposed detected: %s", line);
                return 1;
            }
        }
    }
    fclose(fp);
    return 0;
}

void virt_hide_from_frida(void) {
    VIRT_LOGD("Frida hide: periodic scan check");
}

void virt_hide_from_xposed(void) {
    VIRT_LOGD("Xposed hide: periodic scan check");
}

static void virt_log_tamper_warning(const char *msg) {
    mkdir("/data/local/tmp/virtualizer", 0755);
    FILE *f = fopen("/data/local/tmp/virtualizer/tamper_warnings.log", "a");
    if (!f) return;
    uint64_t now_ns = virt_gettime_realtime_ns();
    time_t sec = (time_t)(now_ns / 1000000000ULL);
    struct tm tm;
    localtime_r(&sec, &tm);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(f, "[%s] %s\n", timestamp, msg);
    fflush(f);
    fclose(f);
}

static void virt_rotate_log(const char *path, size_t max_bytes) {
    struct stat st;
    if (stat(path, &st) != 0) return;
    if ((size_t)st.st_size < max_bytes) return;
    char tmp[VIRT_PATH_BUF_SIZE];
    snprintf(tmp, sizeof(tmp), "%s.old", path);
    rename(path, tmp);
}

static int virt_check_ld_preload(void) {
    const char *ld = getenv("LD_PRELOAD");
    if (!ld) return 0;
    if (strstr(ld, "frida") || strstr(ld, "xposed") ||
        strstr(ld, "substrate") || strstr(ld, "hook") ||
        strstr(ld, "inject") || strstr(ld, "dobby") ||
        strstr(ld, "bhook")) {
        VIRT_LOGW("Tamper: LD_PRELOAD suspicious: %s", ld);
        return 1;
    }
    return 0;
}

int virt_scan_sockets(VIRT_SocketInfo *sockets, int max_sockets) {
    if (!sockets || max_sockets <= 0) return 0;
    int count = 0;
    DIR *d = opendir("/proc/self/fd");
    if (!d) return 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && count < max_sockets) {
        if (de->d_name[0] == '.') continue;
        int fd = atoi(de->d_name);
        if (fd < 0) continue;
        struct stat st;
        if (fstat(fd, &st) < 0) continue;
        if (!S_ISSOCK(st.st_mode)) continue;
        sockets[count].fd = fd;
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);
        if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) == 0) {
            if (addr.ss_family == AF_UNIX) {
                struct sockaddr_un *un = (struct sockaddr_un *)&addr;
                virt_safe_strncpy(sockets[count].name, un->sun_path, sizeof(sockets[count].name));
            } else if (addr.ss_family == AF_INET) {
                struct sockaddr_in *in = (struct sockaddr_in *)&addr;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
                snprintf(sockets[count].name, sizeof(sockets[count].name),
                         "tcp:%s:%u", ip, ntohs(in->sin_port));
            } else if (addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&addr;
                char ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));
                snprintf(sockets[count].name, sizeof(sockets[count].name),
                         "tcp6:[%s]:%u", ip, ntohs(in6->sin6_port));
            } else {
                virt_safe_strncpy(sockets[count].name, "unknown", sizeof(sockets[count].name));
            }
        } else {
            virt_safe_strncpy(sockets[count].name, "unix", sizeof(sockets[count].name));
        }
        count++;
    }
    closedir(d);
    return count;
}

static int virt_check_suspicious_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return 0;
    struct dirent *de;
    int suspicious = 0;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char link[VIRT_PATH_BUF_SIZE];
        char path[VIRT_PATH_BUF_SIZE];
        snprintf(path, sizeof(path), "/proc/self/fd/%s", de->d_name);
        ssize_t n = readlink(path, link, sizeof(link) - 1);
        if (n > 0) {
            link[n] = '\0';
            if (strstr(link, "frida") || strstr(link, "linjector") ||
                strstr(link, "gdb") || strstr(link, "gdbserver") ||
                strstr(link, "strace") || strstr(link, "ptrace") ||
                strstr(link, "magisk") || strstr(link, "ksu")) {
                VIRT_LOGW("Tamper: suspicious fd %s -> %s", de->d_name, link);
                suspicious++;
            }
        }
    }
    closedir(d);
    return suspicious;
}

void virt_anti_tamper_check_self(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return;
    char line[256];
    pid_t tracer_pid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "TracerPid:\t%d", &tracer_pid) == 1) {
            break;
        }
    }
    fclose(f);

    if (tracer_pid > 0) {
        VIRT_LOGW("Self-tamper detected: tracer pid=%d", tracer_pid);
        g_anti_tamper_state.tamper_detected = true;
        g_anti_tamper_state.tamper_type = VIRT_TAMPER_TRACING;
        g_anti_tamper_state.last_tamper_time = time(NULL);
        g_anti_tamper_state.tamper_count++;
        return;
    }

    int ret = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    if (ret <= 0) {
        VIRT_LOGW("Seccomp filter removed! ret=%d", ret);
        g_anti_tamper_state.tamper_detected = true;
        g_anti_tamper_state.tamper_type = VIRT_TAMPER_SECCOMP;
        g_anti_tamper_state.last_tamper_time = time(NULL);
        g_anti_tamper_state.tamper_count++;
    }

    struct pollfd pfd = { .fd = g_virt_notify_fd, .events = POLLIN };
    if (g_virt_notify_fd >= 0 && poll(&pfd, 1, 0) < 0 && errno == EBADF) {
        VIRT_LOGW("Notify fd invalidated!");
        g_anti_tamper_state.tamper_detected = true;
        g_anti_tamper_state.tamper_type = VIRT_TAMPER_NOTIFY_FD;
        g_anti_tamper_state.last_tamper_time = time(NULL);
        g_anti_tamper_state.tamper_count++;
    }
}

int virt_compute_detection_score(VIRT_DetectionScore *score) {
    if (!score) return VIRT_ERR_INVAL;
    memset(score, 0, sizeof(*score));

    if (access("/system/app/Superuser.apk", F_OK) == 0) score->root_score += 0.3f;
    if (access("/data/data/com.topjohnwu.magisk", F_OK) == 0) score->root_score += 0.5f;
    if (access("/data/adb/magisk", F_OK) == 0) score->root_score += 0.4f;
    if (access("/sbin/su", F_OK) == 0) score->root_score += 0.3f;
    if (access("/system/xbin/su", F_OK) == 0) score->root_score += 0.3f;

    if (access("/data/local/tmp/frida-server", F_OK) == 0) score->frida_score += 0.5f;
    if (access("/data/local/tmp/re.frida", F_OK) == 0) score->frida_score += 0.4f;
    if (access("/data/local/tmp/.frida", F_OK) == 0) score->frida_score += 0.3f;
    {
        char maps_line[512];
        FILE *mp = fopen("/proc/self/maps", "r");
        if (mp) {
            while (fgets(maps_line, sizeof(maps_line), mp)) {
                if (strstr(maps_line, "frida") || strstr(maps_line, "gum-")) {
                    score->frida_score += 0.4f;
                    break;
                }
            }
            fclose(mp);
        }
    }
    score->frida_score = VIRT_MIN(score->frida_score, 1.0f);

    if (access("/data/local/tmp/xposed", F_OK) == 0) score->xposed_score += 0.4f;
    if (access("/data/local/tmp/lsposed", F_OK) == 0) score->xposed_score += 0.5f;
    if (access("/data/local/tmp/edxposed", F_OK) == 0) score->xposed_score += 0.4f;
    if (access("/data/local/tmp/riru", F_OK) == 0) score->xposed_score += 0.3f;
    {
        char maps_line[512];
        FILE *mp = fopen("/proc/self/maps", "r");
        if (mp) {
            while (fgets(maps_line, sizeof(maps_line), mp)) {
                if (strstr(maps_line, "xposed") || strstr(maps_line, "lsposed") ||
                    strstr(maps_line, "edxp") || strstr(maps_line, "riru") ||
                    strstr(maps_line, "substrate")) {
                    score->xposed_score += 0.4f;
                    break;
                }
            }
            fclose(mp);
        }
    }
    score->xposed_score = VIRT_MIN(score->xposed_score, 1.0f);

    {
        char pname[256] = {};
        int fd = open("/proc/self/cmdline", O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, pname, sizeof(pname) - 1);
            close(fd);
            if (n > 0) {
                if (strstr(pname, "blue") || strstr(pname, "emu") ||
                    strstr(pname, "virtual") || strstr(pname, "nox") ||
                    strstr(pname, "mumu") || strstr(pname, "ldplayer")) {
                    score->emulator_score = 0.5f;
                }
            }
        }
    }
    {
        char line[256];
        FILE *fp = fopen("/proc/self/status", "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "TracerPid:")) {
                    int tp = 0;
                    if (sscanf(line, "TracerPid:\t%d", &tp) == 1 && tp > 0)
                        score->debugger_score = 0.8f;
                    break;
                }
            }
            fclose(fp);
        }
    }

    score->overall_score = (score->root_score + score->frida_score +
                           score->xposed_score + score->emulator_score +
                           score->debugger_score) / 5.0f;

    snprintf(score->recommendations, sizeof(score->recommendations),
             "Recommendations:\n"
             "- Root risk: %.0f%%\n"
             "- Frida risk: %.0f%%\n"
             "- Xposed risk: %.0f%%\n"
             "- Emulator risk: %.0f%%\n"
             "- Debugger risk: %.0f%%\n"
             "- Overall: %.0f%%",
             score->root_score * 100, score->frida_score * 100,
             score->xposed_score * 100, score->emulator_score * 100,
             score->debugger_score * 100,
             score->overall_score * 100);

    return VIRT_OK;
}

void virt_detection_score_log(void) {
    VIRT_DetectionScore score;
    if (virt_compute_detection_score(&score) != VIRT_OK) return;
    VIRT_LOGI("Detection Score Report:\n%s", score.recommendations);
    if (score.overall_score > 0.3f) {
        VIRT_LOGW("Detection risk elevated: %.0f%% overall", score.overall_score * 100);
    } else if (score.overall_score > 0.6f) {
        VIRT_LOGE("Detection risk CRITICAL: %.0f%% overall", score.overall_score * 100);
    }
}

int virt_anti_tamper_loop(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "anti-tamper", 0, 0, 0);
    virt_anti_tamper_init(&g_anti_tamper_state);

    VIRT_LOGI("Anti-tamper loop started (interval=30s)");
    uint64_t last_mem_check = 0;
    int socket_suspicion = 0;
    while (1) {
        struct timespec ts = { .tv_sec = 30, .tv_nsec = 0 };
        nanosleep(&ts, NULL);

        uint64_t now = virt_gettime_ns();
        if (now - last_mem_check >= (60ULL * VIRT_NS_PER_SEC)) {
            last_mem_check = now;
            int pressure = virt_mem_check_pressure();
            if (pressure > 0) {
                virt_mem_reduce_footprint();
            }
            VIRT_LOGI("Memory stats: usage=%zu peak=%zu oom=%u",
                      virt_mem_get_usage(), virt_mem_get_peak(), g_mem_stats.oom_count);
        }

        int dbg = virt_anti_tamper_detect_debugger();
        int pt  = virt_anti_tamper_detect_ptrace();
        int hk  = virt_anti_tamper_detect_hook();
        int ld  = virt_check_ld_preload();
        int sfd = virt_check_suspicious_fds();

        /* Socket scan for anti-cheat named sockets */
        VIRT_SocketInfo sockets[32];
        int num_sockets = virt_scan_sockets(sockets, 32);
        int ac_sockets = 0;
        static const char *ac_socket_patterns[] = {
            "titanium", "dplugins", "xigncode",
            "easyanticheat", "battleye", NULL
        };
        for (int si = 0; si < num_sockets; si++) {
            for (int spi = 0; ac_socket_patterns[spi]; spi++) {
                if (strstr(sockets[si].name, ac_socket_patterns[spi])) {
                    VIRT_LOGW("Socket: fd=%d name=%s (anti-cheat)",
                              sockets[si].fd, sockets[si].name);
                    ac_sockets++;
                    socket_suspicion++;
                    break;
                }
            }
        }
        if (num_sockets > 0 && VIRT_LOG_LEVEL >= VIRT_LOG_LEVEL_DEBUG) {
            VIRT_LOGD("Socket scan: %d total, %d anti-cheat", num_sockets, ac_sockets);
        }

        if (dbg > 0 || pt > 0 || hk > 0 || ld > 0 || sfd > 0 || ac_sockets > 0) {
            char warn[512];
            snprintf(warn, sizeof(warn),
                     "Tamper: dbg=%d pt=%d hooks=%d ld_preload=%d susp_fds=%d ac_sockets=%d (suspicion=%d)",
                     dbg, pt, hk, ld, sfd, ac_sockets, socket_suspicion);
            VIRT_LOGW("%s", warn);
            virt_log_tamper_warning(warn);
        }

        virt_anti_tamper_check_memory(&g_anti_tamper_state);
        virt_anti_tamper_check_code(&g_anti_tamper_state);

        if (virt_scan_for_frida()) {
            VIRT_LOGW("Anti-tamper: Frida detected in process!");
            virt_log_tamper_warning("Frida detected in process");
        }
        if (virt_scan_for_xposed()) {
            VIRT_LOGW("Anti-tamper: Xposed detected in process!");
            virt_log_tamper_warning("Xposed detected in process");
        }
        virt_hide_from_frida();
        virt_hide_from_xposed();

        virt_anti_tamper_check_self();

        virt_detection_score_log();

        virt_rotate_log("/data/local/tmp/virtualizer/tamper_warnings.log", 524288);

        g_anti_tamper_state.total_checks++;
        g_anti_tamper_state.last_check_ns = virt_gettime_ns();
    }
    return 0;
}

static VIRT_ConnectRule g_connect_rules[VIRT_MAX_CONNECT_RULES];
static uint32_t g_connect_rule_count = 0;

int virt_add_connect_rule(const char *hostname, uint16_t port, int action) {
    if (!hostname) return VIRT_ERR_INVAL;
    if (g_connect_rule_count >= VIRT_MAX_CONNECT_RULES) return VIRT_ERR_NOMEM;
    VIRT_ConnectRule *rule = &g_connect_rules[g_connect_rule_count++];
    virt_safe_strncpy(rule->hostname, hostname, sizeof(rule->hostname));
    rule->port = port;
    rule->action = action;
    rule->has_port = (port != 0);
    return VIRT_OK;
}

int virt_check_connect(const char *hostname, uint16_t port) {
    if (!hostname) return VIRT_ACTION_PASS_THROUGH;
    for (uint32_t i = 0; i < g_connect_rule_count; i++) {
        VIRT_ConnectRule *rule = &g_connect_rules[i];
        size_t rlen = strlen(rule->hostname);
        if (rlen > 0 && strncmp(hostname, rule->hostname, rlen) == 0) {
            if (rule->has_port && rule->port != port) continue;
            return rule->action;
        }
    }
    return VIRT_ACTION_PASS_THROUGH;
}

int virt_init_default_connect_rules(void) {
    /* Block known anti-cheat and detection telemetry endpoints */
    static const char *blocked_hosts[] = {
        "akamai.",
        "cloudfront.net",
        "anticheat",
        "easyanticheat",
        "battleye",
        "xigncode",
        "nprotect",
        "gameguard",
        "tencent",
        "hackshield",
        "denuvo",
        "equ8",
        "fairfight",
        "punkbuster",
        NULL,
    };
    int count = 0;
    for (size_t i = 0; blocked_hosts[i] != NULL; i++) {
        if (virt_add_connect_rule(blocked_hosts[i], 0, VIRT_ACTION_BLOCK_ENOENT) == VIRT_OK)
            count++;
    }
    VIRT_LOGI("Default connect rules: %d loaded", count);
    return count;
}

int virt_mask_cmdline(const char *input, uint32_t input_len,
                      char *output, uint32_t output_size) {
    if (!input || !output || input_len == 0 || output_size == 0)
        return -1;

    static const char *sensitive_keywords[] = {
        "magisk", "modules", "zygisk", "tweak", "mod", "virtual",
        "debug", "test", "patch", "hook", "inject", NULL
    };

    uint32_t out_pos = 0;
    uint32_t in_pos = 0;

    while (in_pos < input_len && out_pos < output_size - 1) {
        const char *segment = input + in_pos;
        uint32_t seg_len = 0;
        while (in_pos + seg_len < input_len && input[in_pos + seg_len] != '\0')
            seg_len++;

        if (seg_len > 0) {
            bool is_sensitive = false;
            for (int i = 0; sensitive_keywords[i]; i++) {
                const char *kw = sensitive_keywords[i];
                for (uint32_t j = 0; j < seg_len; j++) {
                    if (segment[j] == kw[0]) {
                        size_t klen = strlen(kw);
                        if (j + klen <= seg_len &&
                            memcmp(segment + j, kw, klen) == 0) {
                            is_sensitive = true;
                            break;
                        }
                    }
                }
                if (is_sensitive) break;
            }

            if (is_sensitive) {
                const char *replacement = "app_process64";
                uint32_t repl_len = (uint32_t)strlen(replacement);
                uint32_t copy_len = VIRT_MIN(repl_len, output_size - out_pos - 1);
                memcpy(output + out_pos, replacement, copy_len);
                out_pos += copy_len;
            } else {
                uint32_t copy_len = VIRT_MIN(seg_len, output_size - out_pos - 1);
                memcpy(output + out_pos, segment, copy_len);
                out_pos += copy_len;
            }
        }

        if (out_pos < output_size - 1) {
            output[out_pos++] = '\0';
        }
        in_pos += seg_len + 1;
    }

    output[VIRT_MIN(out_pos, output_size - 1)] = '\0';
    return (int)out_pos;
}

int virt_mask_environ(char *buffer, uint32_t buffer_size) {
    if (!buffer || buffer_size == 0) return -1;

    static const char *sensitive_prefixes[] = {
        "LD_PRELOAD=", "LD_LIBRARY_PATH=", "MAGISK=", "MAGISKTMP=",
        "KSU=", "KSUSD=", "ZYGISK=", "APATCH=",
        "DEXOADY=", "RIRU=", "SULIST=", NULL
    };
    static const char *sensitive_containing[] = {
        "magisk", "ksu", "zygisk", "xposed", "frida",
        "substrate", "riru", "edxposed", "lsposed", NULL
    };

    uint32_t read_pos = 0;
    uint32_t write_pos = 0;

    while (read_pos < buffer_size) {
        const char *entry = buffer + read_pos;
        uint32_t entry_len = 0;
        while (read_pos + entry_len < buffer_size && buffer[read_pos + entry_len] != '\0')
            entry_len++;

        if (entry_len == 0) {
            read_pos++;
            continue;
        }

        bool sensitive = false;

        for (int i = 0; sensitive_prefixes[i]; i++) {
            size_t plen = strlen(sensitive_prefixes[i]);
            if (entry_len >= plen && memcmp(entry, sensitive_prefixes[i], plen) == 0) {
                sensitive = true;
                break;
            }
        }

        if (!sensitive) {
            for (int i = 0; sensitive_containing[i]; i++) {
                const char *kw = sensitive_containing[i];
                size_t klen = strlen(kw);
                for (uint32_t j = 0; j + klen <= entry_len; j++) {
                    if (memcmp(entry + j, kw, klen) == 0) {
                        sensitive = true;
                        break;
                    }
                }
                if (sensitive) break;
            }
        }

        if (!sensitive) {
            if (write_pos + entry_len + 1 <= buffer_size) {
                memcpy(buffer + write_pos, entry, entry_len);
                write_pos += entry_len;
                buffer[write_pos++] = '\0';
            }
        }

        read_pos += entry_len + 1;
    }

    if (write_pos < buffer_size)
        buffer[write_pos] = '\0';

    return (int)write_pos;
}

int virt_spoof_uname(struct utsname *uts) {
    if (!uts) return VIRT_ERR_INVAL;
    static const char *fake_sysname  = "Linux";
    static const char *fake_nodename = "localhost";
    static const char *fake_release  = "4.19.157-perf+";
    static const char *fake_version  = "#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 1970";
    static const char *fake_machine  = "aarch64";
    virt_safe_strncpy(uts->sysname,  fake_sysname,  sizeof(uts->sysname));
    virt_safe_strncpy(uts->nodename, fake_nodename, sizeof(uts->nodename));
    virt_safe_strncpy(uts->release,  fake_release,  sizeof(uts->release));
    virt_safe_strncpy(uts->version,  fake_version,  sizeof(uts->version));
    virt_safe_strncpy(uts->machine,  fake_machine,  sizeof(uts->machine));
#ifdef _GNU_SOURCE
    virt_safe_strncpy(uts->domainname, "(none)", sizeof(uts->domainname));
#endif
    return VIRT_OK;
}

uint64_t g_uptime_base_override = 0;

void virt_set_uptime_base(uint64_t seconds) {
    g_uptime_base_override = seconds;
}

int virt_get_fake_uptime(char *buf, size_t buf_size) {
    uint64_t base = g_uptime_base_override;
    if (base == 0) base = VIRT_UPTIME_BASE_SECONDS;
    base += 12345;
    int n = snprintf(buf, buf_size, "%llu.%02llu %llu.%02llu",
                     (unsigned long long)base, 0ULL,
                     (unsigned long long)(base * 2), 0ULL);
    if (n < 0) return -1;
    return VIRT_MIN(n, (int)buf_size - 1);
}

int virt_get_fake_stat(char *buf, size_t buf_size) {
    const char *fake_stat =
        "cpu  1234567 23456 789012 987654321 12345 6789 1234 5678 0 0\n"
        "cpu0 123456 2345 78901 98765432 1234 678 123 567 0 0\n"
        "cpu1 123456 2345 78901 98765432 1234 678 123 567 0 0\n"
        "cpu2 123456 2345 78901 98765432 1234 678 123 567 0 0\n"
        "cpu3 123456 2345 78901 98765432 1234 678 123 567 0 0\n"
        "cpu4 123456 2345 78901 98765432 1234 678 123 567 0 0\n"
        "cpu5 123456 2345 78901 98765432 1234 678 123 567 0 0\n"
        "cpu6 123456 2345 78901 98765432 1234 678 123 567 0 0\n"
        "cpu7 123456 2345 78901 98765432 1234 678 123 567 0 0\n"
        "intr 12345678 ...\n"
        "ctxt 987654321\n"
        "btime 1234567890\n"
        "processes 12345\n"
        "procs_running 2\n"
        "procs_blocked 0\n";
    size_t len = strlen(fake_stat);
    size_t copy_len = VIRT_MIN(len, buf_size - 1);
    memcpy(buf, fake_stat, copy_len);
    buf[copy_len] = '\0';
    return (int)copy_len;
}

int virt_benchmark_run(int iterations) {
    struct timespec start, end;
    uint64_t total_ns;

    VIRT_LOGI("Running benchmark: %d iterations", iterations);

    // Benchmark 1: Trie lookup
    int action;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        virt_trie_lookup("/proc/self/maps", 14, &action);
        virt_trie_lookup("/proc/self/status", 16, &action);
        virt_trie_lookup("/system/build.prop", 19, &action);
        virt_trie_lookup("/data/local/tmp/frida", 21, &action);
        virt_trie_lookup("/sbin/su", 8, &action);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    total_ns = (end.tv_sec - start.tv_sec) * 1000000000ULL + (end.tv_nsec - start.tv_nsec);
    VIRT_LOGI("Trie lookup: %llu ns for %d ops, avg %llu ns/op",
              (unsigned long long)total_ns, iterations * 5,
              (unsigned long long)(total_ns / (iterations * 5)));

    // Benchmark 2: Path matching
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        virt_path_match("/proc/self/maps", 14, "/proc/self/", VIRT_MATCH_PREFIX);
        virt_path_match("/proc/self/maps", 14, "maps", VIRT_MATCH_SUFFIX);
        virt_path_match("/proc/self/maps", 14, "/proc/self/maps", VIRT_MATCH_EXACT);
        virt_path_match("/proc/self/maps", 14, "frida", VIRT_MATCH_SUBSTRING);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    total_ns = (end.tv_sec - start.tv_sec) * 1000000000ULL + (end.tv_nsec - start.tv_nsec);
    VIRT_LOGI("Path matching: %llu ns for %d ops, avg %llu ns/op",
              (unsigned long long)total_ns, iterations * 4,
              (unsigned long long)(total_ns / (iterations * 4)));

    // Benchmark 3: Cache operations
    VIRT_CacheEntry bm_cache[64];
    uint32_t bm_cache_count = 0;
    memset(bm_cache, 0, sizeof(bm_cache));
    virt_cache_insert(bm_cache, &bm_cache_count, 64, "/proc/self/maps", 14, true, VIRT_ACTION_BLOCK_ENOENT);
    virt_cache_insert(bm_cache, &bm_cache_count, 64, "/proc/self/status", 16, true, VIRT_ACTION_BLOCK_ENOENT);
    virt_cache_insert(bm_cache, &bm_cache_count, 64, "/system/build.prop", 19, false, VIRT_ACTION_ALLOW);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        virt_cache_lookup(bm_cache, bm_cache_count, "/proc/self/maps", 14);
        virt_cache_lookup(bm_cache, bm_cache_count, "/proc/self/status", 16);
        virt_cache_lookup(bm_cache, bm_cache_count, "/system/build.prop", 19);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    total_ns = (end.tv_sec - start.tv_sec) * 1000000000ULL + (end.tv_nsec - start.tv_nsec);
    VIRT_LOGI("Cache lookup: %llu ns for %d ops, avg %llu ns/op",
              (unsigned long long)total_ns, iterations * 3,
              (unsigned long long)(total_ns / (iterations * 3)));

    // Benchmark 4: Bloom filter
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        virt_bloom_check("/proc/self/maps", 14);
        virt_bloom_check("/proc/self/status", 16);
        virt_bloom_check("normal_path", 11);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    total_ns = (end.tv_sec - start.tv_sec) * 1000000000ULL + (end.tv_nsec - start.tv_nsec);
    VIRT_LOGI("Bloom filter: %llu ns for %d ops, avg %llu ns/op",
              (unsigned long long)total_ns, iterations * 3,
              (unsigned long long)(total_ns / (iterations * 3)));

    // Benchmark 5: Latency recording
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        virt_latency_record("openat", 5000 + (i % 100) * 100);
        virt_latency_record("connect", 10000 + (i % 50) * 200);
        virt_latency_record("total", 15000 + (i % 20) * 500);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    total_ns = (end.tv_sec - start.tv_sec) * 1000000000ULL + (end.tv_nsec - start.tv_nsec);
    VIRT_LOGI("Latency record: %llu ns for %d ops, avg %llu ns/op",
              (unsigned long long)total_ns, iterations * 3,
              (unsigned long long)(total_ns / (iterations * 3)));

    VIRT_LOGI("Benchmark complete (%d iterations)", iterations);
    return VIRT_OK;
}

int virt_run_self_test(void) {
    int passed = 0;
    int failed = 0;

    VIRT_LOGI("Self-test: starting");

    /* Test 1: Trie operations */
    {
        virt_trie_insert("/proc/self/maps", VIRT_ACTION_BLOCK_ENOENT, 100);
        int action = VIRT_ACTION_PASS_THROUGH;
        int rc = virt_trie_lookup("/proc/self/maps", 14, &action);
        if (rc >= 0 && action == VIRT_ACTION_BLOCK_ENOENT) {
            VIRT_LOGI("  PASS: trie insert/lookup");
            passed++;
        } else {
            VIRT_LOGE("  FAIL: trie insert/lookup (rc=%d action=%d)", rc, action);
            failed++;
        }
        virt_trie_destroy();
    }

    /* Test 2: Cache operations */
    {
        VIRT_CacheEntry cache[4];
        uint32_t count = 0;
        memset(cache, 0, sizeof(cache));
        int rc = virt_cache_insert(cache, &count, 4, "/proc/self/maps", 14, true, VIRT_ACTION_BLOCK_ENOENT);
        if (rc == VIRT_OK && count == 1) {
            int cached = virt_cache_lookup(cache, count, "/proc/self/maps", 14);
            if (cached == VIRT_ACTION_BLOCK_ENOENT) {
                VIRT_LOGI("  PASS: cache insert/lookup");
                passed++;
            } else {
                VIRT_LOGE("  FAIL: cache lookup returned %d", cached);
                failed++;
            }
        } else {
            VIRT_LOGE("  FAIL: cache insert (rc=%d count=%u)", rc, count);
            failed++;
        }
    }

    /* Test 3: Rule matching */
    {
        bool m1 = virt_path_match("/proc/self/maps", 14, "/proc/self/", VIRT_MATCH_PREFIX);
        bool m2 = virt_path_match("/proc/self/maps", 14, "maps", VIRT_MATCH_SUFFIX);
        bool m3 = virt_path_match("/proc/self/maps", 14, "/proc/self/maps", VIRT_MATCH_EXACT);
        bool m4 = virt_path_match("/proc/self/maps", 14, "self", VIRT_MATCH_SUBSTRING);
        if (m1 && m2 && m3 && m4) {
            VIRT_LOGI("  PASS: rule matching (prefix/suffix/exact/substring)");
            passed++;
        } else {
            VIRT_LOGE("  FAIL: rule matching (%d %d %d %d)", m1, m2, m3, m4);
            failed++;
        }
    }

    /* Test 4: Config defaults */
    {
        VIRT_Config cfg = VIRT_DEFAULT_CONFIG;
        int errs = virt_config_validate(&cfg);
        if (errs == 0 &&
            cfg.cache_size == VIRT_MAX_CACHED_PATHS &&
            cfg.handler_stack_size == VIRT_HANDLER_STACK_SIZE) {
            VIRT_LOGI("  PASS: config defaults validate");
            passed++;
        } else {
            VIRT_LOGE("  FAIL: config defaults (errors=%d)", errs);
            failed++;
        }
    }

    /* Test 5: Feature detection */
    {
        int features = 0;
        virt_seccomp_get_features(&features);
        VIRT_LOGI("  INFO: kernel features=0x%x", features);
        passed++;
    }

    /* Test 6: Benchmark */
    {
        if (virt_benchmark_run(100) != VIRT_OK) {
            VIRT_LOGE("  FAIL: benchmark");
            failed++;
        } else {
            VIRT_LOGI("  PASS: benchmark (100 iterations)");
            passed++;
        }
    }

    VIRT_LOGI("Self-test: %d passed, %d failed", passed, failed);
    return failed;
}

int virt_get_fake_selinux_context(char *buf, size_t buf_size) {
    int n = snprintf(buf, buf_size, "%s\n", VIRT_FAKE_SELINUX_CONTEXT);
    if (n < 0) return -1;
    return VIRT_MIN(n, (int)buf_size - 1);
}

int virt_spoof_selinux_context(pid_t target_pid) {
    (void)target_pid;
    return VIRT_OK;
}

int virt_is_selinux_enforcing(void) {
    char buf[16];
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return (buf[0] == '1') ? 1 : 0;
}

int virt_get_fake_proc_version(char *buf, size_t buf_size) {
    const char *fake = "Linux version 5.10.149-android13-4-00001-gdeadbeef (build-user@build-host) "
                       "(Android (version) clang version 16.0.2) "
                       "#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 2024\n";
    size_t len = strlen(fake);
    size_t copy = VIRT_MIN(len, buf_size - 1);
    memcpy(buf, fake, copy);
    buf[copy] = '\0';
    return (int)copy;
}

int virt_get_fake_boot_id(char *buf, size_t buf_size) {
    const char *id = "deadbeef-cafe-babe-0123-456789abcdef\n";
    size_t len = strlen(id);
    size_t copy = VIRT_MIN(len, buf_size - 1);
    memcpy(buf, id, copy);
    buf[copy] = '\0';
    return (int)copy;
}

int virt_get_fake_cpuinfo(char *buf, size_t buf_size) {
    const char *fake =
        "Processor\t: AArch64 Processor rev 14 (aarch64)\n"
        "processor\t: 0\n"
        "BogoMIPS\t: 38.40\n"
        "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp simdhp cpuid asimdrdb lrcpc dcpop asimddp ssbs\n"
        "CPU implementer\t: 0x51\n"
        "CPU architecture\t: 8\n"
        "CPU variant\t: 0x2\n"
        "CPU part\t: 0x801\n"
        "CPU revision\t: 14\n"
        "\n"
        "processor\t: 1\n"
        "BogoMIPS\t: 38.40\n"
        "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp simdhp cpuid asimdrdb lrcpc dcpop asimddp ssbs\n"
        "CPU implementer\t: 0x51\n"
        "CPU architecture\t: 8\n"
        "CPU variant\t: 0x2\n"
        "CPU part\t: 0x801\n"
        "CPU revision\t: 14\n"
        "\n"
        "processor\t: 2\n"
        "BogoMIPS\t: 38.40\n"
        "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp simdhp cpuid asimdrdb lrcpc dcpop asimddp ssbs\n"
        "CPU implementer\t: 0x51\n"
        "CPU architecture\t: 8\n"
        "CPU variant\t: 0x2\n"
        "CPU part\t: 0x801\n"
        "CPU revision\t: 14\n"
        "\n"
        "processor\t: 3\n"
        "BogoMIPS\t: 38.40\n"
        "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp simdhp cpuid asimdrdb lrcpc dcpop asimddp ssbs\n"
        "CPU implementer\t: 0x51\n"
        "CPU architecture\t: 8\n"
        "CPU variant\t: 0x2\n"
        "CPU part\t: 0x801\n"
        "CPU revision\t: 14\n"
        "\n"
        "Hardware\t: Qualcomm Technologies, Inc SM8550\n";
    size_t len = strlen(fake);
    size_t copy = VIRT_MIN(len, buf_size - 1);
    memcpy(buf, fake, copy);
    buf[copy] = '\0';
    return (int)copy;
}