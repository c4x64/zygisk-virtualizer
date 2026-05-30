#include "virtualizer.h"

static uint64_t g_seccomp_engine_events = 0;
static uint64_t g_seccomp_engine_errors = 0;
static uint64_t g_seccomp_engine_continue_fallback = 0;
static int      g_seccomp_engine_init_errno = 0;
static bool     g_seccomp_engine_has_tsync = false;
static bool     g_seccomp_engine_has_continue = true;
static bool     g_seccomp_engine_has_user_notif = false;
static bool     g_seccomp_engine_has_new_listener = false;
static uint32_t g_seccomp_engine_features = 0;
static uint64_t g_seccomp_engine_last_event_id = 0;
static uint64_t g_seccomp_engine_total_latency_ns = 0;
static uint64_t g_seccomp_engine_max_latency_ns = 0;
static uint64_t g_seccomp_engine_min_latency_ns = UINT64_MAX;
static uint32_t g_seccomp_engine_active_listeners = 0;
static uint32_t g_seccomp_engine_total_listeners = 0;
static VIRT_ProcHiderState *g_seccomp_engine_proc_hider = NULL;

const char *VIRT_DECOY_MAPS_PATH = "/data/local/tmp/clean_maps";
const char *VIRT_DECOY_STATUS_PATH = "/data/local/tmp/clean_status";

bool virt_decoy_file_create(const char *path, const char *const *lines) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    for (size_t i = 0; lines[i] != NULL; i++) {
        ssize_t len = (ssize_t)strlen(lines[i]);
        if (write(fd, lines[i], len) != len) { close(fd); return false; }
        if (write(fd, "\n", 1) != 1) { close(fd); return false; }
    }
    close(fd);
    return true;
}

static int virt_seccomp_try_addfd(int notify_fd, const struct seccomp_notif *req,
                                   const char *redirect_path) {
    int local_fd = open(redirect_path, O_RDONLY | O_CLOEXEC);
    if (local_fd < 0) return -errno;
    struct seccomp_notif_addfd addfd;
    memset(&addfd, 0, sizeof(addfd));
    addfd.id = req->id;
    addfd.flags = SECCOMP_ADDFD_FLAG_SEND;
    addfd.srcfd = (__u32)local_fd;
    addfd.newfd = 0;
    addfd.newfd_flags = O_CLOEXEC;
    int new_fd = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
    close(local_fd);
    return new_fd;
}



static sock_filter g_bpf_filter_static[] = {
    {BPF_LD | BPF_W | BPF_ABS, 0, 0, 4},
    {BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_AARCH64},
    {BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW},
    {BPF_LD | BPF_W | BPF_ABS, 0, 0, 0},
    {BPF_JMP | BPF_JEQ | BPF_K, 3, 0, __NR_faccessat},
    {BPF_JMP | BPF_JEQ | BPF_K, 2, 0, __NR_openat},
    {BPF_JMP | BPF_JEQ | BPF_K, 1, 0, __NR_readlinkat},
    {BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW},
    {BPF_RET | BPF_K, 0, 0, SECCOMP_RET_USER_NOTIF},
};

/* Extended filter replaced by dynamic BPF compiler */
/* Keep for reference only */
#if 0
static sock_filter g_bpf_filter_extended[] = {
    {BPF_LD | BPF_W | BPF_ABS, 0, 0, 4},
    {BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_AARCH64},
    {BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW},
    {BPF_LD | BPF_W | BPF_ABS, 0, 0, 0},
    {BPF_JMP | BPF_JEQ | BPF_K, 12, 0, __NR_faccessat},
    {BPF_JMP | BPF_JEQ | BPF_K, 11, 0, __NR_openat},
    {BPF_JMP | BPF_JEQ | BPF_K, 10, 0, __NR_readlinkat},
    {BPF_JMP | BPF_JEQ | BPF_K, 9, 0, __NR_newfstatat},
    {BPF_JMP | BPF_JEQ | BPF_K, 8, 0, __NR_statx},
    {BPF_JMP | BPF_JEQ | BPF_K, 7, 0, __NR_getdents64},
    {BPF_JMP | BPF_JEQ | BPF_K, 6, 0, __NR_faccessat2},
    {BPF_JMP | BPF_JEQ | BPF_K, 5, 0, __NR_readlink},
    {BPF_JMP | BPF_JEQ | BPF_K, 4, 0, __NR_mmap},
    {BPF_JMP | BPF_JEQ | BPF_K, 3, 0, __NR_connect},
    {BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW},
    {BPF_RET | BPF_K, 0, 0, SECCOMP_RET_USER_NOTIF},
};
#endif

typedef struct {
    int       max_instructions;
    int       current;
    sock_filter *instructions;
    bool      has_arch_check;
    uint32_t  arch;
    int       matched_count;
    int      *matched_nrs;
    int       max_matches;
} BPFCompiler;

static void bpf_compiler_init(BPFCompiler *c, sock_filter *buf, int max_insns,
                              int *nr_buf, int max_nrs) {
    memset(c, 0, sizeof(*c));
    c->instructions = buf;
    c->max_instructions = max_insns;
    c->current = 0;
    c->matched_nrs = nr_buf;
    c->max_matches = max_nrs;
    c->has_arch_check = true;
    c->arch = AUDIT_ARCH_AARCH64;
}

static int bpf_compiler_emit(BPFCompiler *c, uint16_t code, uint8_t jt,
                              uint8_t jf, uint32_t k) {
    if (c->current >= c->max_instructions) return -1;
    int idx = c->current++;
    c->instructions[idx].code = code;
    c->instructions[idx].jt = jt;
    c->instructions[idx].jf = jf;
    c->instructions[idx].k = k;
    return idx;
}

static int bpf_compiler_ld_abs(BPFCompiler *c, uint32_t offset) {
    return bpf_compiler_emit(c, BPF_LD | BPF_W | BPF_ABS, 0, 0, offset);
}

static int bpf_compiler_jeq(BPFCompiler *c, uint32_t k, uint8_t jt, uint8_t jf) {
    return bpf_compiler_emit(c, BPF_JMP | BPF_JEQ | BPF_K, jt, jf, k);
}

static int bpf_compiler_ret(BPFCompiler *c, uint32_t k) {
    return bpf_compiler_emit(c, BPF_RET | BPF_K, 0, 0, k);
}

static int bpf_compiler_compile(BPFCompiler *c, VIRT_SeccompFilterProfile *profiles,
                                 int profile_count) {
    int arch_insn = -1;
    int arch_jump = -1;
    int arch_allow = -1;
    int load_nr = -1;
    int jump_insns[64];
    int jump_count = 0;
    int final_allow = -1;
    int final_user_notif = -1;

    arch_insn = bpf_compiler_ld_abs(c, 4);
    if (arch_insn < 0) return -1;

    arch_jump = bpf_compiler_jeq(c, c->arch, 1, 0);
    if (arch_jump < 0) return -1;

    arch_allow = bpf_compiler_ret(c, SECCOMP_RET_ALLOW);
    if (arch_allow < 0) return -1;

    load_nr = bpf_compiler_ld_abs(c, 0);
    if (load_nr < 0) return -1;

    int match_count = 0;
    for (int i = 0; i < profile_count && profiles[i].syscall_nr >= 0; i++) {
        if (profiles[i].intercept) {
            if (c->matched_nrs && match_count < c->max_matches) {
                c->matched_nrs[match_count] = profiles[i].syscall_nr;
            }
            match_count++;
        }
    }
    c->matched_count = match_count;

    if (match_count == 0) {
        int ret_all = bpf_compiler_ret(c, SECCOMP_RET_ALLOW);
        return ret_all >= 0 ? 0 : -1;
    }

    int remaining = match_count;
    for (int i = 0; i < profile_count && profiles[i].syscall_nr >= 0; i++) {
        if (!profiles[i].intercept) continue;
        remaining--;
        int skip = remaining + 1;
        int idx = bpf_compiler_jeq(c, (uint32_t)profiles[i].syscall_nr,
                                    (uint8_t)skip, 0);
        if (idx < 0) return -1;
        jump_insns[jump_count++] = idx;
    }

    final_allow = bpf_compiler_ret(c, SECCOMP_RET_ALLOW);
    if (final_allow < 0) return -1;

    final_user_notif = bpf_compiler_ret(c, SECCOMP_RET_USER_NOTIF);
    if (final_user_notif < 0) return -1;

    int total_insns = c->current;
    (void)jump_insns;
    (void)jump_count;

    return total_insns;
}

static void __attribute__((unused)) bpf_compiler_dump(BPFCompiler *c) {
    VIRT_LOGI("BPF Compiler: %d instructions generated", c->current);
    for (int i = 0; i < c->current; i++) {
        sock_filter *f = &c->instructions[i];
        uint16_t op = f->code & 0xE0;
        const char *op_name = "UNK";
        if (op == BPF_LD) op_name = "LD";
        else if (op == BPF_JMP) op_name = "JMP";
        else if (op == BPF_RET) op_name = "RET";
        uint16_t mode = f->code & 0x18;
        const char *mode_name = "";
        if (op == BPF_LD) {
            if (mode == BPF_W) mode_name = ".W";
            mode_name = ".ABS";
        } else if (op == BPF_JMP) {
            if ((f->code & 0x07) == BPF_JEQ) mode_name = ".JEQ";
            mode_name = ".K";
        }
        VIRT_LOGT("  [%2d] %s%s jt=%u jf=%u k=%u (0x%x)",
                  i, op_name, mode_name, f->jt, f->jf, f->k, f->k);
    }
}

static int virt_seccomp_probe_kernel_features(void) {
    int features = 0;
    struct sock_fprog prog;
    sock_filter dummy[] = {
        {BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW},
    };
    prog.len = ARRAY_COUNT(dummy);
    prog.filter = dummy;

    if (syscall(__NR_seccomp, SECCOMP_GET_ACTION_AVAIL, 0,
                SECCOMP_RET_USER_NOTIF) == 0) {
        features |= 1;
        g_seccomp_engine_has_user_notif = true;
    } else {
        VIRT_LOGD("USER_NOTIF not available: %s", strerror(errno));
    }

    if (syscall(__NR_seccomp, SECCOMP_GET_ACTION_AVAIL, 0,
                SECCOMP_RET_LOG) == 0) {
        features |= 8;
    }

    if (syscall(__NR_seccomp, SECCOMP_GET_ACTION_AVAIL, 0,
                SECCOMP_RET_TRACE) == 0) {
        features |= 16;
    }

    int fd = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                          SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (fd >= 0) {
        features |= 2;
        g_seccomp_engine_has_new_listener = true;
        close(fd);

        fd = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                          SECCOMP_FILTER_FLAG_NEW_LISTENER |
                          SECCOMP_FILTER_FLAG_TSYNC, &prog);
        if (fd >= 0) {
            features |= 4;
            g_seccomp_engine_has_tsync = true;
            close(fd);
        }

        fd = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                          SECCOMP_FILTER_FLAG_NEW_LISTENER |
                          SECCOMP_FILTER_FLAG_TSYNC |
                          SECCOMP_FILTER_FLAG_TSYNC_ESRCH, &prog);
        if (fd >= 0) {
            features |= 32;
            close(fd);
        }
    }

    if (syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, NULL) == 0 ||
        errno != ENOSYS) {
        features |= 64;
    }

    g_seccomp_engine_features = features;

    VIRT_LOGI("Kernel features: USER_NOTIF=%s NEW_LISTENER=%s TSYNC=%s "
              "TSYNC_ESRCH=%s LOG=%s TRACE=%s NOTIF_SIZES=%s "
              "(0x%x)",
              (features & 1)  ? "Y" : "N",
              (features & 2)  ? "Y" : "N",
              (features & 4)  ? "Y" : "N",
              (features & 32) ? "Y" : "N",
              (features & 8)  ? "Y" : "N",
              (features & 16) ? "Y" : "N",
              (features & 64) ? "Y" : "N",
              features);

    return features;
}

int virt_seccomp_install_static(VIRT_Config *cfg,
                                VIRT_SeccompFilterProfile *profiles,
                                int profile_count) {
    if (!cfg || !profiles) return VIRT_ERR_INVAL;

    sock_filter filter_buf[128];
    int nr_buf[64];
    BPFCompiler compiler;
    bpf_compiler_init(&compiler, filter_buf, 128, nr_buf, 64);

    int total_insns = bpf_compiler_compile(&compiler, profiles, profile_count);
    if (total_insns < 0) {
        VIRT_LOGE("BPF compilation failed");
        return VIRT_ERR_INVAL;
    }

    struct sock_fprog prog;
    prog.len = total_insns;
    prog.filter = filter_buf;

    int filter_flags = SECCOMP_FILTER_FLAG_NEW_LISTENER;
    if (cfg->enable_thread_sync && g_seccomp_engine_has_tsync) {
        filter_flags |= SECCOMP_FILTER_FLAG_TSYNC;
    }
    if (g_seccomp_engine_features & 32) {
        filter_flags |= SECCOMP_FILTER_FLAG_TSYNC_ESRCH;
    }

    int notify_fd = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                                  filter_flags, &prog);

    if (notify_fd < 0) {
        g_seccomp_engine_init_errno = errno;
        VIRT_LOGW("seccomp FAST install failed (flags=0x%x): %s",
                   filter_flags, strerror(errno));

        if (errno == EINVAL && (filter_flags & SECCOMP_FILTER_FLAG_TSYNC)) {
            filter_flags &= ~SECCOMP_FILTER_FLAG_TSYNC;
            filter_flags &= ~SECCOMP_FILTER_FLAG_TSYNC_ESRCH;
            notify_fd = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                                      filter_flags, &prog);
        }

        if (notify_fd < 0) {
            VIRT_LOGW("seccomp retry failed (flags=0x%x): %s",
                       filter_flags, strerror(errno));

            if (cfg->enable_kernel_compat) {
                VIRT_LOGI("Trying static precompiled filter as fallback");
                prog.len = ARRAY_COUNT(g_bpf_filter_static);
                prog.filter = g_bpf_filter_static;
                notify_fd = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                                          SECCOMP_FILTER_FLAG_NEW_LISTENER,
                                          &prog);
            }
        }
    }

    if (notify_fd < 0) {
        g_seccomp_engine_init_errno = errno;
        VIRT_LOGE("All seccomp installation methods failed: %s", strerror(errno));
        return VIRT_ERR_NODEV;
    }

    g_seccomp_engine_total_listeners++;
    g_seccomp_engine_active_listeners++;

    VIRT_LOGI("Seccomp filter installed (fd=%d, flags=0x%x, insns=%d, matches=%d)",
              notify_fd, filter_flags, total_insns, compiler.matched_count);

    return notify_fd;
}

int virt_seccomp_create_decoy_files(void) {
    int ok = 0;
    if (virt_decoy_file_create(VIRT_DECOY_MAPS_PATH, VIRT_FAKE_MAPS_CONTENT)) {
        VIRT_LOGD("Decoy maps created at %s", VIRT_DECOY_MAPS_PATH);
        ok++;
    }
    if (virt_decoy_file_create(VIRT_DECOY_STATUS_PATH, VIRT_FAKE_STATUS_CONTENT)) {
        VIRT_LOGD("Decoy status created at %s", VIRT_DECOY_STATUS_PATH);
        ok++;
    }
    return ok;
}

int virt_seccomp_install_static_default(VIRT_Config *cfg) {
    return virt_seccomp_install_static(
        cfg,
        (VIRT_SeccompFilterProfile *)DEFAULT_FILTER_PROFILES,
        ARRAY_COUNT(DEFAULT_FILTER_PROFILES)
    );
}

static long virt_seccomp_execute_faccessat(uint64_t a0, uint64_t a1, uint64_t a2) {
    long ret = syscall(__NR_faccessat, (int)a0, (const char *)(uintptr_t)a1, (int)a2);
    return (ret < 0) ? (long)-errno : 0;
}

static long virt_seccomp_execute_openat(uint64_t a0, uint64_t a1,
                                         uint64_t a2, uint64_t a3) {
    long ret = syscall(__NR_openat, (int)a0, (const char *)(uintptr_t)a1,
                        (int)a2, (mode_t)a3);
    return (ret < 0) ? (long)-errno : ret;
}

static long virt_seccomp_execute_readlinkat(uint64_t a0, uint64_t a1,
                                             uint64_t a2, uint64_t a3,
                                             pid_t target_pid) {
    char tmp[VIRT_PATH_BUF_SIZE];
    long n = syscall(__NR_readlinkat, (int)a0, (const char *)(uintptr_t)a1,
                      tmp, sizeof(tmp));
    if (n < 0) return (long)-errno;
    size_t copy_sz = (size_t)n;
    if ((size_t)a3 < copy_sz) copy_sz = (size_t)a3;
    if (copy_sz > 0) {
        struct iovec lw = { .iov_base = tmp, .iov_len = copy_sz };
        struct iovec rw = { .iov_base = (void *)(uintptr_t)a2, .iov_len = copy_sz };
        syscall(__NR_process_vm_writev, target_pid, &lw, 1UL, &rw, 1UL, 0UL);
    }
    return (long)copy_sz;
}

static long virt_seccomp_execute_readlink(uint64_t a0, uint64_t a1,
                                           uint64_t a2, pid_t target_pid) {
    char tmp[VIRT_PATH_BUF_SIZE];
    long n = syscall(__NR_readlink, (const char *)(uintptr_t)a0, tmp, sizeof(tmp));
    if (n < 0) return (long)-errno;
    size_t copy_sz = (size_t)n;
    if ((size_t)a2 < copy_sz) copy_sz = (size_t)a2;
    if (copy_sz > 0) {
        struct iovec lw = { .iov_base = tmp, .iov_len = copy_sz };
        struct iovec rw = { .iov_base = (void *)(uintptr_t)a1, .iov_len = copy_sz };
        syscall(__NR_process_vm_writev, target_pid, &lw, 1UL, &rw, 1UL, 0UL);
    }
    return (long)copy_sz;
}

static long virt_seccomp_execute_newfstatat(uint64_t a0, uint64_t a1,
                                             uint64_t a2, uint64_t a3,
                                             pid_t target_pid) {
    struct stat st;
    long ret = syscall(__NR_newfstatat, (int)a0, (const char *)(uintptr_t)a1,
                        &st, (int)a3);
    if (ret < 0) return (long)-errno;
    struct iovec lw = { .iov_base = &st, .iov_len = sizeof(st) };
    struct iovec rw = { .iov_base = (void *)(uintptr_t)a2, .iov_len = sizeof(st) };
    syscall(__NR_process_vm_writev, target_pid, &lw, 1UL, &rw, 1UL, 0UL);
    return 0;
}

static long virt_seccomp_execute_statx(uint64_t a0, uint64_t a1,
                                        uint64_t a2, uint64_t a3,
                                        uint64_t a4, pid_t target_pid) {
    struct statx stx;
    long ret = syscall(__NR_statx, (int)a0, (const char *)(uintptr_t)a1,
                        (int)a2, (unsigned int)a3, &stx);
    if (ret < 0) return (long)-errno;
    struct iovec lw = { .iov_base = &stx, .iov_len = sizeof(stx) };
    struct iovec rw = { .iov_base = (void *)(uintptr_t)a4, .iov_len = sizeof(stx) };
    syscall(__NR_process_vm_writev, target_pid, &lw, 1UL, &rw, 1UL, 0UL);
    return 0;
}

static long virt_seccomp_execute_getdents64(uint64_t a0, uint64_t a1,
                                              uint64_t a2, pid_t target_pid) {
    char tmp[8192];
    size_t read_size = VIRT_MIN((size_t)a2, sizeof(tmp));
    long n = syscall(__NR_getdents64, (int)a0,
                      (struct linux_dirent64 *)tmp, (unsigned int)read_size);
    if (n < 0) return (long)-errno;
    if (n == 0) return 0;
    /* Filter hidden fds from /proc/self/fd and /proc/<pid>/fd listings */
    size_t write_len = (size_t)n;
    char filtered[8192];
    uint32_t filtered_len = 0;
    if (g_seccomp_engine_proc_hider &&
        virt_proc_hider_filter_dirents(g_seccomp_engine_proc_hider,
                                        tmp, (uint32_t)n,
                                        filtered, &filtered_len) == VIRT_OK &&
        filtered_len > 0) {
        write_len = (size_t)filtered_len;
        memcpy(tmp, filtered, filtered_len);
    }
    struct iovec lw = { .iov_base = tmp, .iov_len = write_len };
    struct iovec rw = { .iov_base = (void *)(uintptr_t)a1, .iov_len = write_len };
    syscall(__NR_process_vm_writev, target_pid, &lw, 1UL, &rw, 1UL, 0UL);
    return (long)write_len;
}

static long virt_seccomp_execute_connect(uint64_t a0, uint64_t a1, uint64_t a2) {
    struct sockaddr_storage addr;
    size_t addr_size = VIRT_MIN((size_t)a2, sizeof(addr));
    (void)addr_size;
    long ret = syscall(__NR_connect, (int)a0,
                        (const struct sockaddr *)(uintptr_t)a1, (socklen_t)a2);
    return (ret < 0) ? (long)-errno : 0;
}

static long virt_seccomp_execute_mmap(uint64_t a0, uint64_t a1,
                                       uint64_t a2, uint64_t a3,
                                       uint64_t a4, uint64_t a5) {
    void *addr = (void *)(uintptr_t)a0;
    long ret = (long)syscall(__NR_mmap, addr, (size_t)a1, (int)a2,
                              (int)a3, (int)a4, (off_t)a5);
    if ((void *)ret == MAP_FAILED) return (long)-errno;
    return ret;
}

static long virt_seccomp_execute_mprotect(uint64_t a0, uint64_t a1, uint64_t a2) {
    long ret = syscall(__NR_mprotect, (void *)(uintptr_t)a0,
                        (size_t)a1, (int)a2);
    return (ret < 0) ? (long)-errno : 0;
}

static long virt_seccomp_execute_faccessat2(uint64_t a0, uint64_t a1,
                                             uint64_t a2, uint64_t a3) {
    long ret = syscall(__NR_faccessat2, (int)a0, (const char *)(uintptr_t)a1,
                        (int)a2, (int)a3);
    return (ret < 0) ? (long)-errno : 0;
}

static long virt_seccomp_execute_openat2(uint64_t a0, uint64_t a1,
                                          uint64_t a2, uint64_t a3) {
    long ret = syscall(__NR_openat2, (int)a0, (const char *)(uintptr_t)a1,
                        (struct open_how *)(uintptr_t)a2, (size_t)a3);
    return (ret < 0) ? (long)-errno : ret;
}

void virt_handle_prctl(struct seccomp_notif *req,
                        struct seccomp_notif_resp *resp) {
    if (!req || !resp) return;
    resp->id = req->id;

    long option = (long)req->data.args[0];

    if (option == PR_GET_SECCOMP) {
        resp->error = 0;
        resp->val = 0;
        resp->flags = 0;
        VIRT_LOGD("[prctl] PR_GET_SECCOMP spoofed -> 0 (disabled)");
    } else {
        resp->error = 0;
        resp->val = 0;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        if (VIRT_LOG_LEVEL >= VIRT_LOG_LEVEL_TRACE)
            VIRT_LOGT("[prctl] option=%ld CONTINUE (passthrough)", option);
    }
}

long virt_seccomp_execute_syscall(struct seccomp_notif *req) {
    if (!req) return -EINVAL;

    long nr = req->data.nr;
    uint64_t a0 = req->data.args[0];
    uint64_t a1 = req->data.args[1];
    uint64_t a2 = req->data.args[2];
    uint64_t a3 = req->data.args[3];
    uint64_t a4 = req->data.args[4];
    uint64_t a5 = req->data.args[5];
    pid_t pid = req->pid;

    __sync_fetch_and_add(&g_seccomp_engine_events, 1);

    switch (nr) {
        case __NR_faccessat:
            return virt_seccomp_execute_faccessat(a0, a1, a2);
        case __NR_faccessat2:
            return virt_seccomp_execute_faccessat2(a0, a1, a2, a3);
        case __NR_openat:
            return virt_seccomp_execute_openat(a0, a1, a2, a3);
        case __NR_openat2:
            return virt_seccomp_execute_openat2(a0, a1, a2, a3);
        case __NR_readlinkat:
            return virt_seccomp_execute_readlinkat(a0, a1, a2, a3, pid);
        case __NR_readlink:
            return virt_seccomp_execute_readlink(a0, a1, a2, pid);
        case __NR_newfstatat:
            return virt_seccomp_execute_newfstatat(a0, a1, a2, a3, pid);
        case __NR_statx:
            return virt_seccomp_execute_statx(a0, a1, a2, a3, a4, pid);
        case __NR_getdents64:
            return virt_seccomp_execute_getdents64(a0, a1, a2, pid);
        case __NR_connect:
            return virt_seccomp_execute_connect(a0, a1, a2);
        case __NR_mmap:
            return virt_seccomp_execute_mmap(a0, a1, a2, a3, a4, a5);
        case __NR_mprotect:
            return virt_seccomp_execute_mprotect(a0, a1, a2);
        default:
            __sync_fetch_and_add(&g_seccomp_engine_errors, 1);
            return -ENOSYS;
    }
}

int virt_seccomp_read_path(struct seccomp_notif *req,
                            char *buf, size_t buf_size,
                            uint64_t path_addr) {
    if (!req || !buf || !buf_size || !path_addr) return -1;

    struct iovec local = { .iov_base = buf, .iov_len = buf_size };
    struct iovec remote = { .iov_base = (void *)(uintptr_t)path_addr,
                            .iov_len = buf_size };

    ssize_t n = syscall(__NR_process_vm_readv, (pid_t)req->pid,
                        &local, 1UL, &remote, 1UL, 0UL);
    if (n <= 0) return (int)n;

    if (n < (ssize_t)buf_size) {
        buf[n] = '\0';
    } else {
        buf[buf_size - 1] = '\0';
    }

    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] == '\0') return (int)i;
    }

    return (int)n;
}

int virt_seccomp_handler_loop(void *arg) {
    int notify_fd = (int)(intptr_t)arg;
    prctl(PR_SET_NAME, "seccomp-virt", 0, 0, 0);

    struct seccomp_notif req;
    struct seccomp_notif_resp resp;
    VIRT_SyscallStats stats;
    VIRT_Watchdog watchdog;
    VIRT_HealthStatus health;
    VIRT_ProcHiderState proc_hider;
    VIRT_TimingJitter jitter;
    uint64_t event_ring[256];
    uint32_t event_ring_pos = 0;
    bool watchdog_ok = false;
    bool stats_ok = false;

    /* Heap-allocate large arrays — stack is limited to 8MB */
    VIRT_CacheEntry *cache = (VIRT_CacheEntry *)calloc(
        VIRT_MAX_CACHED_PATHS, sizeof(VIRT_CacheEntry));
    uint32_t cache_count = 0;
    VIRT_Rule *rules = (VIRT_Rule *)calloc(
        VIRT_MAX_RULES, sizeof(VIRT_Rule));
    uint32_t rule_count = 0;

    if (!cache || !rules) {
        VIRT_LOGE("Handler: OOM allocating cache/rules");
        free(cache);
        free(rules);
        close(notify_fd);
        return VIRT_ERR_NOMEM;
    }

    memset(&stats, 0, sizeof(stats));
    memset(&health, 0, sizeof(health));
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    memset(&jitter, 0, sizeof(jitter));

    stats.last_reset_tp = virt_gettime_ns();
    health.handler_state = VIRT_HANDLER_RUNNING;
    health.notify_fd = notify_fd;
    health.thread_alive = true;
    health.fd_valid = true;
    health.kernel_continue = g_seccomp_engine_has_continue;
    health.tsync_active = g_seccomp_engine_has_tsync;
    clock_gettime(CLOCK_MONOTONIC, &health.last_heartbeat);
    health.processed_events = 0;
    health.blocked_events = 0;
    health.error_count = 0;
    health.consecutive_errors = 0;
    health.cache_hit_rate = 0;
    health.last_error = 0;
    health.last_error_msg[0] = '\0';
    health.active_threads = 0;
    health.active_rules = 0;
    health.uptime_ns = 0;

    virt_watchdog_init(&watchdog, VIRT_WATCHDOG_INTERVAL_NS, 3);
    virt_watchdog_arm(&watchdog);
    watchdog_ok = true;

    virt_stats_init(&stats);
    stats_ok = true;

    virt_rules_load_defaults(rules, &rule_count, VIRT_MAX_RULES);
    health.active_rules = rule_count;

    virt_proc_hider_init(&proc_hider);
    virt_proc_hider_add_fd(&proc_hider, notify_fd);
    g_seccomp_engine_proc_hider = &proc_hider;

    jitter.enabled = false;
    jitter.base_us = 0;
    jitter.range_us = 0;
    jitter.max_jitter_us = 0;
    jitter.min_jitter_us = UINT32_MAX;

    VIRT_LOGI(
        "Handler v%s started (fd=%d, continue=%s, tsync=%s, "
        "rules=%u, cache=%u, watchdog=%s)",
        VIRTUALIZER_VERSION,
        notify_fd,
        g_seccomp_engine_has_continue ? "yes" : "no",
        g_seccomp_engine_has_tsync ? "yes" : "no",
        rule_count,
        VIRT_MAX_CACHED_PATHS,
        watchdog_ok ? "armed" : "disabled"
    );

    while (true) {
        uint64_t loop_start = virt_gettime_ns();
        memset(&req, 0, sizeof(req));

        struct pollfd pfd = {
            .fd = notify_fd,
            .events = POLLIN,
            .revents = 0,
        };

        int poll_rc = poll(&pfd, 1, VIRT_NOTIF_FD_TIMEOUT_MS);
        if (poll_rc < 0) {
            if (errno == EINTR) continue;
            VIRT_LOGE("poll error: %s", strerror(errno));
            health.consecutive_errors++;
            if (health.consecutive_errors > 10) break;
            continue;
        }
        if (poll_rc == 0) {
            if (watchdog_ok) {
                int wd_rc = virt_watchdog_check(&watchdog);
                if (wd_rc < 0) {
                    VIRT_LOGE("Watchdog triggered");
                    health.last_error = wd_rc;
                    virt_safe_strncpy(health.last_error_msg,
                                      "Watchdog timeout",
                                      sizeof(health.last_error_msg));
                    if (++health.consecutive_errors > 5) break;
                }
            }
            continue;
        }

        int rc = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &req);
        if (rc < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOENT) {
                VIRT_LOGI("Handler ENOENT, target exited (events=%lu)",
                          (unsigned long)health.processed_events);
                break;
            }
            if (errno == EBADF || errno == ENOTTY) {
                VIRT_LOGE("Handler fd invalid (errno=%d)", errno);
                health.fd_valid = false;
                break;
            }
            VIRT_LOGE("NOTIF_RECV error %d: %s", errno, strerror(errno));
            health.consecutive_errors++;
            if (health.consecutive_errors > 10) break;
            continue;
        }

        health.consecutive_errors = 0;
        health.processed_events++;
        g_seccomp_engine_last_event_id = req.id;

        uint64_t path_addr = 0;
        int path_len = -1;
        bool path_readable = false;
        char path_buf[VIRT_PATH_BUF_SIZE];
        path_buf[0] = '\0';

        switch (req.data.nr) {
            case __NR_openat:
            case __NR_openat2:
            case __NR_readlinkat:
            case __NR_readlink:
            case __NR_newfstatat:
            case __NR_statx:
            case __NR_faccessat:
            case __NR_faccessat2:
                path_addr = req.data.args[1];
                break;
            case __NR_mmap:
                if (req.data.args[4] >= 0) path_addr = 0;
                break;
            default:
                path_addr = 0;
                break;
        }

        if (path_addr) {
            path_len = virt_seccomp_read_path(&req, path_buf,
                                               sizeof(path_buf), path_addr);
            path_readable = (path_len > 0);
        }

        if (event_ring_pos < 256) {
            event_ring[event_ring_pos++] = req.id;
        } else {
            event_ring_pos = 0;
            event_ring[event_ring_pos++] = req.id;
        }

        int action = VIRT_ACTION_PASS_THROUGH;
        bool resolved = false;

        if (path_readable && path_len > 0) {
            int cached = virt_cache_lookup(cache, cache_count,
                                            path_buf, (uint32_t)path_len);
            if (cached >= 0) {
                action = cached;
                resolved = true;
                if (cached != VIRT_ACTION_PASS_THROUGH) {
                    health.cache_hit_rate++;
                }
            } else {
                int rule_action = VIRT_ACTION_PASS_THROUGH;
                int rule_rc = virt_rules_lookup(rules, rule_count,
                                                 path_buf, (uint32_t)path_len,
                                                 &rule_action);
                if (rule_rc >= 0) {
                    uint32_t plen = (uint32_t)VIRT_MAX(path_len, 0);
                    action = rule_action;
                    resolved = true;
                    virt_cache_insert(cache, &cache_count,
                                       VIRT_MAX_CACHED_PATHS,
                                       path_buf, plen,
                                       action != VIRT_ACTION_PASS_THROUGH,
                                       action);
                }
            }
        }

        /* Dynamic /proc/self/fd/<hidden_fd> check */
        if (path_readable && path_len > 0 && !resolved) {
            if (virt_proc_hider_check_fd_path(&proc_hider,
                                               path_buf, (uint32_t)path_len)) {
                action = VIRT_ACTION_BLOCK_ENOENT;
                resolved = true;
                if (VIRT_LOG_LEVEL >= VIRT_LOG_LEVEL_DEBUG) {
                    VIRT_LOGD("Hiding fd path: %s", path_buf);
                }
            }
        }

        if (req.data.nr == __NR_faccessat || req.data.nr == __NR_faccessat2) {
            if (action == VIRT_ACTION_PASS_THROUGH ||
                action == VIRT_ACTION_ALLOW) {
                int mode = (int)req.data.args[2];
                if (mode == F_OK) {
                    resolved = true;
                    action = VIRT_ACTION_ALLOW;
                }
            }
        }

        resp.id = req.id;

        /* --- prctl Bypass Engine ---
         * Intercept PR_GET_SECCOMP to return SECCOMP_MODE_DISABLED (0),
         * hiding our USER_NOTIF filter from anti-cheat seccomp probes.
         * All other prctl commands (PR_SET_NAME, PR_SET_DUMPABLE, etc.)
         * are passed through to the kernel via CONTINUE. */
        if (req.data.nr == __NR_prctl) {
            virt_handle_prctl(&req, &resp);
        }

        /* --- mprotect Shadow Mirror Guard ---
         * If an anti-cheat engine attempts mprotect on our execution_base
         * region (where hooks/patches live), spoof success — the caller
         * believes the pages changed permissions while physical protections
         * remain untouched. All OTHER mprotect calls pass through to the
         * kernel via CONTINUE so normal page behavior is never disrupted. */
        if (req.data.nr == __NR_mprotect) {
            uintptr_t target = (uintptr_t)req.data.args[0];
            const ShadowLibraryMirror *sm = virt_get_shadow_mirror();
            if (sm && sm->initialized &&
                target >= sm->execution_base &&
                target < sm->execution_base + sm->segment_size) {
                resp.error = 0;
                resp.val = 0;
                resp.flags = 0;
                VIRT_LOGD("[mprotect] SPOOFED addr=%lx in [%lx-%lx]",
                          target, sm->execution_base,
                          sm->execution_base + sm->segment_size);
            }
            /* No match: resp unchanged → falls through to CONTINUE below */
        }

        /* --- Path Redirection Engine ---
         * For openat/openat2 on sensitive paths, project a clean decoy fd
         * into the target via SECCOMP_IOCTL_NOTIF_ADDFD (auto-sends response).
         * For blocked readlinkat/faccessat etc., and all non-blocked paths,
         * use CONTINUE so the kernel handles the request naturally. */
        bool should_redirect = false;
        const char *redirect_path = NULL;

        if (resolved &&
            action != VIRT_ACTION_PASS_THROUGH &&
            action != VIRT_ACTION_ALLOW) {
            health.blocked_events++;
            if (req.data.nr == __NR_openat || req.data.nr == __NR_openat2) {
                if (strstr(path_buf, "maps"))
                    redirect_path = VIRT_DECOY_MAPS_PATH;
                else if (strstr(path_buf, "status") ||
                         strstr(path_buf, "stat"))
                    redirect_path = VIRT_DECOY_STATUS_PATH;
                if (redirect_path) {
                    int new_fd = virt_seccomp_try_addfd(notify_fd, &req,
                                                         redirect_path);
                    if (new_fd >= 0) {
                        should_redirect = true;
                        if (VIRT_LOG_LEVEL >= VIRT_LOG_LEVEL_DEBUG)
                            VIRT_LOGD("[openat] REDIRECT %s -> fd=%d",
                                      path_buf, new_fd);
                    }
                }
            }
        }

        if (!should_redirect) {
            bool send_direct = (req.data.nr == __NR_prctl);
            if (req.data.nr == __NR_mprotect) {
                const ShadowLibraryMirror *sm = virt_get_shadow_mirror();
                if (sm && sm->initialized &&
                    (uintptr_t)req.data.args[0] >= sm->execution_base &&
                    (uintptr_t)req.data.args[0] < sm->execution_base + sm->segment_size)
                    send_direct = true;
            }
            if (send_direct) {
                rc = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
            } else if (g_seccomp_engine_has_continue) {
                resp.error = 0;
                resp.val = 0;
                resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                rc = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
            } else {
                long exec_ret = virt_seccomp_execute_syscall(&req);
                resp.error = (int)exec_ret;
                resp.val = 0;
                resp.flags = 0;
                rc = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
            }
        }

        uint64_t total_time = virt_gettime_ns() - loop_start;

        if (rc < 0) {
            if (errno == EOPNOTSUPP || errno == EINVAL) {
                if (g_seccomp_engine_has_continue) {
                    VIRT_LOGW("CONTINUE unsupported, falling back");
                    g_seccomp_engine_has_continue = false;
                    g_seccomp_engine_continue_fallback++;
                    resp.flags = 0;
                    resp.error = (int)virt_seccomp_execute_syscall(&req);
                    int rc2 = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
                    if (rc2 < 0 && errno == ENOENT) {
                        continue;
                    }
                }
            } else if (errno == ENOENT) {
                continue;
            } else if (errno == EAGAIN) {
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
                nanosleep(&ts, NULL);
                rc = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
                if (rc < 0 && errno == ENOENT) continue;
            } else {
                VIRT_LOGE("NOTIF_SEND error %d: %s (event=%lu)",
                          errno, strerror(errno),
                          (unsigned long)req.id);
                health.last_error = errno;
                virt_safe_strncpy(health.last_error_msg,
                                  strerror(errno),
                                  sizeof(health.last_error_msg));
                health.consecutive_errors++;
            }
        }

        if (total_time > g_seccomp_engine_max_latency_ns) {
            g_seccomp_engine_max_latency_ns = total_time;
        }
        if (total_time < g_seccomp_engine_min_latency_ns) {
            g_seccomp_engine_min_latency_ns = total_time;
        }
        g_seccomp_engine_total_latency_ns += total_time;

        if (stats_ok) {
            virt_stats_record(&stats, req.data.nr, action, total_time);
        }

        if (watchdog_ok && g_seccomp_engine_has_continue) {
            virt_watchdog_ping(&watchdog);
        }

        clock_gettime(CLOCK_MONOTONIC, &health.last_heartbeat);
        health.uptime_ns = virt_gettime_ns() - stats.last_reset_tp;

        if (VIRT_LOG_LEVEL >= VIRT_LOG_LEVEL_TRACE &&
            health.processed_events % 100 == 0) {
            double avg_lat = (double)g_seccomp_engine_total_latency_ns /
                             (double)VIRT_MAX(health.processed_events, 1ULL);
            VIRT_LOGT("Progress: %lu events, %lu blocked, avg=%.0fns, "
                       "consec_errors=%lu",
                       (unsigned long)health.processed_events,
                       (unsigned long)health.blocked_events,
                       avg_lat,
                       (unsigned long)health.consecutive_errors);
        }

        if (health.processed_events % 5000 == 0) {
            char stats_buf[2048];
            virt_stats_snapshot(&stats, stats_buf, sizeof(stats_buf));
            VIRT_LOGI("Periodic stats:\n%s", stats_buf);
        }
    }

    health.handler_state = VIRT_HANDLER_SHUTDOWN;
    health.thread_alive = false;
    g_seccomp_engine_proc_hider = NULL;

    if (g_seccomp_engine_active_listeners > 0) {
        g_seccomp_engine_active_listeners--;
    }

    if (notify_fd >= 0) {
        close(notify_fd);
    }

    double avg_lat = g_seccomp_engine_total_latency_ns /
                     (double)VIRT_MAX(health.processed_events, 1ULL);
    VIRT_LOGI(
        "Handler exit: events=%lu blocked=%lu errors=%lu "
        "avg_lat=%.0fns max_lat=%luns continue_fb=%lu",
        (unsigned long)health.processed_events,
        (unsigned long)health.blocked_events,
        (unsigned long)g_seccomp_engine_errors,
        avg_lat,
        (unsigned long)g_seccomp_engine_max_latency_ns,
        (unsigned long)g_seccomp_engine_continue_fallback
    );

    free(cache);
    free(rules);
    return 0;
}

int virt_seccomp_get_features(int *out_features) {
    static int cached = -1;
    if (cached < 0) {
        cached = virt_seccomp_probe_kernel_features();
    }
    if (out_features) *out_features = cached;
    return cached;
}

int virt_seccomp_check_notif_id_valid(int notify_fd, uint64_t id) {
    return ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id);
}

uint64_t virt_seccomp_get_event_count(void) {
    return g_seccomp_engine_events;
}

uint64_t virt_seccomp_get_error_count(void) {
    return g_seccomp_engine_errors;
}

uint64_t virt_seccomp_get_continue_fallback_count(void) {
    return g_seccomp_engine_continue_fallback;
}

bool virt_seccomp_has_continue(void) {
    return g_seccomp_engine_has_continue;
}

uint32_t virt_seccomp_get_active_listeners(void) {
    return g_seccomp_engine_active_listeners;
}

uint32_t virt_seccomp_get_total_listeners(void) {
    return g_seccomp_engine_total_listeners;
}

uint64_t virt_seccomp_get_avg_latency_ns(void) {
    uint64_t events = g_seccomp_engine_events;
    if (events == 0) return 0;
    return g_seccomp_engine_total_latency_ns / events;
}

int virt_watchdog_init(VIRT_Watchdog *wd, uint64_t interval_ns,
                        uint32_t max_misses) {
    if (!wd) return VIRT_ERR_INVAL;
    memset(wd, 0, sizeof(*wd));
    wd->interval_ns = interval_ns;
    wd->max_missed = max_misses;
    wd->armed = false;
    wd->triggered = false;
    wd->missed_pings = 0;
    wd->last_ping_ns = virt_gettime_ns();
    wd->timer_fd = -1;
    return VIRT_OK;
}

int virt_watchdog_arm(VIRT_Watchdog *wd) {
    if (!wd) return VIRT_ERR_INVAL;
    wd->armed = true;
    wd->last_ping_ns = virt_gettime_ns();
    wd->deadline.tv_sec = wd->last_ping_ns / 1000000000ULL +
                          wd->interval_ns / 1000000000ULL;
    wd->deadline.tv_nsec = 0;
    return VIRT_OK;
}

int virt_watchdog_disarm(VIRT_Watchdog *wd) {
    if (!wd) return VIRT_ERR_INVAL;
    wd->armed = false;
    return VIRT_OK;
}

int virt_watchdog_ping(VIRT_Watchdog *wd) {
    if (!wd || !wd->armed) return VIRT_ERR_INVAL;
    wd->last_ping_ns = virt_gettime_ns();
    wd->missed_pings = 0;
    return VIRT_OK;
}

int virt_watchdog_check(VIRT_Watchdog *wd) {
    if (!wd || !wd->armed) return VIRT_OK;
    uint64_t now = virt_gettime_ns();
    if (now - wd->last_ping_ns > wd->interval_ns) {
        wd->missed_pings++;
        wd->last_ping_ns = now;
        if (wd->missed_pings >= wd->max_missed) {
            wd->triggered = true;
            VIRT_LOGW("Watchdog triggered: missed=%u max=%u",
                      wd->missed_pings, wd->max_missed);
            return VIRT_ERR_TIMEOUT;
        }
        VIRT_LOGW("Watchdog: missed ping %u/%u",
                  wd->missed_pings, wd->max_missed);
    }
    return VIRT_OK;
}

int virt_health_check(VIRT_HealthStatus *status) {
    if (!status) return VIRT_ERR_INVAL;

    status->uptime_ns = virt_gettime_ns();

    if (status->notify_fd >= 0) {
        int fl = fcntl(status->notify_fd, F_GETFD);
        status->fd_valid = (fl >= 0);
    } else {
        status->fd_valid = false;
    }

    status->kernel_continue = g_seccomp_engine_has_continue;
    status->tsync_active = g_seccomp_engine_has_tsync;

    if (!status->fd_valid &&
        status->handler_state == VIRT_HANDLER_RUNNING) {
        status->handler_state = VIRT_HANDLER_CRASHED;
        virt_safe_strncpy(status->last_error_msg,
                          "FD invalid while running",
                          sizeof(status->last_error_msg));
        status->last_error = VIRT_ERR_NODEV;
    }

    status->error_count = g_seccomp_engine_errors;

    return VIRT_OK;
}

int virt_health_report(const VIRT_HealthStatus *status,
                        char *buf, size_t buf_size) {
    if (!status || !buf || !buf_size) return VIRT_ERR_INVAL;

    int off = 0;
    int state_idx = VIRT_CLAMP(status->handler_state, 0,
                                VIRT_HANDLER_STATE_COUNT - 1);
    uint64_t uptime_ms = status->uptime_ns / 1000000ULL;
    double avg_lat = 0.0;
    if (status->processed_events > 0) {
        avg_lat = (double)g_seccomp_engine_total_latency_ns /
                  (double)status->processed_events;
    }

    off += snprintf(buf + off, buf_size - (size_t)off,
        "=== Virtualizer Health Report v%s ===\n"
        "Handler State:      %s\n"
        "Notify FD:          %d (%s)\n"
        "Thread Alive:       %s\n"
        "CONTINUE Support:   %s\n"
        "TSYNC Active:       %s\n"
        "------------------------\n"
        "Events Processed:   %lu\n"
        "Events Blocked:     %lu\n"
        "Error Count:        %lu\n"
        "Consecutive Errors: %lu\n"
        "Cache Hit Rate:     %u\n"
        "Active Rules:       %u\n"
        "Active Threads:     %u\n"
        "Active Listeners:   %u\n"
        "Total Listeners:    %u\n"
        "------------------------\n"
        "Uptime (ms):        %lu\n"
        "Avg Latency (ns):   %.0f\n"
        "Max Latency (ns):   %lu\n"
        "Min Latency (ns):   %lu\n"
        "Continue Fallbacks: %lu\n"
        "Last Error:         %d (%s)\n"
        "Last Errno:         %d\n",
        VIRTUALIZER_VERSION,
        VIRT_HANDLER_STATE_NAMES[state_idx],
        status->notify_fd,
        status->fd_valid ? "valid" : "INVALID",
        status->thread_alive ? "yes" : "no",
        status->kernel_continue ? "yes" : "no",
        status->tsync_active ? "yes" : "no",
        (unsigned long)status->processed_events,
        (unsigned long)status->blocked_events,
        (unsigned long)status->error_count,
        (unsigned long)status->consecutive_errors,
        status->cache_hit_rate,
        status->active_rules,
        status->active_threads,
        g_seccomp_engine_active_listeners,
        g_seccomp_engine_total_listeners,
        (unsigned long)uptime_ms,
        avg_lat,
        (unsigned long)g_seccomp_engine_max_latency_ns,
        (unsigned long)g_seccomp_engine_min_latency_ns,
        (unsigned long)g_seccomp_engine_continue_fallback,
        status->last_error,
        status->last_error_msg[0] ? status->last_error_msg : "none",
        status->last_errno);

    return VIRT_MIN(off, (int)buf_size - 1);
}

int virt_jitter_apply(VIRT_TimingJitter *jitter) {
    if (!jitter || !jitter->enabled) return VIRT_OK;
    if (jitter->range_us == 0) return VIRT_OK;

    uint32_t val = (uint32_t)rand() % jitter->range_us;
    jitter->total_jitter_ns += (uint64_t)val * 1000ULL;
    jitter->jitter_count++;
    if (val > jitter->max_jitter_us) jitter->max_jitter_us = val;
    if (val < jitter->min_jitter_us) jitter->min_jitter_us = val;
    jitter->avg_jitter_ns = jitter->total_jitter_ns /
                            (double)VIRT_MAX(jitter->jitter_count, 1U);
    if (val > 0) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)val * 1000L };
        nanosleep(&ts, NULL);
    }
    return VIRT_OK;
}