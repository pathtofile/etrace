"""
Constants
"""

TEMPLATE = """
tracepoint:syscalls:sys_enter_{syscall} {{
{filter_code}
{code}
}}
"""

TEMPLATE_EXIT = """
rawtracepoint:sys_exit {{
{filter_code}
  printf("r\\texit\\t%d\\t%d\\n", tid, arg1);
}}
"""

INT_TYPES = [
    "__kernel_old_time_t",
    "__s32",
    "__u32",
    "__u64",
    "aio_context_t",
    "enum landlock_rule_type",
    "gid_t",
    "int",
    "key_serial_t",
    "key_t",
    "loff_t",
    "long",
    "mqd_t",
    "off_t",
    "pid_t",
    "qid_t",
    "rwf_t",
    "size_t",
    "timer_t",
    "u32",
    "uid_t",
    "umode_t",
]
STR_TYPES = ["char *"]

CUSTOM_TYPES = [
    "operator_t",
    "key_serial_t",
    "qid_t",
    "aio_context_t",
    "rwf_t",
    "cap_user_header_t",
    "cap_user_data_t",
    "enum landlock_rule_type",
    "sigset_t",
    "siginfo_t",
]

# Mostly copied from strace:
#   https://github.com/strace/strace/blob/master/src/linux/mips/syscallent-o32.h#L126
SYSCALL_GROUPS = {
    "seccomp": ["syscall", "execve", "socketcall", "ipc", "execveat"],
    "process": [
        "exit",
        "fork",
        "waitpid",
        "execve",
        "kill",
        "wait4",
        "clone",
        "rt_sigqueueinfo",
        "tkill",
        "exit_group",
        "tgkill",
        "waitid",
        "rt_tgsigqueueinfo",
        "execveat",
        "sched_process_exec",
    ],
    "capture-on-enter": ["exit", "execve", "exit_group", "execveat"],
    "desc": [
        "read",
        "write",
        "open",
        "close",
        "creat",
        "lseek",
        "oldfstat",
        "dup",
        "pipe",
        "ioctl",
        "fcntl",
        "dup2",
        "readdir",
        "mmap",
        "ftruncate",
        "fchmod",
        "fchown",
        "fstatfs",
        "socketcall",
        "fstat",
        "fsync",
        "fchdir",
        "_llseek",
        "getdents",
        "_newselect",
        "flock",
        "readv",
        "writev",
        "fdatasync",
        "poll",
        "pread64",
        "pwrite64",
        "sendfile",
        "mmap2",
        "ftruncate64",
        "fstat64",
        "getdents64",
        "fcntl64",
        "readahead",
        "fsetxattr",
        "fgetxattr",
        "flistxattr",
        "fremovexattr",
        "sendfile64",
        "epoll_create",
        "epoll_ctl",
        "epoll_wait",
        "fadvise64",
        "fstatfs64",
        "mq_open",
        "mq_timedsend",
        "mq_timedreceive",
        "mq_notify",
        "mq_getsetattr",
        "inotify_init",
        "inotify_add_watch",
        "inotify_rm_watch",
        "openat",
        "mkdirat",
        "mknodat",
        "fchownat",
        "futimesat",
        "fstatat64",
        "unlinkat",
        "renameat",
        "linkat",
        "symlinkat",
        "readlinkat",
        "fchmodat",
        "faccessat",
        "pselect6",
        "ppoll",
        "splice",
        "sync_file_range",
        "tee",
        "vmsplice",
        "epoll_pwait",
        "utimensat",
        "signalfd",
        "timerfd",
        "eventfd",
        "fallocate",
        "timerfd_create",
        "timerfd_gettime",
        "timerfd_settime",
        "signalfd4",
        "eventfd2",
        "epoll_create1",
        "dup3",
        "pipe2",
        "inotify_init1",
        "preadv",
        "pwritev",
        "perf_event_open",
        "fanotify_init",
        "fanotify_mark",
        "name_to_handle_at",
        "open_by_handle_at",
        "syncfs",
        "setns",
        "finit_module",
        "renameat2",
        "memfd_create",
        "bpf",
        "execveat",
        "userfaultfd",
        "copy_file_range",
        "preadv2",
        "pwritev2",
        "statx",
    ],
    "file": [
        "open",
        "creat",
        "link",
        "unlink",
        "execve",
        "chdir",
        "mknod",
        "chmod",
        "lchown",
        "oldstat",
        "mount",
        "umount",
        "utime",
        "access",
        "rename",
        "mkdir",
        "rmdir",
        "acct",
        "umount2",
        "chroot",
        "symlink",
        "oldlstat",
        "readlink",
        "uselib",
        "swapon",
        "truncate",
        "statfs",
        "stat",
        "lstat",
        "swapoff",
        "quotactl",
        "chown",
        "getcwd",
        "truncate64",
        "stat64",
        "lstat64",
        "pivot_root",
        "setxattr",
        "lsetxattr",
        "getxattr",
        "lgetxattr",
        "listxattr",
        "llistxattr",
        "removexattr",
        "lremovexattr",
        "statfs64",
        "utimes",
        "inotify_add_watch",
        "openat",
        "mkdirat",
        "mknodat",
        "fchownat",
        "futimesat",
        "fstatat64",
        "unlinkat",
        "renameat",
        "linkat",
        "symlinkat",
        "readlinkat",
        "fchmodat",
        "faccessat",
        "utimensat",
        "fanotify_mark",
        "name_to_handle_at",
        "renameat2",
        "execveat",
        "statx",
    ],
    "comm-change": ["execve", "prctl", "execveat"],
    "mem-change": [
        "execve",
        "brk",
        "mmap",
        "munmap",
        "mprotect",
        "mremap",
        "mmap2",
        "remap_file_pages",
        "execveat",
        "pkey_mprotect",
        "shmat",
        "shmdt",
    ],
    "clock": [
        "time",
        "gettimeofday",
        "settimeofday",
        "adjtimex",
        "clock_settime",
        "clock_gettime",
        "clock_getres",
        "clock_adjtime",
    ],
    "memory": [
        "break",
        "brk",
        "mmap",
        "munmap",
        "mprotect",
        "msync",
        "mlock",
        "munlock",
        "mlockall",
        "munlockall",
        "mremap",
        "mmap2",
        "mincore",
        "madvise",
        "io_setup",
        "io_destroy",
        "remap_file_pages",
        "mbind",
        "get_mempolicy",
        "set_mempolicy",
        "migrate_pages",
        "move_pages",
        "mlock2",
        "pkey_mprotect",
        "shmat",
        "shmdt",
    ],
    "stat": [
        "oldstat",
        "oldfstat",
        "oldlstat",
        "stat",
        "lstat",
        "fstat",
        "stat64",
        "lstat64",
        "fstat64",
        "fstatat64",
        "statx",
        "ustat",
        "statfs",
        "fstatfs",
        "statfs64",
        "fstatfs64",
    ],
    "pure": [
        "getpid",
        "getuid",
        "getgid",
        "geteuid",
        "getegid",
        "getppid",
        "getpgrp",
        "gettid",
    ],
    "never-fails": [
        "getpid",
        "getuid",
        "getgid",
        "geteuid",
        "getegid",
        "umask",
        "getppid",
        "getpgrp",
        "personality",
        "setfsuid",
        "setfsgid",
        "gettid",
    ],
    "creds": [
        "setuid",
        "getuid",
        "setgid",
        "getgid",
        "geteuid",
        "getegid",
        "setreuid",
        "setregid",
        "getgroups",
        "setgroups",
        "setfsuid",
        "setfsgid",
        "setresuid",
        "getresuid",
        "setresgid",
        "getresgid",
        "prctl",
        "capget",
        "capset",
    ],
    "signal": [
        "pause",
        "kill",
        "signal",
        "sigaction",
        "sgetmask",
        "ssetmask",
        "sigsuspend",
        "sigpending",
        "sigreturn",
        "sigprocmask",
        "rt_sigreturn",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigpending",
        "rt_sigtimedwait",
        "rt_sigqueueinfo",
        "rt_sigsuspend",
        "sigaltstack",
        "tkill",
        "tgkill",
        "signalfd",
        "signalfd4",
        "rt_tgsigqueueinfo",
    ],
    "ipc": [
        "ipc",
        "semget",
        "semctl",
        "shmget",
        "shmctl",
        "shmat",
        "shmdt",
        "msgget",
        "msgsnd",
        "msgrcv",
        "msgctl",
    ],
    "network": [
        "accept",
        "bind",
        "connect",
        "getpeername",
        "getsockname",
        "getsockopt",
        "listen",
        "recv",
        "recvfrom",
        "recvmsg",
        "send",
        "sendmsg",
        "sendto",
        "setsockopt",
        "shutdown",
        "socket",
        "socketpair",
        "sendfile",
        "getpmsg",
        "putpmsg",
        "sendfile64",
        "accept4",
        "recvmmsg",
        "sendmmsg",
    ],
}

# Add aliases and 'group of groups'
SYSCALL_GROUPS["proc"] = SYSCALL_GROUPS["process"]
SYSCALL_GROUPS["net"] = SYSCALL_GROUPS["network"]
SYSCALL_GROUPS["basic"] = [
    *SYSCALL_GROUPS["file"],
    *SYSCALL_GROUPS["network"],
    *SYSCALL_GROUPS["process"],
]
