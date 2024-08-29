# eTrace
strace-like logging using bpftrace and eBPF
```
name: sys_enter_execve
ID: 729
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:const char * filename;    offset:16;      size:8; signed:0;
        field:const char *const * argv; offset:24;      size:8; signed:0;
        field:const char *const * envp; offset:32;      size:8; signed:0;

print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))
```

```
sudo bpftrace trace_full.bt --include /home/path/code/etrace/include/custom.h -f json

./etrace.py -s landlock_add_rule -s getdents64 -s getdents --ppid 3497
```

# TODO
 - Add custom parsers for directories, networking, execve


# Groups
https://github.com/strace/strace/blob/master/src/sysent_shorthand_defs.h#L42
https://github.com/strace/strace/blob/master/src/linux/mips/syscallent-o32.h#L126
