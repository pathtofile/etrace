#!/usr/bin/env python3
"""
eTrace
"""

import os
import sys
import argparse
from typing import Optional, List
from pathlib import Path

INT_TYPES = [
    "size_t",
    "aio_context_t",
    "aio_context_t *",
    "enum landlock_rule_type",
    "gid_t",
    "gid_t *",
    "int",
    "int *",
    "__kernel_old_time_t *",
    "key_serial_t",
    "key_t",
    "loff_t",
    "loff_t *",
    "long",
    "long *",
    "mqd_t",
    "off_t",
    "pid_t",
    "qid_t",
    "rwf_t",
    "__s32",
    "size_t",
    "size_t *",
    "timer_t",
    "timer_t *",
    "__u32",
    "u32",
    "u32 *",
    "__u64",
    "uid_t",
    "uid_t *",
    "umode_t",
]

STR_TYPES = ["char *"]
JOIN_TYPES = [
    "char **",
]

TEMPLATE = """
tracepoint:syscalls:{name} {{
{code}
}}
"""


def generate_func(
    syscall: str,
    comm: Optional[str],
    pid: Optional[int],
    ppid: Optional[int],
) -> str:
    """
    Generate a single bpftrace function

    Args:
        syscall: Name of syscall
        comm: Only log proceses with this name
        pid: Only log events from this pid
        ppid: Only log events from this parent pid

    Returns:
        str: Script to run with bpftrace
    """
    sysdir = Path(f"/sys/kernel/debug/tracing/events/syscalls/sys_enter_{syscall}")
    with open(sysdir / "format", "r", encoding="utf-8") as f:
        text = f.read()
    # Arguments come after '__syscall_nr' line
    arg_names = ["comm", "pid"]
    arg_fmts = ["%s", "%d"]
    arg_accesses = ["comm", "pid"]
    started = False
    lines = text.split("\n")
    for l in lines:
        if "__syscall_nr" in l:
            started = True
            continue
        if not started:
            continue
        if l.strip() == "" or l.startswith("print fmt: "):
            break
        # Parse argument line to get name and format of variable
        arg_text = l.split(";")[0].strip().replace("field:", "")
        arg_split = arg_text.split(" ")
        arg_name = arg_split[-1]
        arg_type = (
            " ".join(arg_split[:-1]).replace("const ", "").replace("unsigned ", "")
        )
        if arg_type in INT_TYPES:
            arg_access = f"args->{arg_name}"
            arg_fmt = "%d"
        elif arg_type in STR_TYPES:
            arg_access = f"str(args->{arg_name})"
            arg_fmt = "%s"
        elif arg_type in JOIN_TYPES:
            arg_access = f"join(args->{arg_name})"
            arg_fmt = "%s"
        else:
            arg_access = f"args->{arg_name}"
            arg_fmt = "%p"

        arg_names.append(arg_name)
        arg_fmts.append(arg_fmt)
        arg_accesses.append(arg_access)
    i = 0
    format_string = ""
    for i, arg_name in enumerate(arg_names):
        format_string += f"{arg_name}:{arg_fmts[i]}\\t"
    format_string = format_string.strip()
    format_args = ", ".join(arg_accesses)
    code = []
    if comm is not None:
        code.append(f'  if (comm != "{comm}") {{ return }}')

    code.append(f'  printf("{syscall}\\t{format_string}\\n", {format_args});')

    output = TEMPLATE.format(name=sysdir.name, code="\n".join(code)).strip()
    return output


def generate_script(
    syscalls: Optional[List[str]],
    comm: Optional[str],
    pid: Optional[int],
    ppid: Optional[int],
) -> str:
    """
    Generate bpftrace Script

    Args:
        syscalls: List of syscalls
        comm: Only log proceses with this name
        pid: Only log events from this pid
        ppid: Only log events from this parent pid

    Returns:
        str: Script to run with bpftrace
    """
    if syscalls is None:
        syscalls = []
        syscall_dir = Path("/sys/kernel/debug/tracing/events/syscalls")
        for sysdir in syscall_dir.glob("sys_enter_*"):
            syscalls.append(sysdir.name.replace("sys_enter_", ""))

    output = []
    for syscall in syscalls:
        print(syscall, file=sys.stderr)
        output.append(generate_func(syscall, comm, pid, ppid))
    return "\n".join(output)


def main():
    """main"""
    parser = argparse.ArgumentParser("eTrace - strace-like logging using bpftrace")
    parser.add_argument(
        "--syscall", "-s", nargs="*", help="Only log these specific syscalls"
    )
    parser.add_argument("--comm", "-c", help="Only log proceses with this name")
    parser.add_argument("--pid", "-p", type=int, help="Only log events from this pid")
    parser.add_argument(
        "--ppid", "-pp", type=int, help="Only log events from this parent pid"
    )
    args = parser.parse_args()
    if not Path("/sys/kernel/debug/tracing/events/syscalls").exists():
        raise SystemError("Mssing debugfs")
    script = generate_script(args.syscall, args.comm, args.pid, args.ppid)
    print(script)


if __name__ == "__main__":
    if os.getuid() != 0:
        print("Re-Running as root", file=sys.stderr)
        sys.exit(os.system(f"sudo {sys.executable} {' '.join(sys.argv)}"))
    main()
