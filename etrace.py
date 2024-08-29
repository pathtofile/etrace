#!/usr/bin/env python3
"""
eTrace
"""

import os
import sys
import json
import shutil
import argparse
import tempfile
import subprocess
from pathlib import Path
from typing import Optional, List

from custom_handlers import TEMPLATE, HANDLERS

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
]

SYSCALL_GROUPS = {
    "process": [
        "exit",
        "fork",
        "execve",
        "kill",
        "wait4",
        "clone",
        "rt_sigqueueinfo",
        "tkill",
        "tgkill",
        "waitid",
        "execveat",
        "exit_group",
    ]
}


def generate_func(
    syscall: str,
    comm: Optional[str],
    pid: Optional[int],
    ppid: Optional[int],
) -> tuple[List[str], str]:
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
    if syscall in HANDLERS:
        return HANDLERS[syscall](comm, pid, ppid)
    sysdir = Path(f"/sys/kernel/debug/tracing/events/syscalls/sys_enter_{syscall}")
    with open(sysdir / "format", "r", encoding="utf-8") as f:
        text = f.read()
    # Arguments come after '__syscall_nr' line
    arg_names = ["comm", "pid"]
    arg_fmts = ["%s", "%d"]
    arg_accesses = ["comm", "pid"]
    header_lines = []

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
        arg_type_core = arg_type.replace("*", "").strip()
        if arg_type_core in INT_TYPES:
            arg_access = f"args->{arg_name}"
            arg_fmt = "%d"
        elif arg_type in STR_TYPES:
            arg_access = f"str(args->{arg_name})"
            arg_fmt = "%s"
        else:
            arg_access = f"args->{arg_name}"
            arg_fmt = "%p"

        if arg_type_core in CUSTOM_TYPES and arg_type_core not in header_lines:
            if "enum" in arg_type_core:
                header_lines.append(f"{arg_type_core} {{ IGNORED }};")
            else:
                header_lines.append(f"typedef void *{arg_type_core};")

        # print(f"  {arg_type} {arg_name}", file=sys.stderr)
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
    if pid is not None:
        code.append(f"  if (pid != {pid}) {{ return }}")
    if ppid is not None:
        code.append(
            f"  if (pid != {ppid} && curtask->parent->pid != {ppid}) {{ return }}"
        )

    code.append(f'  printf("{syscall}\\t{format_string}\\n", {format_args});')

    output = TEMPLATE.format(name=sysdir.name, code="\n".join(code)).strip()
    return header_lines, output


def generate_script(
    syscalls: Optional[List[str]],
    comm: Optional[str],
    pid: Optional[int],
    ppid: Optional[int],
) -> tuple[str, str]:
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

    header_lines = [
        "#pragma once",
        "#include <linux/sched.h>",
    ]
    func_lines = []
    for syscall in syscalls:
        # print(syscall, file=sys.stderr)
        func_header_lines, func_text = generate_func(syscall, comm, pid, ppid)
        func_lines.append(func_text)
        for header_line in func_header_lines:
            if header_line not in header_lines:
                header_lines.append(header_line)

    header = "\n".join(header_lines) + "\n"
    output = "\n\n".join(func_lines) + "\n"
    return header, output


def run_bpftrace(header_file: Path, script_file: Path, output_json: bool):
    """
    Start and run bpftrace
    """
    # Try to find bpftrace
    path = ":".join(
        [
            os.environ["PATH"],
            str(Path(__file__).parent.resolve()),
            os.getcwd(),
        ]
    )
    bpftrace = shutil.which("bpftrace", path=path)
    if bpftrace is None:
        raise SystemError(
            (
                f"Need bpftrace on the PATH, in the {__file__} "
                "script root, or in the current directory"
            )
        )

    cmd = [bpftrace, str(script_file), "--include", str(header_file)]
    if output_json:
        cmd += ["-f", "json"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    for line in iter(proc.stdout.readline, b""):
        if output_json:
            j = json.loads(line.decode("utf-8", "ignore"))
            if j["type"] == "attached_probes":
                probe_count = j["data"]["probes"]
                print(f"Started {probe_count} probes", file=sys.stderr)
            elif j["type"] == "printf":
                data = j["data"].strip().split("\t")
                dataj = {
                    "syscall": data[0],
                    "comm": data[1].split(":")[-1],
                    "pid": data[2].split(":")[-1],
                }
                for d in data[3:]:
                    ds = d.split(":")
                    dataj[ds[0]] = ":".join(ds[1:])
                print(json.dumps(dataj))
        else:
            print(line.decode("utf-8", "ignore"), end="")


def main():
    """main"""
    parser = argparse.ArgumentParser("eTrace - strace-like logging using bpftrace")
    syscall_group = parser.add_mutually_exclusive_group()
    syscall_group.add_argument(
        "--syscall",
        "-s",
        action="append",
        help="Only log these specific syscalls",
    )
    syscall_group.add_argument(
        "--group",
        "-g",
        choices=SYSCALL_GROUPS.keys(),
        help="strac-elike syscall Group (see readme)",
    )
    parser.add_argument("--comm", "-c", help="Only log proceses with this name")
    parser.add_argument("--pid", "-p", type=int, help="Only log events from this pid")
    parser.add_argument(
        "--ppid", "-pp", type=int, help="Only log events from this pid or its children"
    )
    parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    args = parser.parse_args()
    if not Path("/sys/kernel/debug/tracing/events/syscalls").exists():
        raise SystemError("Mssing debugfs")

    if args.group is not None:
        syscalls = SYSCALL_GROUPS[args.group]
    else:
        syscalls = args.syscall

    header, script = generate_script(syscalls, args.comm, args.pid, args.ppid)
    with tempfile.TemporaryDirectory() as tmpdir:
        header_file = Path(tmpdir, "custom.h").resolve()
        script_file = Path(tmpdir, "trace.bt").resolve()

        with open(header_file, "w", encoding="utf-8") as f:
            f.write(header)
        with open(script_file, "w", encoding="utf-8") as f:
            f.write(script)
        try:
            run_bpftrace(header_file, script_file, args.json)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    if os.getuid() != 0:
        # print("Re-Running as root", file=sys.stderr)
        sys.exit(os.system(f"sudo {sys.executable} {' '.join(sys.argv)}"))
    main()
