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
import logging
import subprocess
from pathlib import Path
from typing import Optional, List

from rich import box
from rich.table import Table
from rich.console import Console

from custom_handlers import TEMPLATE, HANDLERS
from consts import INT_TYPES, STR_TYPES, CUSTOM_TYPES, SYSCALL_GROUPS

logger = None


def setup_logging(verbose: bool, output_file: Optional[str]):
    """Setup logger"""
    global logger

    class LogFilter(object):
        """
        Custom Log filter to only log at either a specfic level
        Or to NOT log a specfic level
        """

        def __init__(self, level: int, negate: bool):
            self.level = level
            self.negate = negate

        def filter(self, logRecord):
            if self.negate:
                return logRecord.levelno != self.level
            else:
                return logRecord.levelno == self.level

    logger = logging.getLogger("etrace")
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(message)s")

    # Logging plan:
    # If INFO, print to console and File
    # If --vebose and Debug, Warning, or Error (i.e. not INFO) print to stderr
    # If not vebose, print Warning, or Error (i.e. not INFO) print to stderr
    hander_stdout = logging.StreamHandler(sys.stdout)
    hander_stdout.setFormatter(formatter)
    hander_stdout.setLevel(logging.INFO)
    hander_stdout.addFilter(LogFilter(logging.INFO, False))
    logger.addHandler(hander_stdout)

    hander_stderr = logging.StreamHandler(sys.stderr)
    hander_stderr.setFormatter(formatter)
    if verbose:
        hander_stderr.setLevel(logging.DEBUG)
        hander_stderr.addFilter(LogFilter(logging.INFO, True))
    else:
        hander_stderr.setLevel(logging.WARNING)
    logger.addHandler(hander_stderr)

    if output_file is not None:
        handler_file = logging.FileHandler(output_file, mode="w")
        handler_file.setFormatter(formatter)
        handler_file.setLevel(logging.INFO)
        handler_file.addFilter(LogFilter(logging.INFO, False))
        logger.addHandler(handler_file)


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

        (list, str): Touple containing:
            - list of lines to add to custom header (to de-dupe with other syscalls)
            - Bpftrace script function to run
    """
    if syscall in HANDLERS:
        return HANDLERS[syscall](comm, pid, ppid)
    sysdir = Path(f"/sys/kernel/debug/tracing/events/syscalls/sys_enter_{syscall}")
    if not sysdir.exists():
        logger.error("Syscall '%s' doesn't exist on this platform", syscall)
        return [], ""
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
        logger.debug("syscall: %s", syscall)
        logger.debug("    %s %s", arg_type, arg_name)

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
            f"  if (pid != {ppid} && curtask->parent->pid != {ppid} && curtask->parent->parent->pid != {ppid}) {{ return }}"
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
        (str, str): Touple containing:
            - Custom header text to write to c header file
            - Bpftrace script to run
    """
    if syscalls is None or len(syscalls) == 0:
        syscalls = []
        syscall_dir = Path("/sys/kernel/debug/tracing/events/syscalls")
        for sysdir in syscall_dir.glob("sys_enter_*"):
            syscalls.append(sysdir.name.replace("sys_enter_", ""))
    logger.debug("Using syscalls: %s", ",".join(syscalls))

    header_lines = [
        "#pragma once",
        "#include <linux/sched.h>",
    ]
    func_lines = []
    for syscall in syscalls:
        func_header_lines, func_text = generate_func(syscall, comm, pid, ppid)
        if func_text != "":
            func_lines.append(func_text)
            for header_line in func_header_lines:
                if header_line not in header_lines:
                    header_lines.append(header_line)

    header = "\n".join(header_lines) + "\n"
    script = "\n\n".join(func_lines) + "\n"
    logger.debug("=== c header: ===")
    logger.debug(header)
    logger.debug("=== bpftrace script: ===")
    logger.debug(script)
    return header, script


def log_output_json(proc: subprocess.Popen):
    """
    Log output as JSON

    Args:
        proc(Popen): bpftrace process
    """
    for line in iter(proc.stdout.readline, b""):
        try:
            j = json.loads(line.decode("utf-8", "ignore"))
            if j["type"] == "attached_probes":
                probe_count = j["data"]["probes"]
                logger.debug(f"Started {probe_count} probes")
            elif j["type"] == "printf":
                # Build JSON with arguments as keys
                data = j["data"].strip().split("\t")
                dataj = {
                    "syscall": data[0],
                    "comm": data[1].split(":")[-1],
                    "pid": data[2].split(":")[-1],
                }
                for d in data[3:]:
                    ds = d.split(":")
                    dataj[ds[0]] = ":".join(ds[1:])
                logger.info(json.dumps(dataj))
        except (json.decoder.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.error("[*] Parsing Exception: %s - Line: %s", exc, line)
            continue


def log_output_pretty(proc: subprocess.Popen):
    """
    Log output to console in a pretty way

    Args:
        proc(Popen): bpftrace process
    """
    table = Table(
        expand=True,
        box=box.SIMPLE,
        style="dark_orange",
        row_styles=["orange1", "orange3"],
    )
    table.add_column("syscall", ratio=1)
    table.add_column("comm", ratio=1)
    table.add_column("pid", ratio=1)
    table.add_column("args", ratio=20)

    console = Console()
    with console.capture() as capture:
        console.print(table)
    logger.info(capture.get())

    for line in iter(proc.stdout.readline, b""):
        try:
            data = line.decode("utf-8", "ignore").strip().split("\t")
            if len(data) == 1:
                logger.debug(data[0])
            else:
                syscall = data[0]
                comm = data[1].split(":")[-1]
                pid = data[2].split(":")[-1]
                fields = "\t".join(data[3:])
                table.add_row(syscall, comm, pid, fields)

                # Only print newest row of actual data
                with console.capture() as capture:
                    console.print(table)
                logger.info(capture.get().splitlines()[-2])
        except UnicodeDecodeError as exc:
            logger.error("[*] Parsing Exception: %s - Line: %s", exc, line)
            continue


def log_output_plain(proc: subprocess.Popen):
    """
    Log output to console in a basic way

    Args:
        proc(Popen): bpftrace process
    """
    for line in iter(proc.stdout.readline, b""):
        try:
            logger.info(line.decode("utf-8", "ignore").strip())
        except UnicodeDecodeError as exc:
            logger.error("[*] Parsing Exception: %s - Line: %s", exc, line)
            continue


def run_bpftrace(header_file: Path, script_file: Path, output_format: str):
    """
    Start and run bpftrace

    Args:
        header_file(Path): Path to custom c header file
        script_file(Path): Path to bpftrace file
        output_format(str): Output format
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
    if output_format == "json":
        cmd += ["-f", "json"]
    logger.debug("Starting bpftrace with: %s", " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    if output_format == "json":
        log_output_json(proc)
    if output_format == "pretty":
        log_output_pretty(proc)
    else:
        log_output_plain(proc)


def main():
    """main"""
    parser = argparse.ArgumentParser(
        "eTrace - strace-like logging using bpftrace and eBPF"
    )
    parser.add_argument(
        "--syscall",
        "-s",
        action="append",
        help="Only log these specific syscalls",
    )
    parser.add_argument(
        "--group",
        "-g",
        choices=SYSCALL_GROUPS.keys(),
        action="append",
        help="strac-elike syscall group (see readme)",
    )
    parser.add_argument("--comm", "-c", help="Only log proceses with this name")
    parser.add_argument("--pid", "-p", type=int, help="Only log events from this pid")
    parser.add_argument(
        "--ppid",
        "-pp",
        type=int,
        help="Only log events from this pid, its children, and its grandchildren",
    )
    parser.add_argument(
        "--format",
        "-f",
        dest="output_format",
        choices=["plain", "pretty", "json"],
        default="pretty",
        help="Output Format",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Also output to file file",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose logging",
    )
    args = parser.parse_args()
    if not Path("/sys/kernel/debug/tracing/events/syscalls").exists():
        raise SystemError("Mssing debugfs")

    setup_logging(args.verbose, args.output)

    syscalls = []
    if args.group is not None:
        for group in args.group:
            syscalls += SYSCALL_GROUPS[group]
    if args.syscall is not None:
        syscalls += args.syscall

    header, script = generate_script(syscalls, args.comm, args.pid, args.ppid)
    with tempfile.TemporaryDirectory() as tmpdir:
        logger.debug("Using tmpdir %s", tmpdir)
        header_file = Path(tmpdir, "custom.h").resolve()
        script_file = Path(tmpdir, "trace.bt").resolve()

        with open(header_file, "w", encoding="utf-8") as f:
            f.write(header)
        with open(script_file, "w", encoding="utf-8") as f:
            f.write(script)
        try:
            run_bpftrace(header_file, script_file, args.output_format)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    if os.getuid() != 0:
        print("Re-Running as root", file=sys.stderr)
        sys.exit(os.system(f"sudo {sys.executable} {' '.join(sys.argv)}"))
    main()
