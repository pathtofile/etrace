"""
Handler to create custom functions for each syscall
"""

from typing import List

# Disable this so long lines aren't too confusing
# pylint:disable=line-too-long


def custom_empty(_filter_code: List[str]) -> tuple[List[str], str]:
    """
    Custom logic for any syscall we can't be bothered implementing
    """
    header_lines = []
    output = ""
    return header_lines, output


def custom_sched_process_exec(filter_code: List[str]) -> tuple[List[str], str]:
    """
    Custom logic for the sched_process_exec syscall
    """
    header_lines = []
    output_lines = []
    output_lines = [
        "tracepoint:sched:sched_process_exec {",
        *filter_code,
    ]

    output_lines.append("  $arg_start=curtask->mm->arg_start;")
    output_lines.append("  $arg_end=curtask->mm->arg_end;")
    output_lines.append(
        '  printf("s\\tsched_process_exec\\t%d\\t%d\\t%s\\tfilename:%s\\targv:%r\\n", tid, pid, comm, str(args->filename), buf(uptr($arg_start), $arg_end-$arg_start));'
    )

    output_lines.append("}")
    output = "\n".join(output_lines)
    return header_lines, output


HANDLERS = {
    "sigaltstack": custom_empty,
    "personality": custom_empty,
    "sched_process_exec": custom_sched_process_exec,
}
