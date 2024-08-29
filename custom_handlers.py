from typing import List, Optional

TEMPLATE = """
tracepoint:syscalls:{name} {{
{code}
}}
"""


def custom_empty(
    _comm: Optional[str], _pid: Optional[int], _ppid: Optional[int]
) -> tuple[List[str], str]:
    """
    Custom logic for any syscall we can't be bothered implementing
    """
    header_lines = []
    output = ""
    return header_lines, output


HANDLERS = {
    "sigaltstack": custom_empty,
    "personality": custom_empty,
}
