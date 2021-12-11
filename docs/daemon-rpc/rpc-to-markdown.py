#!/usr/bin/env python3

import sys
import os
import re
import fileinput
from enum import Enum, auto
import argparse

parser = argparse.ArgumentParser()
parser.add_argument(
    "-L",
    "--markdown-level",
    type=int,
    choices=[1, 2, 3, 4],
    default=1,
    help="Specify a heading level for the top-level endpoints; the default is 1, which means "
    "endpoints start in a `# name` section. For example, 3 would start endpoints with `### name` "
    "instead.",
)
parser.add_argument("--disable-public", help="disable PUBLIC endpoint detection (and disable marking endpoints as requiring admin)")
parser.add_argument("--disable-no-args", help="disable NO_ARGS enforcement of `Inputs: none`")
parser.add_argument("--no-sort", "-S", help="disable sorting endpoints by name (use file order)")
parser.add_argument("--no-group", "-G", help="disable grouping public and private endpoints together")
parser.add_argument("--no-emdash", "-M", help="disable converting ' -- ' to ' — ' (em-dashes)")
parser.add_argument("filename", nargs="+")
args = parser.parse_args()

for f in args.filename:
    if not os.path.exists(f):
        parser.error(f"{f} does not exist!")


# We parse the file looking for `///` comment blocks beginning with "RPC: <name>".
#
# Following comment lines are then a Markdown long description, until we find one or more of:
#
# "Inputs: none."
# "Outputs: none."
# "Inputs:" followed by markdown (typically an unordered list) until the next match from this list.
# "Outputs:" followed by markdown
# "Example input:" followed by a code block (i.e. containing json)
# "Example output:" followed by a code block (i.e. json output)
# "Old names: a, b, c"
#
# subject to the following rules:
# - each section must have exactly one Input; if the type inherits NO_ARGS then it *must* be an
#   "Inputs: none".
# - each section must have exactly one Output
# - "Example input:" section must be immediately followed by an "Example output"
# - "Example output:" sections are permitted without a preceding example input only if the endpoint
#   takes no inputs.
# - 0 or more example pairs are permitted.
# - Old names is permitted only once, if it occurs at all; the given names will be indicated as
#   deprecated, old names for the endpoint.
#
# Immediately following the command we expect to find a not-only-comment line (e.g. `struct
# <whatever>`) and apply some checks to this:
# - if the line does *not* contain the word `PUBLIC` then we mark the endpoint as requiring admin
#   access in its description.
# - if the line contains the word `NO_ARGS` then we double-check that "Inputs: none" was also given
#   and error if a more complex Inputs: section was written.


hdr = '#' * args.markdown_level
MD_INPUT_HEADER = f"{hdr}# Parameters"
MD_OUTPUT_HEADER = f"{hdr}# Returns"

MD_EXAMPLES_HEADER = f"{hdr}# Examples"
MD_EXAMPLE_IN_HDR = f"{hdr}## Input"
MD_EXAMPLE_OUT_HDR = f"{hdr}## Output"

MD_EX_SINGLE_IN_HDR = f"{hdr}# Example Input"
MD_EX_SINGLE_OUT_HDR = f"{hdr}# Example Output"

MD_NO_INPUT = "This endpoint takes no inputs. _(An optional empty dict/object may be provided, but is not required.)_"
MD_ADMIN = "\n\n> _This endpoint requires admin RPC access; it is not available on public RPC servers._"

RPC_COMMENT = re.compile(r"^\s*/// ?")
RPC_START = re.compile(r"^RPC:\s*(\w+)(.*)$")
IN_NONE = re.compile(r"^Inputs?: *[nN]one\.?$")
IN_SOME = re.compile(r"^Inputs?:\s*$")
OUT_SOME = re.compile(r"^Outputs?:\s*$")
EXAMPLE_IN = re.compile(r"^Example [iI]nputs?:\s*$")
EXAMPLE_OUT = re.compile(r"^Example [oO]utputs?:\s*$")
OLD_NAMES = re.compile(r"[Oo]ld [nN]ames?:")
PLAIN_NAME = re.compile(r"\w+")
PUBLIC = re.compile(r"\bPUBLIC\b")
NO_ARGS = re.compile(r"\bNO_ARGS\b")

input = fileinput.input(args.filename)
rpc_name = None


def error(msg):
    print(
        f"\x1b[31;1mERROR\x1b[0m[{input.filename()}:{input.filelineno()}] "
        f"while parsing endpoint {rpc_name}:",
        file=sys.stderr,
    )
    if msg and isinstance(msg, list):
        for m in msg:
            print(f"    - {m}", file=sys.stderr)
    else:
        print(f"    {msg}", file=sys.stderr)
    sys.exit(1)


class Parsing(Enum):
    DESC = auto()
    INPUTS = auto()
    OUTPUTS = auto()
    EX_IN = auto()
    EX_OUT = auto()
    NONE = auto()


cur_file = None
found_some = True

endpoints = []
admin_endpoints = []

while True:
    line = input.readline()
    if not line:
        break

    if cur_file is None or cur_file != input.filename():
        if not found_some:
            error(f"Found no parseable endpoint descriptions in {cur_file}")
        cur_file = input.filename()
        found_some = False

    line, removed_comment = re.subn(RPC_COMMENT, "", line, count=1)
    if not removed_comment:
        continue

    m = re.search(RPC_START, line)
    if not m:
        continue
    if m and m[2]:
        error(f"found trailing garbage after 'RPC: m[1]': {m[2]}")

    rpc_name = m[1]
    description, inputs, outputs = "", "", ""
    done_desc = False
    no_inputs = False
    examples = []
    cur_ex_in = None
    old_names = []

    mode = Parsing.DESC

    while True:
        line = input.readline()
        line, removed_comment = re.subn(RPC_COMMENT, "", line, count=1)
        if not removed_comment:
            break

        if re.search(IN_NONE, line):
            if inputs:
                error("found multiple Inputs:")
            inputs, no_inputs, mode = MD_NO_INPUT, True, Parsing.NONE

        elif re.search(IN_SOME, line):
            if inputs:
                error("found multiple Inputs:")
            mode = Parsing.INPUTS

        elif re.search(OUT_SOME, line):
            if outputs:
                error("found multiple Outputs:")
            mode = Parsing.OUTPUTS

        elif re.search(EXAMPLE_IN, line):
            if cur_ex_in is not None:
                error("found multiple input examples without paired output examples")
            cur_ex_in = ""
            mode = Parsing.EX_IN

        elif re.search(EXAMPLE_OUT, line):
            if not cur_ex_in and not no_inputs:
                error(
                    "found output example without preceding input example (or 'Inputs: none.')"
                )
            examples.append([cur_ex_in, ""])
            cur_ex_in = None
            mode = Parsing.EX_OUT

        elif re.search(OLD_NAMES, line):
            old_names = [x.strip() for x in line.split(':', 1)[1].split(',')]
            if not old_names or not all(re.fullmatch(PLAIN_NAME, n) for n in old_names):
                error(f"found unparseable old names line: {line}")

        elif mode == Parsing.NONE:
            if line and not line.isspace():
                error(f"Found unexpected content while looking for a tag: '{line}'")

        elif mode == Parsing.DESC:
            description += line

        elif mode == Parsing.INPUTS:
            inputs += line

        elif mode == Parsing.OUTPUTS:
            outputs += line

        elif mode == Parsing.EX_IN:
            cur_ex_in += line

        elif mode == Parsing.EX_OUT:
            examples[-1][1] += line

    problems = []
    # We hit the end of the commented section
    if not description or inputs.isspace():
        problems.append("endpoint has no description")
    if not inputs or inputs.isspace():
        problems.append(
            "endpoint has no inputs description; perhaps you need to add 'Inputs: none.'?"
        )
    if not outputs or outputs.isspace():
        problems.append("endpoint has no outputs description")
    if cur_ex_in is not None:
        problems.append(
            "endpoint has a trailing example input without a following example output"
        )
    if not no_inputs and any(not x[0] or x[0].isspace() for x in examples):
        problems.append("found one or more blank input examples")
    if any(not x[1] or x[1].isspace() for x in examples):
        problems.append("found one or more blank output examples")

    public = args.disable_public or re.search(PUBLIC, line)
    if not public:
        description += MD_ADMIN

    if old_names:
        s = 's' if len(old_names) > 1 else ''
        description += f"\n\n> _For backwards compatibility this endpoint is also accessible via the following deprecated endpoint name{s}:_"
        for n in old_names:
            description += f"\n> - _`{n}`_"

    if not args.disable_no_args:
        if re.search(NO_ARGS, line) and not no_inputs:
            problems.append("found NO_ARGS, but 'Inputs: none' was specified in description")

    if problems:
        error(problems)

    md = f"""
{hdr} `{rpc_name}`

{description}

{MD_INPUT_HEADER}

{inputs}

{MD_OUTPUT_HEADER}

{outputs}
"""

    if examples:
        if len(examples) > 1:
            md += f"\n\n{MD_EXAMPLES_HEADER}\n\n"
            for ex in examples:
                if ex[0] is not None:
                    md += f"""
{MD_EXAMPLE_IN_HDR}

{ex[0]}
"""
                md += f"""
{MD_EXAMPLE_OUT_HDR}

{ex[1]}
"""

        else:
            if examples[0][0] is not None:
                md += f"\n\n{MD_EX_SINGLE_IN_HDR}\n\n{examples[0][0]}"
            md += f"\n\n{MD_EX_SINGLE_OUT_HDR}\n\n{examples[0][1]}"

    if not args.no_emdash:
        md = md.replace(" -- ", " — ")

    if public or args.no_group:
        endpoints.append((rpc_name, md))
    else:
        admin_endpoints.append((rpc_name, md))

    found_some = True

if not found_some:
    error(f"Found no parseable endpoint descriptions in {cur_file}")

if not args.no_sort:
    endpoints.sort(key=lambda x: x[0])
    admin_endpoints.sort(key=lambda x: x[0])

for e in endpoints:
    print(e[1])
for e in admin_endpoints:
    print(e[1])
