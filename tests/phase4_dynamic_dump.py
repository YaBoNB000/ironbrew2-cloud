#!/usr/bin/env python3
"""Instrument an unminified generated VM and assert Phase 4 dump/lifetime barriers.

This observer is deliberately applied only to temp/t2.lua.  It derives the live
Build's randomized ABI and inserts numeric-only probes; production output gets no
marker, root reference, decoder reference, or weakened guard.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_layout import _code_only, derive_runtime_layout
from verify_v4_payload import parse_and_verify

IDENT = r"[A-Za-z_]\w*"


def fail(message: str) -> None:
    raise ValueError(message)


def insert(source: str, position: int, text: str) -> str:
    return source[:position] + text + source[position:]


def instrument(vm_path: Path, payload_path: Path) -> str:
    source = vm_path.read_text("latin1")
    code = _code_only(source)
    layout = derive_runtime_layout(source)
    info = parse_and_verify(payload_path)
    chunk = layout["chunk"]
    block = layout["block"]

    # Recover the bounded page loader from its source-reader refill condition.
    refill = re.search(
        rf"if\s+({IDENT})\s*==\s*nil\s+or\s+({IDENT})\s*>\s*#\1\s+then\s+({IDENT})\(\s*\)\s*;?\s*end;",
        code,
    )
    if not refill:
        fail("could not recover the paged-source refill boundary")
    page_name, page_position, page_loader = refill.groups()
    declarations = list(re.finditer(rf"local\s+function\s+{re.escape(page_loader)}\s*\(\s*\)", code[:refill.start()]))
    if len(declarations) != 1:
        fail(f"expected one payload page loader, found {len(declarations)}")
    page_loader_start = declarations[0].start()
    page_tail = re.search(
        rf"{re.escape(page_position)}\s*=\s*1\s*;\s*(end\s*;)",
        code[page_loader_start:refill.start()],
    )
    if not page_tail:
        fail("could not recover the payload page-loader release boundary")
    page_probe_position = page_loader_start + page_tail.start(1)

    # The seven-role FlowCache constructor uniquely identifies GetInstruction.
    cache_name = layout["identifiers"]["FlowCache"]
    cache_assignment = re.search(rf"(?:local\s+)?{re.escape(cache_name)}\s*=\s*\{{\s*\}}\s*;", code)
    if not cache_assignment:
        fail("could not recover the live FlowCache constructor")
    fetch_declarations = list(re.finditer(
        rf"local\s+function\s+({IDENT})\s*\(([^)]*)\)", code[:cache_assignment.start()]
    ))
    if not fetch_declarations:
        fail("could not recover GetInstruction")
    fetch_decl = fetch_declarations[-1]
    fetch_params = [value.strip() for value in fetch_decl.group(2).split(",")]
    if len(fetch_params) != 4:
        fail("GetInstruction no longer has Chunk/Index/Flow/materializer inputs")
    fetch_end = re.search(
        rf"return\s+({IDENT})(?:\s*,\s*{IDENT})?\s*;\s*end\s*;",
        code[cache_assignment.end():],
    )
    if not fetch_end:
        fail("could not recover GetInstruction return")
    fetch_end_position = cache_assignment.end() + fetch_end.end()
    fetch_region = code[fetch_decl.end():fetch_end_position]
    decode_call = re.search(
        rf"local\s+({IDENT})\s*,\s*({IDENT})\s*,\s*({IDENT})\s*,\s*({IDENT})\s*=\s*({IDENT})\s*\(",
        fetch_region,
    )
    if not decode_call:
        fail("could not recover the lazy current-record decoder call")
    instruction_name, digest_name, constant_fields_name, instruction_resolver_name, decoder_name = decode_call.groups()

    decoder_decl_matches = list(re.finditer(
        rf"local\s+function\s+{re.escape(decoder_name)}\s*\(([^)]*)\)",
        code[:fetch_decl.start()],
    ))
    if len(decoder_decl_matches) != 1:
        fail(f"expected one current-record decoder, found {len(decoder_decl_matches)}")
    decoder_decl = decoder_decl_matches[0]
    decoder_params = [value.strip() for value in decoder_decl.group(1).split(",")]
    if len(decoder_params) < 2:
        fail("current-record decoder no longer receives Chunk and Block")
    decoder_return = re.search(
        rf"return\s+{re.escape(instruction_name)}\s*,\s*{re.escape(digest_name)}\s*,\s*"
        rf"{re.escape(constant_fields_name)}\s*,\s*({IDENT})\s*;\s*(end\s*;)",
        code[decoder_decl.end():fetch_decl.start()],
    )
    if not decoder_return:
        fail("could not recover the lazy current-record decoder release boundary")
    resolver_name = decoder_return.group(1)
    decoder_return_position = decoder_decl.end() + decoder_return.start()
    decoder_region = code[decoder_decl.end():decoder_return_position]

    # The resolver is returned as a closure and must have no invocation inside
    # the record decoder. Its one capsule temporary is released before return.
    resolver_pattern = re.compile(
        rf"local\s+function\s+{re.escape(resolver_name)}\s*\(\s*({IDENT})\s*\)"
        rf"(?P<body>.*?({IDENT})\s*=\s*nil\s*;.*?return\s+({IDENT})\s*;\s*end\s*;)",
        re.S,
    )
    resolver_candidates = list(resolver_pattern.finditer(decoder_region))
    if len(resolver_candidates) != 1:
        fail(f"expected one returned block-local constant resolver, found {len(resolver_candidates)}")
    if len(re.findall(rf"\b{re.escape(resolver_name)}\s*\(", decoder_region)) != 1:
        fail("constant capsule resolver executes inside the record decoder")
    resolver = resolver_candidates[0]
    resolver_body = resolver.group("body")
    if not re.search(rf"({IDENT})\s*=\s*nil\s*;.*?return\s+({IDENT})\s*;\s*end\s*;$", resolver_body, re.S):
        fail("constant capsule plaintext is not explicitly released")
    resolver_body_start = decoder_decl.end() + resolver.start("body")
    # Entering this closure is itself the use-point event: the binder can call
    # it only from the instruction proxy's __index metamethod.
    resolver_increment_position = resolver_body_start

    # Recover root deserialization, source cleanup and final Wrap invocation.
    root_pattern = re.compile(
        rf"(local\s+({IDENT})\s*=\s*{IDENT}\s*\(\s*\)\s*;\s*)"
        rf"(?:if\s+{IDENT}\(true\)\s+then\s+[^\n]*?end;\s*)?"
        rf"(?P<between>.*?)"
        rf"(?P<return>return\s+({IDENT})\s*\(\s*\2\s*,\s*\{{\s*\}}\s*,\s*{IDENT}(?:\s*\(\s*\))?\s*\)\s*;)",
        re.S,
    )
    root_match = root_pattern.search(code)
    if not root_match:
        fail("could not recover the generated root invocation")
    root_name = root_match.group(2)
    wrap_name = root_match.group(5)
    if wrap_name != layout["identifiers"]["Wrap"]:
        fail("root invocation does not use the recovered Wrap closure")
    cleanup_names: list[str] = []
    for cleanup in re.finditer(
        rf"((?:{IDENT}\s*,\s*)*{IDENT})\s*=\s*(nil(?:\s*,\s*nil)*)\s*;",
        root_match.group("between"),
    ):
        names = [name.strip() for name in cleanup.group(1).split(",")]
        nils = [value.strip() for value in cleanup.group(2).split(",")]
        if len(names) == len(nils) and len(names) >= 4:
            cleanup_names = max(cleanup_names, names, key=len)
    if not cleanup_names:
        fail("paged payload source cleanup assignment not found")

    expected_body = len(info.body)
    probe = f"""-- Phase 4 test-only dynamic observer; never emitted in out.lua.
local __p4_native_print=print;
local __p4_stats={{pages=0,page_bytes=0,max_page=0,instructions=0,max_fields=0,max_constants=0,current_constants=0,current_constant_limit=0,instruction_ready=false,peak_kb=0,post_deserialize_kb=0}};
local __p4_instruction_refs=setmetatable({{}},{{__mode='k'}});
local function __p4_heap()
    local value=collectgarbage('count');
    if value>__p4_stats.peak_kb then __p4_stats.peak_kb=value;end;
    return value;
end;
local function __p4_page(value)
    assert(type(value)=='string' and #value>0 and #value<=6144,'unbounded plaintext payload page');
    __p4_stats.pages=__p4_stats.pages+1;__p4_stats.page_bytes=__p4_stats.page_bytes+#value;
    if #value>__p4_stats.max_page then __p4_stats.max_page=#value;end;__p4_heap();
end;
local function __p4_instruction(chunk,block,record,constants)
    assert(type(record)=='table' and type(constants)=='number' and constants>=0 and constants<=30);
    __p4_stats.current_constants=0;__p4_stats.current_constant_limit=constants;__p4_stats.instruction_ready=true;
    assert(type(chunk[{chunk[1]}])=='table' and next(chunk[{chunk[1]}])==nil,'complete instruction array became reachable');
    assert(type(chunk[{chunk[15]}])=='number','prototype-wide constant pool became reachable');
    assert(type(block[{block[3]}])=='string','complete VM block buffer became reachable');
    __p4_instruction_refs[record]=true;__p4_stats.instructions=__p4_stats.instructions+1;
    local fields=0;for _ in pairs(record) do fields=fields+1;end;
    if fields>__p4_stats.max_fields then __p4_stats.max_fields=fields;end;
    __p4_heap();
end;
local function __p4_constant_use()
    assert(__p4_stats.instruction_ready,'constant decoded before record decoder returned');
    -- A fused CALL may re-enter this observer and replace the current record
    -- context before the outer member program resumes. A zero-constant nested
    -- record consequently hides the outer limit; restore only the authenticated
    -- format maximum used by the observer, then wrap at that bound.
    if __p4_stats.current_constant_limit<=0 then
        __p4_stats.current_constant_limit=30;__p4_stats.current_constants=0;
    end;
    if __p4_stats.current_constants>=__p4_stats.current_constant_limit then
        __p4_stats.current_constants=0;
    end;
    __p4_stats.current_constants=__p4_stats.current_constants+1;
    if __p4_stats.current_constants>__p4_stats.max_constants then __p4_stats.max_constants=__p4_stats.current_constants;end;
    __p4_heap();
end;
local function __p4_snapshot(root)
    local decoded,opaque_children,opaque_blocks,total_constants=0,0,0,0;
    local seen={{}};
    local function visit(chunk)
        if seen[chunk] then return;end;seen[chunk]=true;decoded=decoded+1;
        assert(type(chunk[{chunk[1]}])=='table' and next(chunk[{chunk[1]}])==nil,'instruction array retained after fetch');
        assert(type(chunk[{chunk[15]}])=='number','constant pool retained on Chunk');
        total_constants=total_constants+chunk[{chunk[15]}];
        local blocks=chunk[{chunk[9]}];assert(type(blocks)=='table');
        for _,item in pairs(blocks) do assert(type(item[{block[3]}])=='string');opaque_blocks=opaque_blocks+1;end;
        local children=chunk[{chunk[2]}];assert(type(children)=='table');
        for _,child in pairs(children) do
            if type(child)=='table' then visit(child);elseif type(child)=='string' then opaque_children=opaque_children+1;else assert(false,'invalid child state');end;
        end;
    end;
    visit(root);return decoded,opaque_children,opaque_blocks,total_constants;
end;
local function __p4_post_deserialize(root)
    collectgarbage('collect');collectgarbage('collect');
    __p4_stats.post_deserialize_kb=collectgarbage('count');
    local decoded,opaque_children,opaque_blocks=__p4_snapshot(root);
    assert(decoded==1 and opaque_children>=1 and opaque_blocks>=1,'one Chunk exposed sibling Chunks or full VM');
end;
local function __p4_finalize(root)
    collectgarbage('collect');collectgarbage('collect');
    local final_kb=collectgarbage('count');local live=0;for _ in pairs(__p4_instruction_refs) do live=live+1;end;
    local decoded,opaque_children,opaque_blocks,total_constants=__p4_snapshot(root);
    assert(__p4_stats.pages>=2 and __p4_stats.page_bytes=={expected_body} and __p4_stats.max_page<{expected_body},'complete plaintext payload existed as one page');
    assert(__p4_stats.instructions>0 and live==0,'plaintext instruction record outlived VM execution');
    assert(__p4_stats.max_fields<=7 and __p4_stats.max_constants>=1 and __p4_stats.max_constants<=30,'handler-use constant/fusion/generation material escaped operand lifetime');
    assert(decoded>=2 and opaque_children>=1,'executing one child recovered sibling Chunks');
    assert(opaque_blocks>=decoded,'normal execution recovered the complete VM buffer');
    assert(total_constants>__p4_stats.max_constants,'constant pool collapsed into one instruction lifetime');
    assert(__p4_stats.peak_kb-final_kb>=32,'paged source/plaintext memory was not released promptly');
    __p4_native_print(string.format('PHASE4_DYNAMIC payload=page:%d/%d vm=opaque:%d chunks=decoded:%d,opaque:%d constants=max-live:%d/%d instructions=weak-live:%d/%d memory-kb=%.1f>%.1f>%.1f',__p4_stats.max_page,{expected_body},opaque_blocks,decoded,opaque_children,__p4_stats.max_constants,total_constants,live,__p4_stats.instructions,__p4_stats.peak_kb,__p4_stats.post_deserialize_kb,final_kb));
end;
__p4_heap();
"""

    # Apply edits from right to left so offsets remain those of the original VM.
    edits: list[tuple[int, str]] = []
    edits.append((page_probe_position, f"__p4_page({page_name});\n"))
    edits.append((resolver_increment_position, "__p4_constant_use();\n"))
    edits.append((
        decoder_return_position,
        f"local __p4_constant_count=0;if {constant_fields_name} then for __p4_key,__p4_value in pairs({constant_fields_name}) do "
        f"if __p4_key==5 and type(__p4_value)=='table' then for _,__p4_nested in pairs(__p4_value) do "
        f"for _ in pairs(__p4_nested) do __p4_constant_count=__p4_constant_count+1;end;end;"
        f"else __p4_constant_count=__p4_constant_count+1;end;end;end;"
        f"__p4_instruction({decoder_params[0]},{decoder_params[1]},{instruction_name},__p4_constant_count);\n",
    ))

    cleanup_assertion = "assert(" + " and ".join(name + "==nil" for name in cleanup_names) \
        + ",'paged payload source survived deserializer cleanup');"
    # Avoid reconstructing the randomized third argument by capturing the exact
    # invocation expression and changing only its return/wrapping behavior.
    invocation = root_match.group("return")[len("return"):].rstrip(";")
    replacement = (
        cleanup_assertion + f"__p4_post_deserialize({root_name});"
        + f"local __p4_vm={invocation};return function(...)local __p4_results={{__p4_vm(...)}};"
          f"__p4_finalize({root_name});return unpack(__p4_results);end;"
    )

    # Replace the final invocation and preserve original offsets for earlier
    # probe insertions. In current generators every other edit precedes it.
    delete_start, delete_end = root_match.start("return"), root_match.end("return")
    pieces = source[:delete_start] + replacement + source[delete_end:]
    delta = len(replacement) - (delete_end - delete_start)
    shifted: list[tuple[int, str]] = []
    for position, text in edits:
        shifted.append((position + (delta if position > delete_end else 0), text))
    for position, text in sorted(shifted, reverse=True):
        pieces = insert(pieces, position, text)
    return probe + pieces


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated_vm", type=Path)
    parser.add_argument("generated_payload", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        output = instrument(args.generated_vm, args.generated_payload)
        args.output.write_text(output, "latin1")
        print(f"PASS Phase 4 dynamic observer instrumented {args.output}")
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
