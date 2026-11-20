import struct
import os
from formats.path import resource_path

BASE_ADDRESS = 0x400000
CODE_OFFSET = 64 + 56

def resolve_runtime_object(path):
    if not path:
        return None

    if not os.path.isabs(path):
        path = resource_path(path)

    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"Runtime object not found: {path}"
        )

    return path

def create_elf(machine_code, output):
    ident = (
        b"\x7fELF"
        + bytes([2, 1, 1, 0, 0])
        + b"\x00" * 7
    )

    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        2,
        62,
        1,
        BASE_ADDRESS + CODE_OFFSET,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0
    )

    program_header = struct.pack(
        "<IIQQQQQQ",
        1,
        5,  # Read + Execute
        0,
        BASE_ADDRESS,
        BASE_ADDRESS,
        CODE_OFFSET + len(machine_code),
        CODE_OFFSET + len(machine_code),
        0x1000
    )

    with open(output, "wb") as f:
        f.write(header)
        f.write(program_header)
        f.write(machine_code)

    os.chmod(output, 0o755)




def create_linked_elf(machine_code, output, external_patches, runtime_object):
    """Link generated SRCC code with native C runtime objects and libraries."""
    import subprocess
    import tempfile

    runtime_object = resolve_runtime_object(runtime_object)

    output = os.path.abspath(output)
    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)

    # Turn external-call placeholder bytes into real assembler call relocations.
    patches = {position - 1: symbol for position, symbol in external_patches}
    asm = resource_path("src/formats/elf.asm")

    with open(asm, "r", encoding="utf-8") as file:
        lines = file.readlines()

    position = 0
    total = len(machine_code)
    while position < total:
        if position in patches:
            symbol = patches[position]
            lines.append(f"call {symbol}@PLT")
            position += 5
            continue

        next_patch = min((p for p in patches if p > position), default=total)
        end = min(next_patch, position + 16, total)
        chunk = machine_code[position:end]
        if chunk:
            lines.append(".byte " + ", ".join(f"0x{b:02x}" for b in chunk))
        position = end

    lines.extend([
        ".size srcc_entry, .-srcc_entry",
        '.section .note.GNU-stack,"", @progbits',
        "",
    ])

    with tempfile.TemporaryDirectory(prefix="srcc-link-") as temp_dir:
        asm_path = os.path.join(temp_dir, "program.s")
        obj_path = os.path.join(temp_dir, "program.o")
        with open(asm_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        subprocess.run(["as", "--64", "-o", obj_path, asm_path], check=True)

        command = ["gcc", "-no-pie", obj_path]
        if runtime_object:
            command.append(runtime_object)

        try:
            libs = subprocess.check_output(
                ["pkg-config", "--libs", "libcurl"],
                text=True,
                stderr=subprocess.PIPE,
            ).split()
        except (subprocess.CalledProcessError, FileNotFoundError) as error:
            raise RuntimeError(
                "Could not get libcurl linker flags. Install libcurl development "
                "files and pkg-config, or check `pkg-config --libs libcurl`."
            ) from error

        command.extend(libs)
        command.extend(["-o", output])
        subprocess.run(command, check=True)
    os.chmod(output, 0o755)


def create_shared_elf(machine_code, output, labels, functions,
                     external_patches=None, runtime_object=None):

    """Build a PIC ELF shared object, optionally linked with native runtimes."""
    import subprocess
    import tempfile
    import re

    runtime_object = resolve_runtime_object(runtime_object)

    exported = list(functions)
    if not exported:
        raise SyntaxError("Shared library must export at least one function")

    for name in exported:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise SyntaxError(f"Invalid exported function name: {name}")
        if name not in labels:
            raise SyntaxError(f"Missing function label: {name}")

    patches = {position - 1: symbol
               for position, symbol in (external_patches or [])}

    offsets = {}
    for name, offset in labels.items():
        offsets.setdefault(offset, []).append(name)

    lines = [".section .text", ".p2align 4"]
    for name in exported:
        lines.extend([f".globl {name}", f".type {name}, @function"])

    position = 0
    total = len(machine_code)
    while position <= total:
        for name in offsets.get(position, []):
            lines.append(f"{name}:")
        if position == total:
            break

        if position in patches:
            lines.append(f"call {patches[position]}@PLT")
            position += 5
            continue

        next_patch = min((p for p in patches if p > position), default=total)
        next_label = min((p for p in offsets if p > position), default=total)
        end = min(next_patch, next_label, position + 16, total)
        chunk = machine_code[position:end]
        if chunk:
            lines.append(".byte " + ", ".join(f"0x{b:02x}" for b in chunk))
        position = end

    for name in exported:
        lines.append(f".size {name}, .-{name}")

    asm_template = resource_path("src/formats/shared_elf.asm")

    with open(asm_template, "r", encoding="utf-8") as file:
        lines.extend(file.readlines())
    assembly = "\n".join(lines)

    output = os.path.abspath(output)
    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="srcc-shared-") as temp_dir:
        asm_path = os.path.join(temp_dir, "library.s")
        obj_path = os.path.join(temp_dir, "library.o")
        with open(asm_path, "w", encoding="utf-8") as file:
            file.write(assembly)

        subprocess.run(["as", "--64", "-o", obj_path, asm_path], check=True)

        command = ["gcc", "-shared", "-o", output, obj_path]
        if runtime_object:
            command.append(runtime_object)
        if runtime_object:
            try:
                libs = subprocess.check_output(
                    ["pkg-config", "--libs", "libcurl"],
                    text=True,
                    stderr=subprocess.PIPE,
                ).split()
            except (subprocess.CalledProcessError, FileNotFoundError) as error:
                raise RuntimeError(
                    "Could not get libcurl linker flags. Install libcurl "
                    "development files and pkg-config."
                ) from error
            command.extend(libs)

        subprocess.run(command, check=True)
    os.chmod(output, 0o755)
