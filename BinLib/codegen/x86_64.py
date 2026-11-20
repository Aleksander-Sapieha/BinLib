
class X86_64:
    def __init__(self):
        self.code = bytearray()
        self.data = bytearray()

        self.labels = {}
        self.rel_patches = []
        self.data_patches = []
        self.rip_patches = []
        self.external_patches = []
        self.pic = False

        self.print_int_needed = False
        self.input_reader_needed = False
        self.input_parser_needed = False
        self.input_error_kinds = set()
        self.input_label_index = 0

    def emit(self, *values):
        self.code.extend(values)

    def label(self, name):
        if name in self.labels:
            raise SyntaxError(f"Duplicate label: {name}")
        self.labels[name] = len(self.code)

    def call(self, name):
        self.emit(0xE8)
        self.rel_patches.append((len(self.code), name))
        self.code.extend(b"\x00" * 4)

    def call_external(self, symbol):
        """Emit a call that the system linker will resolve."""
        self.emit(0xE8)
        self.external_patches.append((len(self.code), symbol))
        self.code.extend(b"\x00" * 4)

    def jump(self, name):
        self.emit(0xE9)
        self.rel_patches.append((len(self.code), name))
        self.code.extend(b"\x00" * 4)

    def jcc(self, condition, name):
        self.emit(0x0F, condition)
        self.rel_patches.append((len(self.code), name))
        self.code.extend(b"\x00" * 4)

    # Integer instructions

    def mov_eax(self, value):
        self.emit(0xB8)
        self.code.extend(
            (value & 0xFFFFFFFF).to_bytes(4, "little")
        )

    def load_variable(self, offset):
        self.emit(0x8B, 0x45, (-offset) & 0xFF)

    def store_variable(self, offset):
        self.emit(0x89, 0x45, (-offset) & 0xFF)

    def push_rax(self):
        self.emit(0x50)

    def pop_rcx(self):
        self.emit(0x59)

    def mov_ecx_eax(self):
        self.emit(0x89, 0xC1)

    def add_eax_ecx(self):
        self.emit(0x01, 0xC8)

    def sub_eax_ecx(self):
        self.emit(0x29, 0xC8)

    def mul_eax_ecx(self):
        self.emit(0x0F, 0xAF, 0xC1)

    def div_eax_ecx(self):
        self.emit(0x99)       # cdq
        self.emit(0xF7, 0xF9) # idiv ecx

    def neg_eax(self):
        self.emit(0xF7, 0xD8)

    def compile_binary(self, operation):
        instructions = {
            "+": self.add_eax_ecx,
            "-": self.sub_eax_ecx,
            "*": self.mul_eax_ecx,
            "/": self.div_eax_ecx,
            "//": self.div_eax_ecx,
        }

        if operation not in instructions:
            raise SyntaxError(
                f"Unsupported arithmetic operator: {operation}"
            )

        instructions[operation]()

    # Strings

    def lea_rip_rsi(self, offset):
        self.emit(0x48, 0x8D, 0x35)
        self.rip_patches.append((len(self.code), offset))
        self.code.extend(b"\x00" * 4)

    def lea_rip_rdi(self, offset):
        self.emit(0x48, 0x8D, 0x3D)
        self.rip_patches.append((len(self.code), offset))
        self.code.extend(b"\x00" * 4)

    def lea_rip_rax(self, offset):
        # lea rax, [rip + displacement]
        self.emit(0x48, 0x8D, 0x05)
        self.rip_patches.append((len(self.code), offset))
        self.code.extend(b"\x00" * 4)

    def load_parameter_rax(self):
        # First function argument is saved at [rbp-8].
        self.emit(0x48, 0x8B, 0x45, 0xF8)  # mov rax, [rbp-8]

    def movabs_rdi_data(self, offset):
        if self.pic:
            self.lea_rip_rdi(offset)
        else:
            self.emit(0x48, 0xBF)
            self.data_patches.append((len(self.code), offset))
            self.code.extend(b"\x00" * 8)

    def load_parameter_rsi(self):
        # First function argument is saved at [rbp-8] by function_start().
        self.emit(0x48, 0x8B, 0x75, 0xF8)  # mov rsi, [rbp-8]

    def movabs_rsi(self, offset):
        if self.pic:
            self.lea_rip_rsi(offset)
        else:
            self.emit(0x48, 0xBE)
            self.data_patches.append((len(self.code), offset))
            self.code.extend(b"\x00" * 8)

    def write(self, text):
        encoded = text.encode("utf-8")

        if not encoded:
            return

        offset = len(self.data)
        self.data.extend(encoded)

        self.mov_eax(1)
        self.emit(0xBF)
        self.code.extend((1).to_bytes(4, "little"))

        self.movabs_rsi(offset)

        self.emit(0xBA)
        self.code.extend(len(encoded).to_bytes(4, "little"))

        self.emit(0x0F, 0x05)

    def lea_rbp_rsi(self, offset):
        self.emit(0x48, 0x8D, 0xB5)
        self.code.extend((-offset).to_bytes(4, "little", signed=True))

    def store_stack_eax(self, offset):
        self.emit(0x89, 0x85)
        self.code.extend((-offset).to_bytes(4, "little", signed=True))

    def read_input_line(self, buffer_offset, length_offset):
        self.input_reader_needed = True
        self.input_error_kinds.add("read")

        index = self.input_label_index
        self.input_label_index += 1
        loop_label = f"__srcc_input_loop_{index}"
        done_label = f"__srcc_input_done_{index}"
        store_label = f"__srcc_input_store_{index}"

        self.lea_rbp_rsi(buffer_offset)
        self.emit(0x45, 0x31, 0xC0)  # xor r8d, r8d
        self.label(loop_label)
        self.emit(
            0xB8, 0, 0, 0, 0,       # read
            0xBF, 0, 0, 0, 0,       # stdin
            0xBA, 1, 0, 0, 0,       # one byte
            0x0F, 0x05,             # syscall
            0x85, 0xC0              # test eax, eax
        )
        self.jcc(0x84, done_label)  # EOF
        self.jcc(0x88, "__srcc_input_read_error")
        self.emit(0x80, 0x3E, 0x0A)  # cmp byte [rsi], newline
        self.jcc(0x84, done_label)
        self.emit(
            0x41, 0x81, 0xF8, 0xFF, 0, 0, 0  # cmp r8d, 255
        )
        self.jcc(0x83, "__srcc_input_too_long")
        self.emit(0x41, 0xFF, 0xC0)  # inc r8d
        self.emit(0x48, 0xFF, 0xC6)  # inc rsi
        self.jump(loop_label)

        self.label(done_label)
        self.emit(0x45, 0x85, 0xC0)  # test r8d, r8d
        self.jcc(0x84, store_label)
        self.emit(0x80, 0x7E, 0xFF, 0x0D)  # cmp byte [rsi-1], CR
        self.jcc(0x85, store_label)
        self.emit(0x41, 0xFF, 0xC8)  # dec r8d
        self.label(store_label)
        self.emit(0x44, 0x89, 0x85)
        self.code.extend((-length_offset).to_bytes(4, "little", signed=True))

    def write_input(self, buffer_offset, length_offset):
        self.emit(
            0xB8, 1, 0, 0, 0,       # write
            0xBF, 1, 0, 0, 0        # stdout
        )
        self.lea_rbp_rsi(buffer_offset)
        self.emit(0x8B, 0x95)
        self.code.extend((-length_offset).to_bytes(4, "little", signed=True))
        self.emit(0x0F, 0x05)

    def parse_input_integer(self, buffer_offset, length_offset):
        self.input_parser_needed = True
        self.input_error_kinds.add("integer")
        self.lea_rbp_rdi(buffer_offset)
        self.emit(0x8B, 0xB5)
        self.code.extend((-length_offset).to_bytes(4, "little", signed=True))
        self.call("__srcc_parse_int")

    def lea_rbp_rdi(self, offset):
        self.emit(0x48, 0x8D, 0xBD)
        self.code.extend((-offset).to_bytes(4, "little", signed=True))

    def generate_input_parser(self):
        self.label("__srcc_parse_int")
        self.emit(
            0x55,                   # push rbp
            0x48, 0x89, 0xE5,       # mov rbp, rsp
            0x85, 0xF6              # test esi, esi
        )
        self.jcc(0x84, "__srcc_parse_invalid")
        self.emit(
            0x45, 0x31, 0xC0,       # xor r8d, r8d
            0x0F, 0xB6, 0x0F        # movzx ecx, byte [rdi]
        )
        self.emit(0x80, 0xF9, 0x2D)  # cmp cl, '-'
        self.jcc(0x85, "__srcc_parse_check_plus")
        self.emit(0x41, 0xB8, 1, 0, 0, 0)  # mov r8d, 1
        self.jump("__srcc_parse_sign")

        self.label("__srcc_parse_check_plus")
        self.emit(0x80, 0xF9, 0x2B)  # cmp cl, '+'
        self.jcc(0x85, "__srcc_parse_start")

        self.label("__srcc_parse_sign")
        self.emit(
            0x48, 0xFF, 0xC7,       # inc rdi
            0xFF, 0xCE,             # dec esi
            0x85, 0xF6              # test esi, esi
        )
        self.jcc(0x84, "__srcc_parse_invalid")

        self.label("__srcc_parse_start")
        self.emit(0x31, 0xC0)  # xor eax, eax
        self.label("__srcc_parse_loop")
        self.emit(0x85, 0xF6)  # test esi, esi
        self.jcc(0x84, "__srcc_parse_done")
        self.emit(
            0x0F, 0xB6, 0x0F,       # movzx ecx, byte [rdi]
            0x83, 0xF9, 0x30        # cmp ecx, '0'
        )
        self.jcc(0x82, "__srcc_parse_invalid")
        self.emit(0x83, 0xF9, 0x39)  # cmp ecx, '9'
        self.jcc(0x87, "__srcc_parse_invalid")
        self.emit(
            0x83, 0xE9, 0x30,       # sub ecx, '0'
            0x48, 0x6B, 0xC0, 0x0A  # imul rax, rax, 10
        )
        self.jcc(0x80, "__srcc_parse_invalid")
        self.emit(0x48, 0x01, 0xC8)  # add rax, rcx
        self.jcc(0x80, "__srcc_parse_invalid")
        self.emit(
            0x48, 0xFF, 0xC7,       # inc rdi
            0xFF, 0xCE              # dec esi
        )
        self.jump("__srcc_parse_loop")

        self.label("__srcc_parse_done")
        self.emit(0x45, 0x85, 0xC0)  # test r8d, r8d
        self.jcc(0x84, "__srcc_parse_check_range")
        self.emit(0x48, 0xF7, 0xD8)  # neg rax
        self.jcc(0x80, "__srcc_parse_invalid")

        self.label("__srcc_parse_check_range")
        self.emit(
            0x48, 0x63, 0xD0,       # movsxd rdx, eax
            0x48, 0x39, 0xD0         # cmp rax, rdx
        )
        self.jcc(0x85, "__srcc_parse_invalid")
        self.emit(0x5D, 0xC3)  # pop rbp; ret

        self.label("__srcc_parse_invalid")
        self.jump("__srcc_invalid_integer")

    def generate_input_error(self, label, message):
        self.label(label)
        encoded = message.encode("utf-8")
        offset = len(self.data)
        self.data.extend(encoded)
        self.emit(
            0xB8, 1, 0, 0, 0,       # write
            0xBF, 2, 0, 0, 0        # stderr
        )
        self.lea_rip_rsi(offset)
        self.emit(0xBA)
        self.code.extend(len(encoded).to_bytes(4, "little"))
        self.emit(
            0x0F, 0x05,             # syscall
            0xB8, 60, 0, 0, 0,      # exit
            0xBF, 1, 0, 0, 0,       # status 1
            0x0F, 0x05              # syscall
        )

    # Function support

    def function_start(self):
        self.emit(
            0x55,
            0x48, 0x89, 0xE5,
            0x48, 0x83, 0xEC, 0x10,
            0x48, 0x89, 0x7D, 0xF8,
            0x48, 0x89, 0x75, 0xF0
        )

    def write_parameter(self):
        self.emit(
            0xB8, 1, 0, 0, 0,
            0xBF, 1, 0, 0, 0,
            0x48, 0x8B, 0x75, 0xF8,
            0x8B, 0x55, 0xF0,
            0x0F, 0x05
        )

    def function_end(self):
        # Functions without an explicit return produce integer zero.
        self.emit(0x31, 0xC0, 0xC9, 0xC3)  # xor eax,eax; leave; ret

    # Integer printing runtime

    def print_integer(self):
        self.print_int_needed = True

    def generate_integer_printer(self):
        self.label("__srcc_print_int")

        self.emit(
            0x55,                   # push rbp
            0x48, 0x89, 0xE5,       # mov rbp, rsp
            0x48, 0x83, 0xEC, 0x20, # sub rsp, 32
            0x89, 0xF8,             # mov eax, edi
            0xC6, 0x45, 0xFF, 0x0A, # newline at [rbp-1]
            0x48, 0x8D, 0x75, 0xFF, # lea rsi, [rbp-1]
            0xB9, 10, 0, 0, 0,     # mov ecx, 10
            0x45, 0x31, 0xC0,      # xor r8d, r8d
            0x85, 0xC0             # test eax, eax
        )

        self.jcc(0x89, "__srcc_positive")

        self.emit(
            0x41, 0xB8, 1, 0, 0, 0, # mov r8d, 1
            0xF7, 0xD8               # neg eax
        )

        self.label("__srcc_positive")
        self.label("__srcc_digit_loop")

        self.emit(
            0x31, 0xD2,       # xor edx, edx
            0xF7, 0xF1,       # div ecx
            0x80, 0xC2, 0x30, # add dl, '0'
            0x48, 0xFF, 0xCE, # dec rsi
            0x88, 0x16,       # mov [rsi], dl
            0x85, 0xC0        # test eax, eax
        )

        self.jcc(0x85, "__srcc_digit_loop")

        self.emit(0x45, 0x85, 0xC0)
        self.jcc(0x84, "__srcc_no_sign")

        self.emit(
            0x48, 0xFF, 0xCE,
            0xC6, 0x06, 0x2D
        )

        self.label("__srcc_no_sign")

        self.emit(
            0x48, 0x8D, 0x55, 0xFF, # lea rdx, [rbp-1]
            0x48, 0x29, 0xF2,       # sub rdx, rsi
            0xB8, 1, 0, 0, 0,       # write
            0xBF, 1, 0, 0, 0,       # stdout
            0x0F, 0x05,             # syscall
            0xC9,                   # leave
            0xC3                    # ret
        )

    def print_eax(self):
        self.print_integer()
        self.emit(0x89, 0xC7)  # mov edi, eax
        self.call("__srcc_print_int")

    # Program exit

    def exit(self, status=0):
        self.mov_eax(60)
        self.emit(0xBF)
        self.code.extend(status.to_bytes(4, "little"))
        self.emit(0x0F, 0x05)

    # Finalize machine code

    def finish(self, base_address, code_offset):
        if self.print_int_needed:
            self.generate_integer_printer()
        if self.input_parser_needed:
            self.generate_input_parser()
        if "read" in self.input_error_kinds:
            self.generate_input_error(
                "__srcc_input_read_error",
                "Could not read from standard input\n",
            )
        if self.input_reader_needed:
            self.generate_input_error(
                "__srcc_input_too_long",
                "Input line exceeds 255 bytes\n",
            )
        if "integer" in self.input_error_kinds:
            self.generate_input_error(
                "__srcc_invalid_integer",
                "Input is not a valid 32-bit integer\n",
            )

        # Resolve RIP-relative references to data appended after the code.
        for position, offset in self.rip_patches:
            target = len(self.code) + offset
            displacement = target - (position + 4)
            self.code[position:position + 4] = displacement.to_bytes(
                4, "little", signed=True
            )

        data_address = base_address + code_offset + len(self.code)

        for position, offset in self.data_patches:
            address = data_address + offset

            self.code[position:position + 8] = (
                address.to_bytes(8, "little")
            )

        external_positions = {position for position, _ in self.external_patches}

        for position, name in self.rel_patches:
            if position in external_positions:
                continue
            if name not in self.labels:
                raise SyntaxError(f"Unknown label: {name}")

            displacement = (
                self.labels[name] - (position + 4)
            )

            self.code[position:position + 4] = (
                displacement.to_bytes(4, "little", signed=True)
            )

        return bytes(self.code + self.data)
