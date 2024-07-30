const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    const listing = "listing_0040_challenge_movs";

    try compareToNasm(alloc, listing, .{ .print = true });
}

fn parse(writer: anytype, data: []const u8, args: Args) !void {
    var idx: usize = 0;

    while (idx < data.len) {
        const inst_slice = Instruction.getNext(data[idx..]);
        const op = getOp(inst_slice);

        if (args.print) {
            std.debug.print("getOp bin: {b:0>8}\n", .{inst_slice});
            std.debug.print("parsed op: {?}\n", .{op});
            std.debug.print("getLen: {}\n", .{inst_slice.len});
        }

        const opcode = Instruction.getOpcode(inst_slice);
        const operands = Instruction.getOperands(inst_slice);

        var ops_buf: [32]u8 = undefined;
        const ops = switch (op.?) {
            .ctrl_loop, .ctrl_jmp_conditional => operands[0..1],
            else => operands[0..],
        };

        const ops_str = std.mem.trim(u8, try renderOperands(ops, &ops_buf), "\xaa");

        if (args.print) {
            std.debug.print("parsed:\t{s} {s}\n\n", .{ @tagName(opcode), ops_str });
        }

        _ = try writer.print("{s} {s}\n", .{ @tagName(opcode), ops_str });

        idx += inst_slice.len;
    }
}

fn renderOperands(operands: []const Operand, buf: []u8) ![]u8 {
    var local_buf: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&local_buf);
    const alloc = fba.allocator();

    var list = std.ArrayList([]const u8).init(alloc);
    defer list.deinit();

    for (operands) |op| {
        var op_buf = try alloc.alloc(u8, 32);
        const op_str = switch (op) {
            .addr => |addr| @constCast(try addr.render(op_buf)),
            .imm => |val| op_buf[0..std.fmt.formatIntBuf(op_buf, val, 10, .lower, .{})],
        };

        const trimmed = std.mem.trim(u8, op_str, "\xaa");
        try list.append(trimmed);
    }

    const joined = try std.mem.join(alloc, ", ", list.items);

    std.mem.copyForwards(u8, buf, joined);

    return buf;
}

const OpType = enum {
    // MOVs
    regmem_to_reg,
    imm_to_regmem,
    imm_to_reg,
    mem_to_acc,
    acc_to_mem,
    segreg_to_reg,

    // ADDs ( TODO: arithmetic, actually)
    add_regmem_to_regmem,
    add_imm_to_reg,
    add_imm_from_acc,

    //control
    ctrl_jmp_conditional,
    ctrl_loop,
};

const REGMEM_TO_REG_OP = 0b10001000;
const IMM_TO_REGMEM_OP = 0b11000110;
const IMM_TO_REG_OP = 0b10110000;
const MEM_TO_ACC_OP = 0b10100000;
const SEGREG_TO_REG_OP = 0b10001100;

const ADD_REGMEM_TO_REGMEM_OP = 0b00000000;
const ADD_IMM_TO_REG_OP = 0b10000000;
const ADD_IMM_FROM_ACC_OP = 0b00000100;

const CTRL_LOOP_OP = 0b11100000;
const CTRL_JMP_COND_OP = 0b01110000;

// TODO: probably a better way to look through opcode masks
fn getOp(data: []const u8) ?OpType {
    const op = data[0];

    if (op & CTRL_LOOP_OP == CTRL_LOOP_OP) {
        return .ctrl_loop;
    }

    if (op & CTRL_JMP_COND_OP == CTRL_JMP_COND_OP) {
        return .ctrl_jmp_conditional;
    }

    // NOTE: masking an imm_to_reg op can match the mask for regmem_to_reg, so we check for imm_to_reg first
    if (op & IMM_TO_REG_OP == IMM_TO_REG_OP) {
        return .imm_to_reg;
    }

    if (op & REGMEM_TO_REG_OP == REGMEM_TO_REG_OP) {
        return .regmem_to_reg;
    }

    if (op & IMM_TO_REGMEM_OP == IMM_TO_REGMEM_OP) {
        return .imm_to_regmem;
    }

    if (op & MEM_TO_ACC_OP == MEM_TO_ACC_OP) {
        return .mem_to_acc;
    }

    if (op & SEGREG_TO_REG_OP == SEGREG_TO_REG_OP) {
        return .segreg_to_reg;
    }

    if (op & ADD_IMM_TO_REG_OP == ADD_IMM_TO_REG_OP) {
        return .add_imm_to_reg;
    }

    if (op & ADD_IMM_FROM_ACC_OP == ADD_IMM_FROM_ACC_OP) {
        return .add_imm_from_acc;
    }

    if (op & ADD_REGMEM_TO_REGMEM_OP == ADD_REGMEM_TO_REGMEM_OP) {
        return .add_regmem_to_regmem;
    }

    return null;
}

test "getOp" {
    const reg_to_reg = [_]u8{ 0b10001011, 0b11100100, 0b10101010, 0b10101010 };

    try std.testing.expectEqual(.regmem_to_reg, getOp(&reg_to_reg));

    try std.testing.expectEqual(.add_regmem_to_regmem, getOp(&.{0b00000011}));
}

// to get length of first parsed instruction, we need both mov type (1st byte) and mod value (2nd byte).
fn getLength(data: []const u8) u8 {
    const op_type = getOp(data);

    const mod: u2 = @truncate(data[1] >> 6);
    const rm: u3 = @truncate(data[1]);
    const wide = Instruction.getWideBit(data);

    const sign = bitFlag(data[0] >> 1);

    const direct_address_disp: u8 = if (mod == 0b00 and rm == 0b110) 2 else 0;

    const len: u8 = switch (op_type.?) {
        .regmem_to_reg, .add_regmem_to_regmem => switch (mod) {
            0b11 => 2,
            0b00 => 2,
            0b01 => 3,
            0b10 => 4,
        },
        .imm_to_regmem => switch (mod) {
            0b11 => if (wide) 4 else 3,
            0b00 => if (wide) 4 else 3,
            0b01 => if (wide) 5 else 4,
            0b10 => if (wide) 6 else 5,
        },
        .add_imm_to_reg => switch (mod) {
            0b11 => if ((!sign and wide)) 4 else 3,
            0b00 => if ((!sign and wide)) 4 else 3,
            0b01 => if ((!sign and wide)) 5 else 4,
            0b10 => if ((!sign and wide)) 6 else 5,
        },
        .mem_to_acc, .acc_to_mem => 3,
        .segreg_to_reg => 4,
        .imm_to_reg, .add_imm_from_acc => if (wide) 3 else 2,

        .ctrl_jmp_conditional, .ctrl_loop => 2,
    };

    return len + direct_address_disp;
}

test "getLength" {
    // regmem to reg, no disp
    try std.testing.expectEqual(2, getLength(&.{ 0b10001001, 0b11011110 }));
    // regmem to reg, 8-bit disp
    try std.testing.expectEqual(3, getLength(&.{ 0b10001001, 0b01011110 }));
    // regmem to reg, 16-bit disp
    try std.testing.expectEqual(4, getLength(&.{ 0b10001001, 0b10011110 }));

    // imm to regmem, no disp, 8-bit data
    try std.testing.expectEqual(3, getLength(&.{ 0b11000110, 0b11011110 }));
    // imm to regmem, no disp, 16-bit data
    try std.testing.expectEqual(4, getLength(&.{ 0b11000111, 0b11011110 }));

    // imm to regmem, 8-bit disp, 8-bit data,
    try std.testing.expectEqual(4, getLength(&.{ 0b11000110, 0b01011110 }));
    // imm to regmem, 16-bit disp, 8-bit data
    try std.testing.expectEqual(5, getLength(&.{ 0b11000110, 0b10011110 }));

    // imm to regmem, 8-bit disp, 16-bit data,
    try std.testing.expectEqual(5, getLength(&.{ 0b11000111, 0b01011110 }));
    // imm to regmem, 16-bit disp, 16-bit data
    try std.testing.expectEqual(6, getLength(&.{ 0b11000111, 0b10011110 }));

    // imm to reg
    try std.testing.expectEqual(2, getLength(&.{ 0b10110000, 0b10011110 }));
    try std.testing.expectEqual(3, getLength(&.{ 0b10111000, 0b10011110 }));

    try std.testing.expectEqual(4, getLength(&.{ 0b00000011, 0b10010110 }));

    // arith_imm_to_reg
    try std.testing.expectEqual(3, getLength(&.{ 0b10000011, 0b11111110, 0b00000010 })); // cmp si, 2
    try std.testing.expectEqual(4, getLength(&.{ 0b10000001, 0b11111110, 0b00000010 }));
    // handle direct address
    try std.testing.expectEqual(5, getLength(&.{ 0b10000011, 0b00111110, 0b11100010, 0b00010010 })); // cmp [4834], 29
}

// gets least significant bit of val as boolean
pub fn bitFlag(val: anytype) bool {
    return @bitCast(@as(u1, @truncate(val)));
}

const Instruction = struct {

    // returns slice representing next valid instruction.
    fn getNext(data: []const u8) []const u8 {
        const inst_len = getLength(data);
        return data[0..inst_len];
    }

    // assumes not immediate, which i guess is just always in the same place, lol
    fn getDestinationBit(inst_data: []const u8) bool {
        const op = getOp(inst_data);

        return switch (op.?) {
            .imm_to_reg, .add_imm_to_reg, .add_imm_from_acc => false,
            else => !bitFlag(inst_data[0] >> 1),
        };
    }

    fn getWideBit(inst_data: []const u8) bool {
        const op = getOp(inst_data);

        return switch (op.?) {
            .imm_to_reg => bitFlag(inst_data[0] >> 3),
            else => bitFlag(inst_data[0]),
        };
    }

    fn getWide(data: []const u8, idx: usize) u16 {
        // lets just yank whatevers at the end of the slice if we're exceeding bounds
        const sl = data[@min(idx, data.len - 1)..@min(idx + 2, data.len)];

        // i think we actually want little endian here? seems like vals are ordered lo -> hi
        return switch (sl.len) {
            2 => std.mem.readInt(u16, sl[0..2], .little),
            1 => sl[0],
            0 => 0,
            else => unreachable,
        };
    }

    fn getOpcode(data: []const u8) OpCode {
        const op = getOp(data);
        return switch (op.?) {
            .regmem_to_reg, .imm_to_regmem, .imm_to_reg, .mem_to_acc, .acc_to_mem, .segreg_to_reg => .mov,
            .add_regmem_to_regmem, .add_imm_from_acc => blk: {
                const mini_op: u3 = @truncate(data[0] >> 3);
                break :blk switch (mini_op) {
                    0b000 => .add,
                    0b101 => .sub,
                    0b111 => .cmp,
                    else => unreachable,
                };
            },
            .add_imm_to_reg => blk: {
                const mini_op: u3 = @truncate(data[1] >> 3);
                break :blk switch (mini_op) {
                    0b000 => .add,
                    0b101 => .sub,
                    0b111 => .cmp,
                    else => unreachable,
                };
            },
            .ctrl_jmp_conditional => switch (@as(u4, @truncate(data[0]))) {
                0b0100 => .je,
                0b1100 => .jl,
                0b1110 => .jle,
                0b0010 => .jb,
                0b0110 => .jbe,
                0b1010 => .jp,
                0b0000 => .jo,
                0b1000 => .js,
                0b0101 => .jne,
                0b1101 => .jnl,
                0b1111 => .jnle,
                0b0011 => .jnb,
                0b0111 => .jnbe,
                0b1011 => .jnp,
                0b0001 => .jno,
                0b1001 => .jns,
            },
            .ctrl_loop => switch (@as(u2, @truncate(data[0]))) {
                0b10 => .loop,
                0b01 => .loopz,
                0b00 => .loopnz,
                0b11 => .jczx,
            },
        };
    }

    fn getOperands(inst_data: []const u8) [2]Operand {
        const op = getOp(inst_data);
        const wide = getWideBit(inst_data);

        const mod: u2 = @truncate(inst_data[1] >> 6);
        const reg: u3 = @truncate(inst_data[1] >> 3);
        const rm: u3 = @truncate(inst_data[1]);

        var operands: [2]Operand = switch (op.?) {
            .regmem_to_reg, .add_regmem_to_regmem => blk: {

                // usually starts at 3rd byte if its there
                const disp: u16 = getWide(inst_data, 2);

                const a = getAddress(0b11, reg, wide, disp);
                const b = getAddress(mod, rm, wide, disp);

                break :blk .{
                    .{ .addr = a },
                    .{ .addr = b },
                };
            },
            .imm_to_regmem, .add_imm_to_reg => blk: {
                const disp: u16 = getWide(inst_data, 2);
                const data: u16 = getWide(inst_data, 4);

                const addr: Address = getAddress(mod, rm, wide, disp);

                break :blk .{ .{ .addr = addr }, .{ .imm = data } };
            },
            .imm_to_reg => blk: {
                const data: u16 = if (wide) getWide(inst_data, 1) else inst_data[1];

                break :blk .{
                    .{ .addr = getAddress(0b11, reg, wide, 0) },
                    .{ .imm = data },
                };
            },
            .add_imm_from_acc => blk: {
                const addr: Address = getAddress(0b11, 0b000, wide, 0);
                const data: u16 = getWide(inst_data, 1);

                break :blk .{ .{ .addr = addr }, .{ .imm = data } };
            },

            .ctrl_loop, .ctrl_jmp_conditional => blk: {
                const data: u16 = getWide(inst_data, 1);
                // we toss the second operand
                break :blk .{ .{ .imm = data }, .{ .imm = 0 } };
            },
            else => unreachable,
        };

        if (getDestinationBit(inst_data)) {
            std.mem.swap(Operand, &operands[0], &operands[1]);
        }

        return operands;
    }

    fn getAddress(mod: u2, reg: u3, wide: bool, disp: u16) Address {
        var address: Address = .{};

        // direct address
        if (mod == 0b00 and reg == 0b110) {
            address.indirect = true;
            address.offset = disp;
            return address;
        }

        // handle just register
        if (mod == 0b11) {
            address.reg = getRegister(reg, wide);
            return address;
        }

        // handle regmem, wow this is yucky
        address.indirect = true;
        // TODO: going through each reg value in a big switch case would be clearer
        if (reg == 0b111) {
            address.reg = .bx;
        } else if (reg == 0b110) {
            address.reg = .bp;
        } else {
            if (reg & 0b001 > 0) {
                address.memreg = .di;
            } else {
                address.memreg = .si;
            }

            if (reg & 0b010 > 0) {
                address.reg = .bp;
            } else {
                address.reg = .bx;
            }

            // toss B register in this case
            if (reg & 0b100 > 0) {
                address.reg = null;
            }
        }

        address.offset = switch (mod) {
            0b11, 0b00 => 0,
            0b01 => @as(u8, @truncate(disp)),
            0b10 => disp,
        };

        return address;
    }

    fn getRegister(reg: u3, wide: bool) Register {
        const high: bool = reg & 0b100 > 0;

        // packed struct fields are in reverse order, thats wild
        const Options = packed struct(u2) { wide: bool, high: bool };
        const opts: u2 = @bitCast(Options{ .wide = wide, .high = high });

        return switch (@as(u2, @truncate(reg))) {
            0b00 => switch (opts) { // high, wide
                0b11 => .sp,
                0b01 => .ax,
                0b10 => .ah,
                0b00 => .al,
            },
            0b01 => switch (opts) {
                0b11 => .bp,
                0b01 => .cx,
                0b10 => .ch,
                0b00 => .cl,
            },
            0b10 => switch (opts) {
                0b11 => .si,
                0b01 => .dx,
                0b10 => .dh,
                0b00 => .dl,
            },
            0b11 => switch (opts) {
                0b11 => .di,
                0b01 => .bx,
                0b10 => .bh,
                0b00 => .bl,
            },
        };
    }
};

const Address = struct {
    reg: ?Register = null, // no register == immediate address
    memreg: ?Register = null, // for SI, DI. Probably not the right name
    offset: u16 = 0, // DISP
    offset_wide: bool = false, // 8bits if false, 16 if true
    indirect: bool = false, // indicates the address is stored as a value

    pub fn render(a: Address, buf: []u8) ![]const u8 {
        var local_buf: [256]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&local_buf);
        const alloc = fba.allocator();

        var list = std.ArrayList([]const u8).init(alloc);
        defer list.deinit();

        // max rendered val will be 65536
        var offset_buf: [5]u8 = undefined;
        _ = std.fmt.formatIntBuf(&offset_buf, a.offset, 10, .lower, .{});
        const offset_slice = std.mem.trim(u8, &offset_buf, "\xaa");

        const elems = [_][]const u8{
            if (a.reg != null) @tagName(a.reg.?) else "",
            if (a.memreg != null) @tagName(a.memreg.?) else "",
            if (a.offset > 0) offset_slice else "",
        };

        for (elems) |item| {
            if (item.len > 0) {
                try list.append(item);
            }
        }

        const elems_str = try std.mem.join(alloc, " + ", list.items);

        const maybe_left_br = if (a.indirect) "[" else "";
        const maybe_right_br = if (a.indirect) "]" else "";
        return try std.fmt.bufPrint(buf, "{s}{s}{s}", .{ maybe_left_br, elems_str, maybe_right_br });
    }
};

const Operand = union(enum) { addr: Address, imm: u16 };

pub const OpCode = enum {
    mov,
    add,
    adc,
    sub,
    cmp,
    je,
    jl,
    jle,
    jb,
    jbe,
    jp,
    jo,
    js,
    jne,
    jnl,
    jnle,
    jnb,
    jnbe,
    jnp,
    jno,
    jns,
    loop,
    loopz,
    loopnz,
    jczx,
};

// memory address: number and/or Register
pub const Register = enum {
    al,
    bl,
    cl,
    dl,
    ah,
    bh,
    ch,
    dh,
    ax,
    bx,
    cx,
    dx,
    sp,
    bp,
    si,
    di,
};

const Args = struct { print: bool = false };
fn compareToNasm(alloc: std.mem.Allocator, comptime listing: []const u8, args: Args) !void {
    const listing_path = "../computer_enhance/perfaware/part1";

    // assemble to local listing file
    const nasm_args = [_][]const u8{ "nasm", listing_path ++ "/" ++ listing ++ ".asm", "-o", listing };
    var child = std.process.Child.init(&nasm_args, alloc);

    _ = try child.spawnAndWait();
    // errdefer std.fs.cwd().deleteFile(listing) catch unreachable;
    defer std.fs.cwd().deleteFile(listing) catch unreachable;

    // get binary data
    var binary_data_buf: [4096]u8 = undefined;
    const binary_data = try std.fs.cwd().readFile(listing, &binary_data_buf);

    var output_buf: [4096]u8 = undefined;
    var output_stream = std.io.fixedBufferStream(&output_buf);

    try parse(output_stream.writer(), binary_data, args);

    var output_file = try std.fs.cwd().createFile(listing ++ "_ours" ++ ".asm", .{});
    // errdefer std.fs.cwd().deleteFile(listing ++ "_ours" ++ ".asm") catch {};
    defer std.fs.cwd().deleteFile(listing ++ "_ours" ++ ".asm") catch {};

    if (args.print) {
        std.debug.print("Output ASM:\n{s}\n", .{output_stream.getWritten()});
    }

    _ = try output_file.writeAll(output_stream.getWritten());

    // assemble our file
    const our_nasm_args = [_][]const u8{ "nasm", listing ++ "_ours" ++ ".asm", "-o", listing ++ "_ours" };
    child = std.process.Child.init(&our_nasm_args, alloc);

    _ = try child.spawnAndWait();
    // errdefer std.fs.cwd().deleteFile(listing ++ "_ours") catch {};
    defer std.fs.cwd().deleteFile(listing ++ "_ours") catch {};

    // get binary data
    var our_data_buf: [1024]u8 = undefined;
    const our_data = try std.fs.cwd().readFile(listing ++ "_ours", &our_data_buf);

    if (args.print) {
        std.debug.print("LISTING: {s}\n", .{listing});
        std.debug.print("Their binary:\n{b}\n", .{binary_data});
        std.debug.print("Our binary:\n{b}\n", .{our_data});
    }
    try std.testing.expectEqualSlices(u8, binary_data, our_data);
}

test "listing_0037" {
    const alloc = std.testing.allocator_instance.allocator();
    const listing = "listing_0037_single_register_mov";

    try compareToNasm(alloc, listing, .{});
}

test "listing_0038" {
    const alloc = std.testing.allocator_instance.allocator();
    const listing = "listing_0038_many_register_mov";

    try compareToNasm(alloc, listing, .{});
}

test "listing_0039" {
    const alloc = std.testing.allocator_instance.allocator();
    const listing = "listing_0039_more_movs";

    try compareToNasm(alloc, listing, .{});
}

// NOTE: not gonna do this
test "listing_0040" {
    const alloc = std.testing.allocator_instance.allocator();
    const listing = "listing_0040_challenge_movs";

    try compareToNasm(alloc, listing, .{ .print = true });
}

// NOTE: jump labels will bork this, likely
test "listing_0041" {
    const alloc = std.testing.allocator_instance.allocator();
    const listing = "listing_0041_add_sub_cmp_jnz";

    try compareToNasm(alloc, listing, .{ .print = true });
}
