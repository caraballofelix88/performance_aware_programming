const std = @import("std");

pub fn main() !void {
    var file_buf: [1024]u8 = undefined;
    const data = try std.fs.cwd().readFile("../computer_enhance/perfaware/part1/listing_0037_single_register_mov", &file_buf);
    const out_writer = std.io.getStdOut().writer();

    parse(out_writer, data);
}

fn parse(writer: anytype, data: []const u8) !void {
    var idx: usize = 0;
    while (idx < data.len) {
        const inst_slice = Instruction.getNext(data[idx..]);

        const opcode = Instruction.getOpcode(getOp(inst_slice).?);
        const operands = Instruction.getOperands(inst_slice);

        // TODO: handle printing operand
        _ = try writer.print("{s} {s}, {s}\n", .{
            @tagName(opcode),
            @tagName(operands[0].addr.reg.?),
            @tagName(operands[1].addr.reg.?),
        });

        idx += inst_slice.len;
    }
}

const OpType = enum {
    // MOVs
    regmem_to_reg,
    imm_to_regmem,
    imm_to_reg,
    mem_to_acc,
    acc_to_mem,
    segreg_to_reg,
};

fn getOp(data: []const u8) ?OpType {
    const op = data[0];

    const REGMEM_TO_REG_OP = 0b10001000;
    const IMM_TO_REGMEM_OP = 0b11000110;
    const IMM_TO_REG_OP = 0b11010000;
    const MEM_TO_ACC_OP = 0b10100000;
    const SEGREG_TO_REG_OP = 0b10001100;

    if (op & REGMEM_TO_REG_OP == REGMEM_TO_REG_OP) {
        return .regmem_to_reg;
    }

    if (op & IMM_TO_REGMEM_OP == IMM_TO_REGMEM_OP) {
        return .imm_to_regmem;
    }

    if (op & IMM_TO_REG_OP == IMM_TO_REG_OP) {
        return .imm_to_reg;
    }

    if (op & MEM_TO_ACC_OP == MEM_TO_ACC_OP) {
        return .mem_to_acc;
    }

    if (op & SEGREG_TO_REG_OP == SEGREG_TO_REG_OP) {
        return .segreg_to_reg;
    }

    return null;
}

test "getOp" {
    const reg_to_reg = [_]u8{ 0b10001011, 0b11100100, 0b10101010, 0b10101010 };

    try std.testing.expectEqual(.regmem_to_reg, getOp(&reg_to_reg));
}

// to get length of first parsed instruction, we need both mov type (1st byte) and mod value (2nd byte).
fn getLength(data: []const u8) u8 {
    const mov_type = getOp(data);

    const mod: u2 = @truncate(data[1] >> 6);
    const wide: bool = @as(u1, @truncate(data[0])) == 1;

    return switch (mov_type.?) {
        .regmem_to_reg => switch (mod) {
            0b11 => 2,
            0b00 => 2,
            0b01 => 3,
            0b10 => 4,
        },
        .imm_to_regmem => if (wide) 3 else 2,
        .mem_to_acc => 2,
        .segreg_to_reg => 4,
        else => unreachable, // TODO: unreachables should be errors.
    };
}

// TODO: do we really need an object for this? revise later
const Instruction = struct {

    // returns slice representing next valid instruction.
    fn getNext(data: []const u8) []const u8 {
        const inst_len = getLength(data);
        return data[0..inst_len];
    }

    // assumes not immediate, which i guess is just always in the same place, lol
    fn getDestinationBit(inst_data: []const u8) bool {
        return @as(u1, @truncate(inst_data[0] >> 1)) == 1;
    }

    fn getWideBit(inst_data: []const u8) bool {
        const op = getOp(inst_data);

        return switch (op) {
            .imm_to_reg => @as(u1, @truncate(inst_data[0] >> 3)) == 1,
            else => @truncate(inst_data[0]),
        };
    }

    // returns value of least significant bit
    fn boolFromBit(data: u8) bool {
        return data & 0b1 > 0;
    }

    fn getWide(data: []const u8, idx: usize) u16 {
        // lets just truncate the slice if we don't have space
        const sl = data[idx..@min(idx + 2, data.len)];
        // i think we actually want little endian here? seems like vals are ordered lo -> hi

        return switch (sl.len) {
            2 => std.mem.readInt(u16, sl[0..2], .little),
            1 => sl[0],
            0 => 0,
            else => unreachable, // TODO: again with the dang unreachables
        };
    }

    fn getOpcode(op: OpType) OpCode {
        return switch (op) {
            .regmem_to_reg, .imm_to_regmem, .imm_to_reg, .mem_to_acc, .acc_to_mem, .segreg_to_reg => .mov,
        };
    }

    fn getOperands(inst_data: []const u8) [2]Operand {
        const op = getOp(inst_data);
        var operands: [2]Operand = undefined;

        if (op == .regmem_to_reg) {
            const mod: u2 = @truncate(inst_data[1] >> 6);
            const wide: bool = boolFromBit(inst_data[0]);

            const reg: u3 = @truncate(inst_data[1] >> 3);
            const rm: u3 = @truncate(inst_data[1]);

            // usually starts at 3rd byte if its there
            const disp: u16 = getWide(inst_data, 2);

            const a = getAddress(mod, reg, wide, disp);
            const b = getAddress(mod, rm, wide, disp);

            operands = .{
                .{ .addr = a },
                .{ .addr = b },
            };
        } else if (op == .imm_to_regmem) {
            const mod: u2 = @truncate(inst_data[1] >> 6);
            const wide: bool = boolFromBit(inst_data[0]);
            const rm: u3 = @truncate(inst_data[1]);

            const disp: u16 = getWide(inst_data, 2);
            const data: u16 = getWide(inst_data, 4);

            const addr: Address = getAddress(mod, rm, wide, disp);

            operands = .{ .{ .addr = addr }, .{ .imm = data } };
        }

        // TODO: this doesnt hold for certain ops.
        if (!getDestinationBit(inst_data)) {
            const swap = operands[0];
            operands[0] = operands[1];
            operands[1] = swap;
        }

        return operands;
    }

    // pass in displacement value even if it goes unused
    fn getAddress(mod: u2, reg: u3, wide: bool, disp: u16) Address {
        var address: Address = .{};

        // handle direct address
        if (mod == 0b00 and reg == 0b110) {
            address.offset = 0;
            return address; // lol i dont know what goes here actually
        }

        // handle just register
        if (mod == 0b11) {
            address.reg = getRegister(reg, wide);
            return address;
        }

        // handle regmem, wow this is yucky
        if (reg == 0b111) {
            address.reg = .bx;
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

    fn getMemReg() Address {}

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
    reg: ?Register = null, // no register == immediate addresso
    memreg: ?Register = null, // for SI, DI. Probably not the right name
    offset: u16 = 0, // DISP
};

const Operand = union(enum) { addr: Address, imm: u16 };

pub const OpCode = enum {
    mov,
};

// memory address: number andor Register
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

const Args = struct { print: ?bool = false };
fn compareToNasm(alloc: std.mem.Allocator, comptime listing: []const u8, args: Args) !void {
    const listing_path = "../computer_enhance/perfaware/part1";

    // assemble to local listing file
    const nasm_args = [_][]const u8{ "nasm", listing_path ++ "/" ++ listing ++ ".asm", "-o", listing };
    var child = std.process.Child.init(&nasm_args, alloc);

    _ = try child.spawnAndWait();
    defer std.fs.cwd().deleteFile(listing) catch unreachable;

    // get binary data
    var binary_data_buf: [1024]u8 = undefined;
    const binary_data = try std.fs.cwd().readFile(listing, &binary_data_buf);

    var output_buf: [1024]u8 = undefined;
    var output_stream = std.io.fixedBufferStream(&output_buf);

    try parse(output_stream.writer(), binary_data);

    var output_file = try std.fs.cwd().createFile(listing ++ "_ours" ++ ".asm", .{});
    std.debug.print("Output ASM:\n{s}\n", .{output_stream.getWritten()});
    _ = try output_file.writeAll(output_stream.getWritten());

    defer std.fs.cwd().deleteFile(listing ++ "_ours" ++ ".asm") catch {};

    // assemble our file
    const our_nasm_args = [_][]const u8{ "nasm", listing ++ "_ours" ++ ".asm", "-o", listing ++ "_ours" };
    child = std.process.Child.init(&our_nasm_args, alloc);

    _ = try child.spawnAndWait();
    defer std.fs.cwd().deleteFile(listing ++ "_ours") catch {};

    // get binary data
    var our_data_buf: [1024]u8 = undefined;
    const our_data = try std.fs.cwd().readFile(listing ++ "_ours", &our_data_buf);

    if (args.print.?) {
        std.debug.print("LISTING: {s}\n", .{listing});
        std.debug.print("Their binary:\n{b}\n", .{binary_data});
        std.debug.print("Our binary:\n{b}\n", .{our_data});
    }
    try std.testing.expectEqualSlices(u8, binary_data, our_data);

    errdefer std.fs.cwd().deleteFile(listing ++ "_ours" ++ ".asm") catch {};
    errdefer std.fs.cwd().deleteFile(listing ++ "_ours") catch {};
    errdefer std.fs.cwd().deleteFile(listing) catch {};
}

test "listing_0037" {
    const alloc = std.testing.allocator_instance.allocator();
    const listing = "listing_0037_single_register_mov";

    try compareToNasm(alloc, listing, .{ .print = true });
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
