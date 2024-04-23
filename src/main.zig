const std = @import("std");

pub fn main() !void {
    var file_buf: [1024]u8 = undefined;
    const data = try std.fs.cwd().readFile("../computer_enhance/perfaware/part1/listing_0037_single_register_mov", &file_buf);

    const out_writer = std.io.getStdOut().writer();

    // [][][][][][]|[]|[]||[][]|[][][]|[][][]
    //    opcode    D  W   MOD   REG    R/M

    parse(out_writer, data);
}

fn parse(writer: anytype, data: []const u8) !void {
    var idx: usize = 0;
    while (idx < data.len - 1) : (idx += 2) {
        const slice = data[idx .. idx + 2];
        std.debug.print("raw bytes, index {}:\t{any}\n", .{ idx, slice });

        const inst: Instruction = @bitCast(std.mem.readInt(u16, slice[0..2], .big));
        const ops = inst.getOperands();

        _ = try writer.print("{s} {s}, {s}\n", .{ @tagName(inst.getOpCode()), @tagName(ops[0]), @tagName(ops[1]) });
    }
}

// packed struct fields are in reverse order, thats wild
const Instruction = packed struct(u16) {
    rm: u3,
    reg: u3,
    mod: u2,
    // is our data transfer 16 bits?
    // = false: 1 byte, true: 2 bytes (word, wide)
    w: bool,
    // is the destination to or from the register field?
    // = false: REG field is destination (dest, source)
    // = true: REG field is source (source, dest)
    d: bool,
    op: u6,

    fn getOpCode(i: Instruction) OpCode {
        return switch (i.op) {
            0b100010 => .mov,
            else => unreachable,
        };
    }

    fn getOperands(i: Instruction) [2]Register {
        std.debug.print("getOperands instruction:\t{}\n", .{i});
        if (i.mod != 0b11) {
            // uh oh, only supporting register mode for now
            unreachable;
        }

        if (i.d) {
            return .{ getRegister(i.reg, i.w), getRegister(i.rm, i.w) };
        }

        return .{ getRegister(i.rm, i.w), getRegister(i.reg, i.w) };
    }
};

fn getRegister(reg: u8, wide: bool) Register {
    const val: u2 = @truncate(reg & 0b11);
    const high: bool = reg & 0b100 > 0;

    const Options = packed struct(u2) { wide: bool, high: bool };

    const opts: u2 = @bitCast(Options{ .wide = wide, .high = high });

    return switch (val) {
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
    _ = try output_file.writeAll(output_stream.getWritten());

    defer std.fs.cwd().deleteFile(listing ++ "_ours" ++ ".asm") catch unreachable;

    // assemble our file
    const our_nasm_args = [_][]const u8{ "nasm", listing ++ "_ours" ++ ".asm", "-o", listing ++ "_ours" };
    child = std.process.Child.init(&our_nasm_args, alloc);

    _ = try child.spawnAndWait();
    defer std.fs.cwd().deleteFile(listing ++ "_ours") catch unreachable;

    // get binary data
    var our_data_buf: [1024]u8 = undefined;
    const our_data = try std.fs.cwd().readFile(listing ++ "_ours", &our_data_buf);

    if (args.print.?) {
        std.debug.print("LISTING: {s}\n", .{listing});
        std.debug.print("Their binary:\n{x}\n", .{binary_data});
        std.debug.print("Our binary:\n{x}\n", .{our_data});
    }
    try std.testing.expectEqualSlices(u8, binary_data, our_data);

    errdefer std.fs.cwd().deleteFile(listing ++ "_ours" ++ ".asm") catch {};
    errdefer std.fs.cwd().deleteFile(listing ++ "_ours") catch {};
    errdefer std.fs.cwd().deleteFile(listing) catch {};
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

test "listing_0039" {}
