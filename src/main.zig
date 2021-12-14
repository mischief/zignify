const std = @import("std");
const sha256 = std.crypto.hash.sha2.Sha256;
const sha512 = std.crypto.hash.sha2.Sha512;
const ed = std.crypto.sign.Ed25519;
const base64 = std.base64.standard;
const Allocator = std.mem.Allocator;
const bcrypt = std.crypto.pwhash.bcrypt;

const bcrypt_pbkdf = @cImport({
    @cDefine("_GNU_SOURCE", {});
    @cInclude("src/bcrypt_pbkdf.h");
});

const CommentHeader = "untrusted comment: ";
const VerifyWith = "verify with ";

const InputError = error{
    NoPassword,
    BadPassword,
};

const SignatureError = error{
    MalformedSignature,
    MismatchedKeys,
    InvalidSecretKDF,
    KeyTooBig,
};

const CryptoError = error{
    BcryptError,
};

const Sum = struct {
    name: []const u8,
    sum: [sha256.digest_length]u8,
};

const Sec = struct {
    pub const salt_length = 16;

    comment: [1024]u8,
    commentlen: usize,
    pkalg: [2]u8,
    kdfrounds: u32,
    salt: [salt_length]u8,
    checksum: [8]u8,
    keynum: [8]u8,
    seckey: [ed.secret_length]u8,
    kp: ed.KeyPair,

    fn init(reader: anytype, pass: []const u8) !Sec {
        var s: Sec = undefined;

        var chk: [2 + 4 + 16 + 8 + 8 + ed.secret_length]u8 = undefined;

        _ = try readFile(reader, &s.pkalg, chk.len, &chk, null);

        if (!std.mem.eql(u8, chk[0..2], "BK")) {
            return SignatureError.InvalidSecretKDF;
        }

        var be = std.mem.bytesAsValue(u32, chk[2..6]);
        s.kdfrounds = std.mem.bigToNative(u32, be.*);

        std.mem.copy(u8, &s.salt, chk[6..22]);
        std.mem.copy(u8, &s.checksum, chk[22..30]);
        std.mem.copy(u8, &s.keynum, chk[30..38]);
        std.mem.copy(u8, &s.seckey, chk[38 .. 38 + ed.secret_length]);

        var zork: [ed.secret_length]u8 = undefined;

        try kdf(pass, s.salt[0..], s.kdfrounds, zork[0..]);

        for (s.seckey) |_, i| {
            s.seckey[i] = s.seckey[i] ^ zork[i];
        }

        var hash: [sha512.digest_length]u8 = undefined;
        sha512.hash(s.seckey[0..], &hash, .{});

        if (!std.mem.eql(u8, s.checksum[0..8], hash[0..8])) {
            return InputError.BadPassword;
        }

        s.kp = ed.KeyPair.fromSecretKey(s.seckey);

        return s;
    }
};

test "test sec init" {
    var r = std.io.fixedBufferStream(test_sec).reader();
    _ = try Sec.init(r, "hacker");
}

const Sig = struct {
    comment: [1024]u8 = undefined,
    commentlen: usize = undefined,
    pkalg: [2]u8 = undefined,
    keynum: [8]u8 = undefined,
    sig: [ed.signature_length]u8 = undefined,

    blob: [32 * 1024]u8 = undefined,
    bloblen: usize = 0,

    fn init(reader: anytype) !Sig {
        var s: Sig = undefined;

        var chk: [8 + ed.signature_length]u8 = undefined;

        s.bloblen = try readFile(reader, &s.pkalg, chk.len, &chk, s.blob[0..]);

        std.mem.copy(u8, &s.keynum, chk[0..8]);
        std.mem.copy(u8, &s.sig, chk[8..]);

        return s;
    }

    fn create(comment: []const u8, keynum: [8]u8, sig: [ed.signature_length]u8, blob: ?[]const u8) Sig {
        var s: Sig = undefined;

        std.mem.copy(u8, s.comment[0..], comment);
        s.commentlen = comment.len;
        std.mem.copy(u8, s.pkalg[0..], "Ed");

        s.keynum = keynum;
        s.sig = sig;

        if (blob) |b| {
            std.mem.copy(u8, s.blob[0..], b);
            s.bloblen = b.len;
        }

        return s;
    }

    fn dump(self: *Sig, allocator: std.mem.Allocator, wr: anytype) !void {
        try wr.print("{s}{s}\n", .{ CommentHeader, self.comment[0..self.commentlen] });
        var concat = try std.mem.concat(allocator, u8, &[_][]u8{ &self.pkalg, &self.keynum, &self.sig });
        defer allocator.free(concat);

        const encblock = try allocator.alloc(u8, base64.Encoder.calcSize(concat.len));
        defer allocator.free(encblock);
        const encoded = base64.Encoder.encode(encblock, concat);
        try wr.print("{s}\n", .{encoded});
        try wr.writeAll(self.blob[0..self.bloblen]);
    }
};

const Pub = struct {
    pkalg: [2]u8,
    keynum: [8]u8,
    public_key: [ed.public_length]u8,

    fn init(reader: anytype) !Pub {
        var p: Pub = undefined;
        var chk: [8 + ed.public_length]u8 = undefined;

        _ = try readFile(reader, &p.pkalg, chk.len, &chk, null);

        std.mem.copy(u8, &p.keynum, chk[0..8]);
        std.mem.copy(u8, &p.public_key, chk[8..]);

        return p;
    }
};

fn readFile(
    reader: anytype,
    pkalg: *[2]u8,
    comptime edlen: usize,
    eddata: *[edlen]u8,
    blob: ?[]u8,
) !usize {
    var buf_reader = std.io.bufferedReader(reader);
    var in_stream = buf_reader.reader();

    var buf: [1024]u8 = undefined;

    var maybecom = try in_stream.readUntilDelimiterOrEof(&buf, '\n');
    var com = maybecom orelse return SignatureError.MalformedSignature;

    if (!std.mem.startsWith(u8, com, CommentHeader)) {
        return SignatureError.MalformedSignature;
    }

    //std.mem.copy(u8, sig.comment[0..], com[CommentHeader.len..]);
    //sig.commentlen = com.len - CommentHeader.len;

    var maybeb64 = try in_stream.readUntilDelimiterOrEof(&buf, '\n');
    var b64 = maybeb64 orelse return SignatureError.MalformedSignature;

    var b64dec: [104]u8 = undefined;

    var decsz = try base64.Decoder.calcSizeForSlice(b64[0..]);

    if (decsz > b64dec.len) {
        return SignatureError.KeyTooBig;
    }

    try base64.Decoder.decode(b64dec[0..], b64[0..]);

    if (!std.mem.startsWith(u8, b64dec[0..2], "Ed")) {
        return SignatureError.MalformedSignature;
    }

    std.mem.copy(u8, pkalg[0..], b64dec[0..2]);
    std.mem.copy(u8, eddata, b64dec[2..decsz]);

    var rv: usize = 0;

    if (blob) |b| {
        rv = try in_stream.readAll(b);
    }

    return rv;
}

fn getpass(prompt: []const u8, oput: []u8) ![]u8 {
    const stdin = std.io.getStdIn();
    const handle = stdin.handle;

    var ot: std.os.linux.termios = undefined;

    switch (std.os.errno(std.os.linux.tcgetattr(handle, &ot))) {
        .SUCCESS => {},
        else => |err| return std.os.unexpectedErrno(err),
    }

    var nt = ot;
    nt.lflag &= ~std.os.linux.ECHO;

    switch (std.os.errno(std.os.linux.tcsetattr(handle, std.os.linux.TCSA.FLUSH, &nt))) {
        .SUCCESS => {},
        else => |err| return std.os.unexpectedErrno(err),
    }

    defer {
        switch (std.os.errno(std.os.linux.tcsetattr(handle, std.os.linux.TCSA.FLUSH, &ot))) {
            .SUCCESS => {},
            else => |err| std.debug.print("Terminal restoration failed: {}\n", .{err}),
        }
    }

    //try std.os.tcsetattr(handle, std.os.TCSA.FLUSH, newterm);

    std.debug.print("{s}", .{prompt});

    const reader = stdin.reader();

    defer std.debug.print("\n", .{});

    return (try reader.readUntilDelimiterOrEof(oput, '\n')) orelse return InputError.NoPassword;
}

fn kdf(pass: []const u8, salt: []const u8, rounds: c_uint, key: []u8) !void {
    if (rounds == 0) {
        std.mem.set(u8, key, 0);
        return;
    }

    // correct
    if (bcrypt_pbkdf.bcrypt_pbkdf(pass.ptr, pass.len, salt.ptr, salt.len, key.ptr, key.len, rounds) != 0) {
        return CryptoError.BcryptError;
    }

    std.debug.print("C  : {s}\n", .{std.fmt.fmtSliceHexLower(key)});

    var alsokey: [ed.secret_length]u8 = undefined;
    try bcrypt.pbkdf(pass, salt, alsokey[0..], rounds);

    std.debug.print("Zig: {s}\n", .{std.fmt.fmtSliceHexLower(alsokey[0..])});

    if (!std.mem.eql(u8, key, alsokey[0..])) {
        return CryptoError.BcryptError;
    }
}

fn verify(pkf: []const u8, sigf: []const u8) !void {
    var pk = try std.fs.cwd().openFile(pkf, .{});
    defer pk.close();

    var s = try std.fs.cwd().openFile(sigf, .{});
    defer s.close();

    var pkey = try Pub.init(pk.reader());
    var sig = try Sig.init(s.reader());

    if (!std.mem.eql(u8, pkey.keynum[0..], sig.keynum[0..])) {
        return SignatureError.MismatchedKeys;
    }

    try ed.verify(sig.sig, sig.blob[0..sig.bloblen], pkey.public_key);

    std.debug.print("Signature Verified\n", .{});
}

fn writeOut(path: []const u8, comm: []const u8, blob: []const u8) !void {
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();

    try file.writeAll(CommentHeader);
    try file.writeAll(comm);
    try file.writeAll("\n");
    try file.writeAll(blob);
    try file.writeAll("\n");
}

fn generate(pubf: []const u8, secf: []const u8, rounds: c_uint) !void {
    // create
    const kp = try ed.KeyPair.create(null);

    var hash: [sha256.digest_length]u8 = undefined;
    sha256.hash(kp.secret_key[0..], &hash, .{});

    var salt: [Sec.salt_length]u8 = undefined;
    std.crypto.random.bytes(&salt);

    const passwd = "hacker";

    var zork: [ed.secret_length]u8 = undefined;

    if (bcrypt_pbkdf.bcrypt_pbkdf(passwd, passwd.len, &salt, salt.len, &zork, zork.len, rounds) != 0) {
        std.debug.print("it broken\n", .{});
        return CryptoError.BcryptError;
    }

    //const zork = std.crypto.pwhash.bcrypt.bcrypt(passwd, salt, .{ .rounds_log = rounds });

    var zorred: [kp.secret_key.len]u8 = undefined;

    for (kp.secret_key) |_, i| {
        zorred[i] = kp.secret_key[i] ^ zork[i];
    }

    // binary blocks
    var pubbin: [2 + 8 + ed.public_length]u8 = undefined;
    var secbin: [2 + 8 + ed.secret_length]u8 = undefined;

    // random keyid
    var keyid: [8]u8 = undefined;
    std.crypto.random.bytes(&keyid);

    // public key binary
    std.mem.copy(u8, pubbin[0..2], "Ed");
    std.mem.copy(u8, pubbin[2..10], keyid[0..]);
    std.mem.copy(u8, pubbin[10 .. 10 + ed.public_length], kp.public_key[0..]);

    // private key binary
    std.mem.copy(u8, secbin[0..2], "Ed");
    std.mem.copy(u8, secbin[2..10], keyid[0..]);
    std.mem.copy(u8, secbin[10 .. 10 + ed.secret_length], kp.secret_key[0..]);

    var pubblock: [1024]u8 = undefined;
    var secblock: [1024]u8 = undefined;

    const pubenc = base64.Encoder.encode(pubblock[0..], pubbin[0..]);
    const secenc = base64.Encoder.encode(secblock[0..], secbin[0..]);

    std.debug.print("Pub {s}\n", .{pubenc});
    std.debug.print("Sec {s}\n", .{secenc});

    try writeOut(pubf, pubf, pubenc);
    try writeOut(secf, secf, secenc);
}

fn sign(allocator: std.mem.Allocator, secf: []const u8, msgf: []const u8, msgsigf: []const u8) !void {
    var passBuf: [1024]u8 = undefined;
    var pwSlice = try getpass("passphrase: ", passBuf[0..]);

    var secr = try std.fs.cwd().openFile(secf, .{});
    defer secr.close();

    var sec = try Sec.init(secr.reader(), pwSlice);

    var msg = try std.fs.cwd().openFile(msgf, .{});
    defer msg.close();

    var msgbytes = try msg.readToEndAlloc(allocator, 8192);
    defer allocator.free(msgbytes);

    var signature = try ed.sign(msgbytes, sec.kp, null);

    var file = try std.fs.cwd().createFile(msgsigf, .{});
    defer file.close();

    var writer = file.writer();

    var buf: [1024]u8 = undefined;
    const comm = try std.fmt.bufPrint(buf[0..], "{s}{s}", .{ VerifyWith, secf });

    var sig = Sig.create(comm, sec.keynum, signature, msgbytes);

    try sig.dump(allocator, writer);
}

fn usage(err: ?anyerror) noreturn {
    if (err) |e| {
        std.debug.print("Error: {}\n\n", .{e});
    }
    std.debug.print("Usage:\n", .{});
    std.debug.print("\tzignify verify key.pub msg.sig\n", .{});
    std.debug.print("\tzignify generate key.pub key.sec\n", .{});
    std.debug.print("\tzignify sign key.sec msg msg.sig\n", .{});
    std.process.exit(1);
}

fn hashU() void {
    var file = try std.fs.cwd().openFile("foo.txt", .{});
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    var in_stream = buf_reader.reader();

    var hash = sha256.init(.{});

    var buf: [1024]u8 = undefined;
    while (try in_stream.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        hash.update(line[0..]);
    }

    var sum: [sha256.digest_length]u8 = undefined;

    hash.final(&sum);

    std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(sum[0..])});
}

pub fn main() anyerror!void {
    const allocator = std.heap.page_allocator;

    var iter = std.process.args();

    // skip prog name;
    _ = iter.next(allocator);

    const cmd = iter.next(allocator) orelse usage(null) catch |err| usage(err);

    if (std.mem.eql(u8, cmd, "verify")) {
        const pkf = iter.next(allocator) orelse usage(null) catch |err| usage(err);
        const sigf = iter.next(allocator) orelse usage(null) catch |err| usage(err);
        verify(pkf, sigf) catch |err| usage(err);
    } else if (std.mem.eql(u8, cmd, "generate")) {
        const pubf = iter.next(allocator) orelse usage(null) catch |err| usage(err);
        const secf = iter.next(allocator) orelse usage(null) catch |err| usage(err);
        generate(pubf, secf, 42) catch |err| usage(err);
    } else if (std.mem.eql(u8, cmd, "sign")) {
        const secf = iter.next(allocator) orelse usage(null) catch |err| usage(err);
        const msgf = iter.next(allocator) orelse usage(null) catch |err| usage(err);
        const msgsigf = iter.next(allocator) orelse usage(null) catch |err| usage(err);
        sign(allocator, secf, msgf, msgsigf) catch |err| usage(err);
    } else {
        usage(null);
    }

    //std.debug.print("Comment: {s}\n", .{sig.comment[0..sig.commentlen]});
    //std.debug.print("PK: {s} Keynum: {s} Sig: {s}\n", .{ sig.pkalg, std.fmt.fmtSliceHexLower(sig.keynum[0..]), std.fmt.fmtSliceHexLower(sig.sig[0..]) });
    //std.debug.print("Siglen: {}\n", .{sig.sig.len});
}

const test_sec =
    \\untrusted comment: my key secret key
    \\RWRCSwAAACqfu2YlqBjoIHG2rVfQwdhFviGGNZGNhYW1XuViVcdNfZ9YtAp1pioWzjBTdbjeOfYeKhVbYke0oywmOfSpY7l8m+trPpjiIZ/HGOzRpfBWGKNPDV9bgHHqu2MfY42r7NM=
;

const test_sigblob =
    \\untrusted comment: verify with mykey.pub
    \\RWS1XuViVcdNfXOisHoOQ0ZOWJfMlud5hv1+ruxHl6LhlSwyTPqQJelRjf7dM4d9r3cT8880unucKdzZKWV3RMSA/ZBGbiKotwQ=
    \\SHA256 (foo.txt) = 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7a
;

const test_pubkey =
    \\untrusted comment: my key public key
    \\RWS1XuViVcdNfVpOzrfeTcs6bSMfAi2nwi97x8hg2j7kogNJht4uTQLk
;

test "parse sig" {}
