-- live_leaf.lua <stellaris.exe> <module.lua> [fnmatch ffi.lua]: calls a few pure leaf functions of
-- the game through generated declarations, in an image this script maps itself (Windows x64,
-- LuaJIT). Nothing of the game runs but these functions: the image is copied into memory and
-- relocated; imports are not resolved, no entry point or TLS callback runs, and every function
-- called makes no call itself (checked in the call graph beforehand).
--
-- What it checks: float results (XMM0), a static function's hidden result pointer (first), an
-- instance method's hidden result pointer (after this), const references, a void method that
-- writes its object. Results are checked against identities, not against the PDB.

local exe_path, module_path, ffi_lua = ...
local ffi = require("ffi")
assert(ffi.os == "Windows" and ffi.arch == "x64", "Windows x64 only")
local fnffi = dofile(ffi_lua or "ffi.lua")
local b = assert(fnffi.load(module_path))

ffi.cdef([[
void *VirtualAlloc(void *address, size_t size, uint32_t type, uint32_t protect);
int VirtualFree(void *address, size_t size, uint32_t type);
]])

-- map the image
local f = assert(io.open(exe_path, "rb"))
local file = f:read("*a")
f:close()
local raw = ffi.cast("const uint8_t *", file)
local function u16(o) return ffi.cast("const uint16_t *", raw + o)[0] end
local function u32(o) return ffi.cast("const uint32_t *", raw + o)[0] end
local pe = u32(0x3c)
assert(u32(pe) == 0x4550, "not a PE file")
local nsec, optsize = u16(pe + 6), u16(pe + 20)
local opt = pe + 24
local image_base = ffi.cast("const uint64_t *", raw + opt + 24)[0]
local size_of_image, size_of_headers = u32(opt + 56), u32(opt + 60)
local reloc_rva, reloc_size = u32(opt + 112 + 5 * 8), u32(opt + 112 + 5 * 8 + 4)
local mem = ffi.C.VirtualAlloc(nil, size_of_image, 0x3000, 0x40) -- MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
assert(mem ~= nil, "VirtualAlloc")
local base = ffi.cast("uint8_t *", mem)
ffi.copy(base, raw, size_of_headers)
for i = 0, nsec - 1 do
    local s = opt + optsize + 40 * i
    local va, rawsize, rawptr = u32(s + 12), u32(s + 16), u32(s + 20)
    if rawsize > 0 then
        ffi.copy(base + va, raw + rawptr, rawsize)
    end
end
local delta = ffi.cast("uint64_t", base) - image_base
local p, stop, relocs = reloc_rva, reloc_rva + reloc_size, 0
while p < stop do
    local page, size = ffi.cast("uint32_t *", base + p)[0], ffi.cast("uint32_t *", base + p)[1]
    if size == 0 then break end
    for k = 8, size - 2, 2 do
        local e = ffi.cast("uint16_t *", base + p + k)[0]
        if bit.rshift(e, 12) == 10 then -- IMAGE_REL_BASED_DIR64
            local at = ffi.cast("uint64_t *", base + page + bit.band(e, 0xfff))
            at[0] = at[0] + delta
            relocs = relocs + 1
        end
    end
    p = p + size
end
print(string.format("mapped %s: %d bytes at %s, %d relocations", exe_path, size_of_image, tostring(mem), relocs))
local addr = tonumber(ffi.cast("uintptr_t", base))
local function fn(name, which)
    local d = assert(b:func(name, which))
    return (b:fn(name, addr + d.rva, which))
end

local failures, checks = 0, 0
local function check(cond, what)
    checks = checks + 1
    if not cond then
        failures = failures + 1
    end
    print((cond and "ok   " or "FAIL ") .. what)
end

-- CColor: float results in XMM0, const this
local color = b:type("CColor")()
local comp = ffi.cast("float *", color)
comp[0], comp[1], comp[2], comp[3] = 0.25, 0.5, 0.75, 1.0
check(fn("CColor::GetRed")(color) == 0.25, "CColor::GetRed returns a float in XMM0")
check(fn("CColor::GetGreen")(color) == 0.5, "CColor::GetGreen")
check(fn("CColor::GetBlue")(color) == 0.75, "CColor::GetBlue")
check(fn("CColor::GetAlpha")(color) == 1.0, "CColor::GetAlpha")

-- CFixedPoint::Atan2 (static): the result through a hidden pointer, first; const references
local CFP = b:type("CFixedPoint")
local function fp(v)
    local x = CFP()
    x._Value.m_nVal = v
    return x
end
local atan2 = fn("CFixedPoint::Atan2")
local function at(y, x)
    local out = CFP()
    local r = atan2(out, fp(y), fp(x))
    assert(r == ffi.cast("CFixedPoint *", out), "Atan2 returns the hidden pointer")
    return tonumber(out._Value.m_nVal)
end
local one = 1000000
local q, h, z, nq = at(one, one), at(one, 0), at(0, one), at(-one, one)
print(string.format("Atan2: (1,1) %d, (1,0) %d, (0,1) %d, (-1,1) %d", q, h, z, nq))
check(math.abs(z) <= 1, "Atan2(0, 1) = 0 (to a unit)")
check(math.abs(q - math.pi / 4 * 100000) < 2, "Atan2(1, 1) = pi/4 (CFixedPoint counts 1e-5)")
check(nq == -q, "Atan2(-1, 1) = -Atan2(1, 1)")
check(q > 0 and math.abs(h - 2 * q) <= 2, "Atan2(1, 0) = 2 Atan2(1, 1) (pi/2 = 2 pi/4)")
check(math.abs(at(3 * one, 3 * one) - q) <= 1, "Atan2 depends on the ratio only")

-- operator fpml::fixed_point (instance): the result through a hidden pointer after this
local tofp = fn("CFixedPoint::operator fpml::fixed_point<__int64,48,15>")
local FP = b:type("fpml::fixed_point<__int64,48,15>")
local function conv(v)
    local out = FP()
    local r = tofp(fp(v), out)
    assert(r == ffi.cast("fpml__fixed_point___int64_48_15_ *", out), "returns the hidden pointer")
    return out.value_
end
local c1, c2 = conv(1000), conv(2000)
print(string.format("operator fixed_point: 1000 -> %s, 2000 -> %s, 0 -> %s", tostring(c1), tostring(c2), tostring(conv(0))))
check(conv(0) == 0 and math.abs(tonumber(c2) - 2 * tonumber(c1)) <= 1 and tonumber(c1) == math.floor(0.01 * 32768), "conversion to 2^-15 units (hidden pointer after this)")

-- CFixedPoint::GetRounded(fixed_point const&) (static, hidden pointer first) and
-- RoundTo (void, writes this): rounding is idempotent
local getrounded = fn("CFixedPoint::GetRounded", "CFixedPoint *(*)(CFixedPoint *, const fpml__fixed_point___int64_48_15_ *)")
local src = FP()
src.value_ = c1 * 2.5
local out = CFP()
getrounded(out, src)
local r1 = tonumber(out._Value.m_nVal)
local again = FP()
again.value_ = conv(r1)
local out2 = CFP()
getrounded(out2, again)
print(string.format("GetRounded(2.5 units) -> %d", r1))
check(tonumber(out2._Value.m_nVal) == r1, "GetRounded is idempotent")
local x = fp(1234567)
local step = fp(1000)
fn("CFixedPoint::RoundTo")(x, step)
local rounded = tonumber(x._Value.m_nVal)
print(string.format("RoundTo(1234567, 1000) -> %d", rounded))
check(rounded ~= 1234567 and rounded % 1000 == 0, "RoundTo writes this: a multiple of the step")

ffi.C.VirtualFree(mem, 0, 0x8000)
print(string.format("live_leaf: %d checks, %d failures", checks, failures))
os.exit(failures == 0 and 0 or 1)
