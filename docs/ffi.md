# LuaJIT FFI declarations from a PDB

`stellar-fnmatch cdef` turns a build's PDB into a Lua module of LuaJIT FFI declarations: a C
definition for every class, struct, union and enum that is asked for (with what they need), and a
C declaration of every function that follows the MSVC x64 calling convention. The module is read by
lua_fnmatch's `fnmatch.ffi` (its README, "Typed functions and classes"), which declares types on
demand, gives typed function pointers for addresses that `fnmatch.bundle` found, and makes virtual
calls. `stellar-fnmatch ffi-check` checks the declarations against evidence outside the PDB's type
records.

- [V] is verified by a test or a measurement given here; [I] is inferred.
- Numbers are for GOG 4.5.2 (`stellaris.exe`, `stellaris.pdb` 390 MB) unless a section says otherwise.

## Commands

```
# a module for some classes and functions (with what they need)
stellar-fnmatch cdef --pdb stellaris.pdb --fnx gog-4.5.2.fnx --exe stellaris.exe \
    --classes CNamedColor,CAIAttitude --functions-file functions.lua --out gog-4.5.2.ffi.lua
# everything (for the checks: 91,816 types, 136,050 functions, 169 MB, 8 s)
stellar-fnmatch cdef --pdb stellaris.pdb --fnx gog-4.5.2.fnx --exe stellaris.exe \
    --all-classes --all-functions --out full.lua --report full.json
# the checks against the Linux build, the vftables and the code
nm -C --defined-only stellaris-linux > linux.nm
stellar-fnmatch ffi-check --pdb stellaris.pdb --exe stellaris.exe --fnx gog-4.5.2.fnx --linux-nm linux.nm
# every layout and declaration under LuaJIT (one process per slice: 65,536 ctypes per Lua state)
sh tests/ffi/run_checks.sh luajit full.lua 128 24              # Linux
powershell tests/ffi/run_checks.ps1 -LuaJit luajit.exe -Module full.lua -Slices 64 -Jobs 5
```

| option | |
|---|---|
| `--classes`, `--classes-file` | classes by C++ name (or C name); every definition with that name |
| `--functions`, `--functions-file` | functions by PDB name; a file is one name per line, or a Lua list with `name = "..."` entries such as stellarstellaris's `functions.lua` |
| `--all-classes`, `--all-functions` | everything |
| `--fnx` | the build's extract: build identity in the module, and which functions may throw |
| `--exe` | the build's executable: decides how the classes the PDB is ambiguous about are passed by value (below) |
| `--prefix` | before every C name, for a Lua state that has declarations of its own |
| `--no-fields` | leave the member lists out |

`tests/ffi/sample_gog452.lua` is a generated sample: the five database classes of stellarstellaris's
`docs/databases.md` and their databases, and the functions of its `functions.lua` (56 types, 75
functions, 139 KB).

## The module

A Lua chunk that returns `M`, written as many small functions (a Lua function has room for 65,536
constants):

| field | |
|---|---|
| `format` (1), `abi` (`"msvc-x64"`), `generator`, `pdb` (`file`, `guid`, `age`), `build` (`id`, `version`, `build`, `md5`, `image_base`: from `--fnx`) | |
| `types[cname]` | `cpp` (C++ name), `kind` (`struct`, `union`, `enum`), `size`, `align`, `cdef` (the definition), `deps` (C names needed complete first), `refs` (needed as declarations), `fields`, `bases`, `vfptrs`, `values` (enums), `packed`, `virtual_bases`, `notes` |
| `opaque[cname]` | types used only through pointers: `cpp`, `kind` |
| `functions[name]` | a list (overloads, and names the linker folded onto one address), each `rva`, `decl` (`R (*)(A, B)`), `cpp`, `kind` (`free`, `static`, `method`, `ctor`, `dtor`), `ret` (`void`, `value`, `hidden`), `this` (C name of what `this` points to), `this_adjust`, `class`, `throws` and `via`, `virtual` (`vfptr`, `slot`, `intro`, `pure`), `deps`, `refs`, `params` (`category|passing|C++ type`), `variadic`, `rewrites` |
| `names[cpp]` | C++ name to C name (a list when several definitions share it) |

A field is `{ name, offset, cpp type, bit position, bits, from = base path, cpp_name = ..., unit = ... }`.

## Types

### Rules

Each rule is checked by the layout validation (below) unless marked otherwise.

- **Names.** Every class, struct, union and enum definition gets a C name: its C++ name with `::`
  as `__`, `*` as `P`, `&` as `R` and other punctuation as `_`
  (`CPdxArray<CShip *,int>` is `CPdxArray_CShipP_int_`); C keywords and LuaJIT's predefined types
  get a `_` appended; names longer than 100 characters are cut and given a hash; a name taken by an
  earlier definition gets a hash of the decorated name. Definitions are keyed by their decorated
  name (`.?AVCShip@@`), forward references resolved to them; 4 decorated names have two definitions
  of different sizes (the first is kept).
- **Fixed-width types only.** `int` and `long` are `int32_t` (MSVC's `long` is 32 bits),
  `__int64` `int64_t`, `wchar_t` and `char16_t` `uint16_t`, `char32_t` `uint32_t`, `long double`
  `double` (8 bytes on MSVC), `char` stays `char` (one byte everywhere), `bool` `bool`.
  References are pointers. Pointers to functions are `void *` (their types would pull in more
  types; `fields` and `params` keep the C++ type). Pointers to members are `int32_t` arrays (data)
  and `uint64_t` arrays or `void *` (functions), by their PDB size [I: never dereferenced].
- **Bases are flattened.** The data members of the non-virtual bases are emitted at their offsets
  in the derived class, so `obj._Index` works on a `CNamedColor`. A name a base shares with the
  class (or another base) is qualified with the base's C name (`CPersistent___x`). `bases` lists
  every base subobject with its offset, for `fnmatch.ffi`'s `cast`.
- **vtable pointers** are `void **__vfptr` (`__vfptr_<hex offset>` in a base at that offset); a
  class's own vfptr is at its offset 0, as MSVC lays it out. **Virtual bases**: only the
  `__vbptr`; their members are not emitted (where they are is known only at run time). 11 classes,
  mostly the C++ library's streams.
- **Padding.** Explicit `uint8_t _pN[n]` between members and up to the size, so no offset depends
  on the host's alignment rules.
- **Overlaps** (anonymous unions, unions whose anonymous structs the PDB flattens): members that
  overlap form a group, emitted as an anonymous union of lanes; a lane is a run of members that do
  not overlap (an anonymous struct with leading padding, or a single member at the group's start).
  LuaJIT rounds the anonymous union up to its alignment, which the layout accounts for. 294 classes.
- **Bitfields.** MSVC gives bitfields storage units: the members at one offset, of one declared type
  (a new unit starts when the type's size changes or a field does not fit). Each unit is an
  anonymous struct of bitfields of the unit's type, with unnamed fields filling the gaps. Inside one
  unit of one type, MSVC and the GCC rules LuaJIT follows place bits the same way; LuaJIT's
  `ffi.offsetof` returns the unit offset, bit position and width, which the validation compares with
  the PDB. LuaJIT's bitfield containers are at most 32 bits: a 64-bit unit is split into two 32-bit
  ones when no field crosses bit 32, and kept as a `uint64_t _bits_<offset>` member with the fields
  as accessors (`unit` in `fields`; `fnmatch.ffi`'s `getbits`, `setbits`) otherwise (5 units in 4
  types). `bool` fields stay `bool`; enum-typed ones take the enum's integer type. 113 types.
- **Packing.** When LuaJIT, without `packed`, would put a member elsewhere (a member off its
  natural alignment, a size that is not a multiple of the alignment: `#pragma pack`), the struct
  and its anonymous parts are declared `__attribute__((packed))`. 242 types.
- **Enums** are `typedef <fixed-width int> E;`; their values are in `values`, not in C (the
  enumerators of different enums would collide in C's one namespace).
- **Members without a size** (lambda closures inside `std::function` storage, 12) are left as
  padding and listed in `notes`.

### Declared on demand

A Lua state has room for 65,536 ctypes, and every member is one; all 91,816 types of 4.5.2 make
563,268. So types are declared one closure at a time: `deps` are the types needed complete before
a definition (members by value, element types of arrays), `refs` those needed only as
`struct X;` (pointers). `fnmatch.ffi` declares a type with its closure on first use, in one
`ffi.cdef`.

## Functions

### Rules (MSVC x64)

| rule | evidence |
|---|---|
| `this` first (RCX). For an override reached through a secondary base, the function expects a pointer to that base subobject (`this_adjust` bytes into the object, from the PDB's function type); `this` is then declared as a pointer to that base class, so passing the derived pointer fails in LuaJIT instead of corrupting memory, and `fnmatch.ffi`'s `cast` gives the right pointer (2,104 functions) | [V] fixture: `Derived::Other1` called with `this` + 16 |
| A class, struct or union result of an **instance method** always goes through a hidden pointer, after `this` (RDX); the function returns the pointer in RAX. The declaration takes the pointer and returns it (6,464 methods) | [V] the PDB marks all 6,464 "C++ style ReturnUDT"; the code: RAX = that pointer at every return of 92.3% of the hidden-result functions (a linear data-flow over each function; the rest return through paths the tracker loses; control: 0 of 6,237 methods returning an integer), callers pass a stack address in 93% of 39,114 call sites; fixture `Derived::GetVec`, `GetBig`; game `CFixedPoint::operator fpml::fixed_point` called |
| A class result of a **free or static function** goes through a hidden pointer, first (RCX), when the PDB says "C++ style ReturnUDT" (not a C++03 POD: user constructor, destructor or copy assignment, bases, virtual functions, private members) or its size is not 1, 2, 4 or 8 bytes; otherwise in RAX (1,994 + 25 functions) | [V] the flag and the POD rule agree on 305 of 306 small results (the other is a lambda); fixture `ffx_big`, `ffx_handle`, `Derived::MakeHandle`, `ffx_vec`, `Derived::MakeVec`; game `CFixedPoint::Atan2` called |
| References are pointers | [V] Linux cross-check |
| `float` and `double` parameters stay `float` and `double`: LuaJIT passes them in the XMM register of their position, the others in the GPR of theirs, from the fifth on the stack, as MSVC does | [V] fixture `ffx_mix` (six mixed parameters); 1,713 of 1,906 call sites write XMM*n* before the call (193 not seen in the window); game `CColor::GetRed` (result in XMM0) called |
| A class **by value** of a size other than 1, 2, 4 or 8 bytes is passed as a pointer to a copy the caller makes; the callee owns and destroys it (MSVC destroys by-value arguments in the callee) (1,860 parameters) | [V] callers pass a stack address at 14,152 of 15,661 call sites (576 pass an address held in a register, 908 not seen); fixture `ffx_take_big`; fixture `ffx_take_counted`: the copy's destructor ran in the callee |
| A class of 1, 2, 4 or 8 bytes by value is in a register when it has a trivial copy constructor: no virtual functions or bases, no declared copy constructor, members and bases alike; a destructor does not matter. Otherwise by address, as above (5,467 in registers) | [V] fixture: `HandleC` (defaulted copy constructor), `WithDtor` (destructor only), `Vec2` in a register, `Counted` (copy constructor) by address; game: callers set up classes declared in a register by a stack address at 45 of 7,636 call sites (0.6%) |
| A class with a declared **move constructor and no listed copy constructor** is ambiguous in the PDB: a defaulted copy constructor is not listed at all (fixture `HandleC`), so "copy constructor deleted" (by address) and "defaulted" (in a register) have the same records. With `--exe`, the code of the functions taking the class decides: each one either dereferences the argument register (by address) or uses its value (in a register). In 4.5.2: 63 classes in a register (`TPdxRef<T>`, `std::variant<TPdxRef...>`, `CSimpleBitMask<E>`), 15 by address; 225 parameters (lambda closures given to the C++ library's algorithms, `Eigen::Matrix<float,2,1>`) have no evidence and are declared by address [I] | [V] fixture: `Handle` (user move constructor) and `HandleD` (defaulted move constructor) by address, decided by the DLL's code; game: `CAddBuildableToQueueCommand`'s constructor stores its `TPdxRef` arguments from EDX and R8D |
| Enums by value are their integer type | [V] fixture `ffx_color` |
| Variadic functions: LuaJIT mirrors vararg registers in both register sets, as MSVC expects; a Lua number goes as a `double`, so integers must be passed as cdata (39 functions) | [V] fixture `ffx_sum` |
| Pointers to member functions by value: 8 bytes in a register, larger by address [I] | |

Every change from the C++ signature is listed in the function's `rewrites`, in words: the hidden
result and its position, a by-value class made a pointer to a copy and why, the `this` adjustment,
the deleting destructor of a virtual destructor, the move-constructor cases with their evidence.

### Virtual methods

- **Slots.** An introducing declaration has its vtable offset in the PDB; the method is in the
  primary vftable of the class that introduces it: its own vfptr at offset 0, or that of the first
  base (by offset) that has one. An override finds the introducing declaration in its bases (same
  name, same parameters and `const`), the vfptr offset adding up along the way. 65,967 virtual
  methods get a slot; 19 do not [V: vftables below].
- **Destructors.** MSVC lists `__vecDelDtor` (the deleting destructor) as introduced in every class
  that has one, but its slot is in the vftable of the first base, by offset, that already has a
  virtual destructor; only when none has one does the class introduce it, in its primary vftable.
  A slot can hold an adjustor thunk (`sub rcx, 16; jmp`) to the deleting destructor: calling the
  slot with the subobject that holds the vfptr is what the thunk expects. The deleting destructor
  is `void *(void *this, uint32_t flags)`, flags 1 frees the memory [V: vftables; fixture].
- `fnmatch.ffi`'s `vfn(obj, name)` reads the vtable at `obj + vfptr` and returns the slot's
  function with that subobject as `this`.

### Which functions may throw

From the call graph of the `.fnx` (`src/throws.rs`): a function may throw ("yes") when direct calls
or tail jumps reach a throw site, a function that calls `_CxxThrowException` (linked statically in
the GOG builds; through an import thunk when the CRT is a DLL), or the C++ library's throwing
helpers. "maybe": no such path, but it makes virtual or indirect calls, which are not followed;
"no" otherwise; "unknown": the function is not in the extract. EH funclets count for their owner.
`via` says what is thrown: `alloc` (`operator new`, array sizes), `std` (the library's
`_Xlength_error`, `_Xout_of_range`, ...), `game` (any other `throw`), `seh` (`RaiseException`
outside the C++ runtime, not a C++ exception and not counted).

| 4.5.2 | functions |
|---|---|
| yes | 62,406: `alloc` only 16,996 (`alloc,seh` 66 more), `alloc,std` 26,266 (with `seh` or not), `std` 1,405, with `game` 17,673 |
| maybe | 42,916 |
| no | 29,962 |
| unknown | 766 |

A `catch` in a caller is not looked at, so "yes" is an upper bound [I].

What happens to such an exception in LuaJIT is in lua_fnmatch's README ("C++ exceptions"): on
Windows x64, with LuaJIT 2.1 at 6f54a53 (the one lua_fnmatch and stellarstellaris-win build), a
Lua `pcall` above the call catches it, compiled or not, and the state stays usable [V].

## Validation

### Layouts and declarations under LuaJIT

`tests/ffi/check.lua` declares each type with its closure and compares `ffi.sizeof` of the type
and `ffi.offsetof` of every member (and the bit position and width of every bitfield; the unit's
offset for accessor fields) with the PDB's values; `decls` declares each function's types and calls
`ffi.typeof` on its declaration.

| | types | members | declarations |
|---|---|---|---|
| Linux x64, LuaJIT 6f54a53 built with GCC | 91,816 of 91,816 | 210,255 of 210,255 | 136,050 of 136,050 |
| Windows x64, LuaJIT 6f54a53 built with MSVC (`msvcbuild.bat`) | 91,816 of 91,816 | 210,255 of 210,255 | 136,050 of 136,050 |

All classes, not a sample [V].

### Against the Linux build

The Linux build (Steam depot 281994, 4.5.2) keeps every symbol, Itanium-mangled; `nm -C` gives each
function's parameter list. Names are put in one form (no spaces next to punctuation, `__int64` as
`long`, no `class`/`enum` keywords, GCC's `(anonymous namespace)`); a name with one signature on
both sides is a pair, overloads pair when the parameter count leaves one candidate. Each parameter
is a pointer (to const or not), a reference (to const or not, or rvalue), a fundamental type (by
kind and width), or a class or enum by value.

| | |
|---|---|
| names on both sides | 64,563 (of 110,408 PDB names; the C++ library differs entirely) |
| pairs | 66,250 (61,781 unique, 4,469 overloads by parameter count; 783 overloads not paired) |
| parameter count agrees | 66,194 (99.92%) |
| parameters, by kind (pointer, reference, value, fundamental) | 67,911 of 67,935 (99.96%) |
| parameters, exactly (const, width, rvalue) | 67,903 (99.95%) |
| functions agreeing in every parameter | 66,162 (99.87%) |
| `const` methods | 59,700 agree, 3 do not |

The disagreements, by kind:
- **Platform code** (the functions differ): 36 have a third parameter on Linux
  (`CCountry::HasTradition(CTraditionType const*, bool)`), 3 template instantiations differ in
  their parameter lists, and 2 single cases (`HasAscensionPerk` takes a reference on Linux).
- **Pairing**: about 40 constructors where the PDB has only the move constructor and Linux only the
  copy constructor (or another one) of a class: different functions, paired by count.
- **Data model**: 8 `unsigned long` / `long` parameters, 32 bits on Windows (LLP64) and 64 on Linux
  (LP64); the declaration is right for Windows.

An earlier version found two real errors this way, both fixed: a `const` pointer inside a reference
(`T const* const&`) is `const` in the pointer record, not in a modifier (293 parameters); and the
same for pointers to const pointers (148).

### vtables

The vftables are public symbols (`??_7CShip@@6BCSelectable@@@`: CShip's vftable for its
CSelectable subobject). The qualifier names a base that tells the vftable apart; it can hold several
vfptrs, so each symbol takes the one vfptr of that base no other symbol of the class takes; the
unqualified one takes what is left. For every virtual method of a class with a vftable symbol, the
slot is read from the executable and compared with the function's address (an adjustor thunk
followed to its target; a destructor's slot must hold a deleting destructor).

| | |
|---|---|
| vftable symbols | 18,647, 18,629 mapped to a (class, vfptr) |
| virtual methods checked | 39,508 (9 more slots hold `_purecall`: pure virtual destructors) |
| the slot holds the method | 39,252 (99.35%): 14,577 destructors, 815 through an adjustor thunk |
| something else | 256 |
| no vftable symbol for the class | 1,834 |

The 256 are mostly methods whose code the linker folded with others (`return false;` at one address
for hundreds of names), where the PDB's name for the address and the slot disagree, and classes
with a base twice in their hierarchy, where the vftable names are ambiguous to this check [I].

### The code

`ffi-check` decodes every function of the executable:
- each `call` to a typed function: what last wrote each argument register before it (a stack
  address, a load, a constant, ...), per kind of parameter;
- each hidden-result function: whether RAX holds the hidden pointer at every return.

Results are in the tables above. The tracking is linear (no control-flow graph), so "not seen" and
"some returns" are the tracker's limits [I].

### Calls

- **Fixture** (lua_fnmatch `tests/fixtures/ffi`, an MSVC-built DLL with known source): every
  layout, every recorded rule, and on Windows a call of every function: hidden results (first and
  after `this`), by-value classes in registers and by address, floats by position on the stack,
  varargs, bitfields (C fields and accessors), a packed struct, an anonymous union, enums, virtual
  calls through both vfptrs, a direct call with the adjusted `this`, the deleting destructor, C++
  exceptions. 476 checks [V].
- **Game code**: `tests/ffi/live_leaf.lua` maps the GOG executable itself (sections copied, 189,974
  relocations applied, imports not resolved, nothing else run) and calls leaf functions (no calls
  in the call graph): `CColor::GetRed/Green/Blue/Alpha` (float results), `CFixedPoint::Atan2`
  (static, hidden result first: `Atan2(1, 1)` = 78,539, pi/4 at CFixedPoint's 10^-5),
  `operator fpml::fixed_point` (hidden result after `this`), `GetRounded`, `RoundTo` (writes
  `this`). 12 checks [V].

## Using it in stellarstellaris (not done here)

How the injected game's Lua would use it (`lua/stellar/resolve.lua` and the database builder):

1. Generate per reference build, on the dev machine:
   `stellar-fnmatch cdef --pdb <gog pdb> --fnx <fnx> --exe <gog exe> --functions-file
   lua/stellar/functions.lua --classes-file <the classes Lua touches> --out <build>.ffi.lua`.
   The output is derived from the PDB, so it is generated rather than committed.
2. `resolve.lua`: `local b = fnmatch.ffi.load(path)`, `fnmatch.bundle(image, { ffi = b })`, and for
   each entry `declaration = <its rva in the reference build>` (signatures.lua has it). Found
   entries then carry `entry.fn`, the typed function at the found address; `resolve.functions`
   can return it beside the address.
3. Check that the module fits the running game: the Steam and GOG builds of one version share the
   commit (the build string), so layouts and declarations carry over [I: the same compiler output,
   which the signature matching relies on too]; refuse a module of another version.
4. Replace hand-written offsets: `b:type("CNamedColor")`, `obj._Index`, `b:cast(obj,
   "CPersistent")`, `b:enum(...)`. Objects Lua builds also need the vftable addresses of the running
   build, which the module does not give (they are GOG addresses): take them from an object the game
   made (the null objects), or find them like functions.
5. Live calls in the game: start in the dev channel with pure functions, wrap calls of functions
   that may throw in `pcall`.

## What is left

- vftable addresses (data) in the running build, for objects Lua constructs.
- Members of virtual bases (11 classes, mostly the C++ library's), typed function-pointer members.
- Parameter names (the module symbols' `S_LOCAL` with the parameter flag) for readable declarations.
- The 256 unexplained vtable slots and the 225 by-value parameters without evidence.
- A finer "may throw": `catch` blocks and `noexcept` in callers, targets of virtual calls.
- Two modules of different builds in one Lua state need `--prefix` (the C names would collide).
