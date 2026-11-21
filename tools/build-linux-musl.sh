#!/usr/bin/env bash
# Zig compiles bundled C; only the final executable links against Rust's musl.
set -euo pipefail

if [[ ${AGMI_MUSL_FINAL_LINK:-} = 1 ]]; then
    unset AGMI_MUSL_FINAL_LINK
    exec "$AGMI_MUSL_CLANG" --target=x86_64-unknown-linux-musl \
        "-fuse-ld=$AGMI_MUSL_LLD" "$@" -Xlinker -Map -Xlinker "$AGMI_MUSL_MAP"
fi
if [[ ${AGMI_MUSL_RUSTC_WRAPPER:-} = 1 ]]; then
    compiler=$1
    shift
    name= kind= previous=
    for arg in "$@"; do
        case $previous in
            --crate-name) name=$arg ;;
            --crate-type) kind=$arg ;;
        esac
        previous=$arg
    done
    if [[ $name = agmi && $kind = bin ]]; then
        export AGMI_MUSL_FINAL_LINK=1
        exec "$compiler" "$@" -C "linker=$AGMI_MUSL_SCRIPT"
    fi
    exec "$compiler" "$@"
fi

if (( $# != 0 )); then
    printf 'Usage: %s (set CARGO_TARGET_DIR to override the build directory)\n' "$0" >&2
    exit 2
fi
fail() { printf '%s\n' "$*" >&2; exit 1; }
digest() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
target=x86_64-unknown-linux-musl
rust=1.96.0
llvm=22.1.8
here=$(cd "$(dirname "$0")" && pwd -P)
export AGMI_MUSL_SCRIPT="$here/$(basename "$0")"
cd "$here/.."
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$PWD/target/linux-musl}
mkdir -p "$CARGO_TARGET_DIR"
CARGO_TARGET_DIR=$(cd "$CARGO_TARGET_DIR" && pwd -P)

for tool in rustup zig cargo-zigbuild clang ld.lld llvm-nm llvm-readelf shasum; do
    command -v "$tool" >/dev/null || fail "Required release tool missing: $tool"
done
zig_info=$(zig version)
zigbuild_info=$(cargo-zigbuild --version)
clang_info=$(clang --version)
lld_info=$(ld.lld --version)
[[ $zig_info = 0.17.1 ]] || fail 'Expected Zig 0.17.1'
[[ $zigbuild_info = 'cargo-zigbuild 0.24.1' ]] || fail 'Expected cargo-zigbuild 0.24.1'
[[ $clang_info = *"clang version $llvm "* || $clang_info = *"clang version $llvm"$'\n'* ]] || fail "Expected Clang $llvm"
[[ $lld_info = *"LLD $llvm "* || $lld_info = *"LLD $llvm" ]] || fail "Expected LLD $llvm"
export AGMI_MUSL_CLANG=$(command -v clang) AGMI_MUSL_LLD=$(command -v ld.lld)
sysroot=$(rustup run "$rust" rustc --print sysroot)
libc="$sysroot/lib/rustlib/$target/lib/self-contained/libc.a"
[[ -s $libc ]] || fail "Install $target for Rust $rust before building"

rm -f "$CARGO_TARGET_DIR/agmi-linux-musl-provenance.txt" "$CARGO_TARGET_DIR/agmi-linux-musl.map"
proof=$(mktemp -d "$CARGO_TARGET_DIR/.musl-link.XXXXXXXX")
trap 'rm -rf "$proof"' EXIT
export AGMI_MUSL_MAP="$proof/link.map"
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WORKSPACE_WRAPPER ZIG_LIB_DIR
export RUSTUP_TOOLCHAIN=$rust RUSTC="$sysroot/bin/rustc"
export PATH="$sysroot/bin:$PATH"
# A cached agmi executable could have used an earlier linker or wrapper. Keep
# dependency caches, but recreate the executable and its link map together.
rustup run "$rust" cargo clean --release --target "$target" -p agmi
export AGMI_MUSL_RUSTC_WRAPPER=1 RUSTC_WRAPPER="$AGMI_MUSL_SCRIPT"
rustup run "$rust" cargo zigbuild --locked --release --target "$target" --bin agmi

binary="$CARGO_TARGET_DIR/$target/release/agmi"
[[ -s $AGMI_MUSL_MAP ]] || fail 'Final link did not produce a fresh map'
elf=$(llvm-readelf -h -l -d "$binary")
[[ $elf = *'ELF64'* && $elf = *'Advanced Micro Devices X86-64'* && $elf = *'LOAD '* \
    && $elf != *INTERP* && $elf != *NEEDED* ]] || fail 'Expected a statically linked Linux x86-64 ELF'
symbols=$(llvm-nm -n --defined-only "$binary")
[[ $symbols != *'heap.SmpAllocator'* && $symbols != *'c.malloc.malloc'* ]] \
    || fail 'Zig allocator linked into release'
binary_digest=$(digest "$binary")
libc_digest=$(digest "$libc")
map_digest=$(digest "$AGMI_MUSL_MAP")
rust_info=$(rustc -Vv)
{
    printf 'target=%s\nbinary_sha256=%s\nlibc_archive_sha256=%s\nlink_map_sha256=%s\n' \
        "$target" "$binary_digest" "$libc_digest" "$map_digest"
    printf 'zig=%s\n%s\n%s\n%s\n%s\n\n' \
        "$zig_info" "$zigbuild_info" "$rust_info" "$clang_info" "$lld_info"
    # Match the final ELF's entry-point offsets with the actual archive inputs,
    # rather than merely checking that mallocng symbols are present somewhere.
    for pair in 'malloc:lite_malloc.lo:.text.default_malloc' 'free:free.lo:.text.free' '__libc_malloc_impl:malloc.lo:.text.__libc_malloc_impl'; do
        IFS=: read -r symbol member section <<< "$pair"
        address=$(awk -v sym="$symbol" '$NF == sym { sub(/^0+/, "", $1); print $1 }' <<< "$symbols")
        mapped=$(awk -v input="$libc($member):($section)" 'index($0, input) { sub(/^0+/, "", $1); print $1 }' "$AGMI_MUSL_MAP")
        [[ $address =~ ^[0-9a-fA-F]+$ && $address = "$mapped" ]] \
            || fail "Final ELF $symbol is not the Rust target's native musl definition"
        printf 'allocator_symbol=%s 0x%s libc.a(%s):(%s)\n' "$symbol" "$address" "$member" "$section"
    done
    printf '\n%s\n' "$elf"
} > "$proof/provenance.txt"
mv "$AGMI_MUSL_MAP" "$CARGO_TARGET_DIR/agmi-linux-musl.map"
mv "$proof/provenance.txt" "$CARGO_TARGET_DIR/agmi-linux-musl-provenance.txt"
printf 'Verified native musl malloc/free and static x86-64 ELF: %s\n' "$binary"
