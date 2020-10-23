echo "Needs '/.cargo/config' file!"

# Add osxcross toolchain to path
export PATH="/mnt/m/RustOSX/osxcross/target/bin:$PATH"

# Make libz-sys (git2-rs -> libgit2-sys -> libz-sys) build as a statically linked lib
# This prevents the host zlib from being linked
export LIBZ_SYS_STATIC=1

# Use Clang for C/C++ builds
export CC=o64-clang
export CXX=o64-clang++

cargo build --release --target x86_64-apple-darwin
