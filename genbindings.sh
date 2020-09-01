#!/usr/bin/env bash

# Generate (and reasonably test) C bindings

set -e
# First build the latest c-bindings-gen binary
cd c-bindings-gen && cargo build && cd ..

# Then wipe all the existing C bindings (because we're being run in the right directory)
# note that we keep the few manually-generated files first:
mv lightning-c-bindings/src/c_types/mod.rs ./
mv lightning-c-bindings/src/bitcoin ./

rm -rf lightning-c-bindings/src

mkdir -p lightning-c-bindings/src/c_types/
mv ./mod.rs lightning-c-bindings/src/c_types/
mv ./bitcoin lightning-c-bindings/src/

# Finally, run the c-bindings-gen binary, building fresh bindings.
SRC="$(pwd)/lightning/src"
OUT="$(pwd)/lightning-c-bindings/src"
OUT_TEMPL="$(pwd)/lightning-c-bindings/src/c_types/derived.rs"
OUT_F="$(pwd)/lightning-c-bindings/include/rust_types.h"
OUT_CPP="$(pwd)/lightning-c-bindings/include/lightningpp.hpp"
RUST_BACKTRACE=1 ./c-bindings-gen/target/debug/c-bindings-gen $SRC/ $OUT/ lightning $OUT_TEMPL $OUT_F $OUT_CPP

# Now cd to lightning-c-bindings, build the generated bindings, and call cbindgen to build a C header file
PATH="$PATH:~/.cargo/bin"
cd lightning-c-bindings
cargo build
cbindgen -v --config cbindgen.toml -o include/lightning.h

# cbindgen is relatively braindead when exporting typedefs -
# it happily exports all our typedefs for private types, even with the
# generics we specified in C mode! So we drop all those types manually here.
sed -i '' 's/typedef LDKnative.*Import.*LDKnative.*;//g' include/lightning.h

# Finally, sanity-check the generated C and C++ bindings with demo apps:

# Naively run the C demo app:
gcc -Wall -g -pthread demo.c ../target/debug/liblightning.a -ldl
./a.out

# And run the C++ demo app in valgrind to test memory model correctness and lack of leaks.
g++ -Wall -g -pthread demo.cpp -L../target/debug/ -llightning -ldl -std=c++14
if [ -x "`which valgrind`" ]; then
	LD_LIBRARY_PATH=../target/debug/ valgrind --error-exitcode=4 --memcheck:leak-check=full --show-leak-kinds=all ./a.out
	echo
else
	echo "WARNING: Please install valgrind for more testing"
fi

# Test a statically-linked C++ version, tracking the resulting binary size and runtime 
# across debug, LTO, and cross-language LTO builds (using the same compiler each time).
clang++ -Wall -pthread demo.cpp ../target/debug/liblightning.a -ldl -std=c++14
./a.out
echo " C++ Bin size and runtime w/o optimization:"
ls -lha a.out
time ./a.out > /dev/null

HOST_PLATFORM="$(rustc --version --verbose | grep "host:")"

# Then, check with memory sanitizer, if we're on Linux and have rustc nightly
if [ "$HOST_PLATFORM" = "host: x86_64-unknown-linux-gnu" ]; then
	if cargo +nightly --version >/dev/null 2>&1; then
		LLVM_V=$(rustc +nightly --version --verbose | grep "LLVM version" | awk '{ print substr($3, 0, 2); }')
		if [ -x "$(which clang-$LLVM_V)" ]; then
			cargo +nightly clean
			cargo +nightly rustc -Zbuild-std --target x86_64-unknown-linux-gnu -v -- -Zsanitizer=memory -Zsanitizer-memory-track-origins -Cforce-frame-pointers=yes
			mv ../target/x86_64-unknown-linux-gnu/debug/liblightning.* ../target/debug/

			# Sadly, std doesn't seem to compile into something that is memsan-safe as of Aug 2020,
			# so we'll always fail, not to mention we may be linking against git rustc LLVM which
			# may differ from clang-llvm, so just allow everything here to fail.
			set +e

			# First the C demo app...
			clang-$LLVM_V -fsanitize=memory -fsanitize-memory-track-origins -Wall -g -pthread demo.c ../target/debug/liblightning.a -ldl
			./a.out

			# ...then the C++ demo app
			clang++-$LLVM_V -fsanitize=memory -fsanitize-memory-track-origins -Wall -g -pthread demo.cpp ../target/debug/liblightning.a -ldl
			./a.out

			# restore exit-on-failure
			set -e
		else
			echo "WARNING: Can't use memory sanitizer without clang-$LLVM_V"
		fi
	else
		echo "WARNING: Can't use memory sanitizer without rustc nightly"
	fi
else
	echo "WARNING: Can't use memory sanitizer on non-Linux, non-x86 platforms"
fi

# Finally, if we're on OSX or on Linux, build the final debug binary with address sanitizer (and leave it there)
if [ "$HOST_PLATFORM" = "host: x86_64-unknown-linux-gnu" -o "$HOST_PLATFORM" = "host: x86_64-apple-darwin" ]; then
	RUSTC_BOOTSTRAP=1 cargo rustc -v -- -Cforce-frame-pointers=yes

	# First the C demo app...
	clang -Wall -g -pthread demo.c ../target/debug/liblightning.a -ldl
	ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' ./a.out

	# ...then the C++ demo app
	clang++ -Wall -g -pthread demo.cpp ../target/debug/liblightning.a -ldl -std=c++14
	ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' ./a.out
else
	echo "WARNING: Can't use address sanitizer on non-Linux, non-OSX non-x86 platforms"
fi

# Now build with LTO on on both C++ and rust, but without cross-language LTO:
cargo rustc -v --release -- -C lto
clang++ -Wall -flto -O2 -pthread demo.cpp ../target/release/liblightning.a -ldl -std=c++14
echo "C++ Bin size and runtime with only RL (LTO) optimized:"
ls -lha a.out
time ./a.out > /dev/null

# Finally, test cross-language LTO. Note that this will fail if rustc and clang++
# build against different versions of LLVM (eg when rustc is installed via rustup
# or Ubuntu packages). This should work fine on Distros which do more involved
# packaging than simply shipping the rustup binaries (eg Debian should Just Work
# here).
cargo rustc -v --release -- -C lto
clang++ -Wall -flto -O2 -pthread demo.cpp ../target/release/liblightning.a -ldl -std=c++14
echo "C++ Bin size and runtime with cross-language LTO:"
ls -lha a.out
time ./a.out > /dev/null
