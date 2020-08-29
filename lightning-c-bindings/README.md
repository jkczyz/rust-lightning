The wrapper crate and C/C++ Headers in this folder are auto-generated from the Rust-Lightning
source by the c-bindings-gen crate contained in the source tree and
[cbindgen](https://github.com/eqrion/cbindgen). They are intended to be used as a base for building
language-specific bindings, and are thus incredibly low-level and may be difficult to work with
directly.

In other words, if you're reading this, you're either writing bindings for a new language, or
you're in the wrong place - individual language bindings should come with their own documentation.

LDK C Bindings
===================

The C bindings available at include/lightning.h require inclusion of include/rust_types.h first.

All of the Rust-Lightning types are mapped into C equivalents which take a few forms, namely:

 * Structs are mapped into a simple wrapper containing a pointer to the native Rust-Lightning
   object and a flag to indicate whether the object is owned or only a reference. Such mappings
   usually generate a `X_free` function which must be called to release the allocated resources.
   Note that calling `X_free` will do nothing if the underlying pointer is NULL or if the reference
   flag is set.

   You MUST NOT create such wrapper structs manually, relying instead on constructors which have
   been mapped from equivalent Rust constructors.

   Note that, thanks to the is-reference flag, such structs effectively represent both `&RustThing`
   and `RustThing`. Further, the same applies to `Option<RustThing>`, in which cases `inner` may be
   set to NULL.

   For example, this is the mapping of ChannelManager.
   ```
   typedef struct MUST_USE_STRUCT LDKChannelManager {
      /** ... */
      LDKlnChannelManager *inner;
      bool _underlying_ref;
   } LDKChannelManager;
   ```

 * Traits are mapped into a concrete struct containing a void pointer and a jump table listing the
   functions which the trait must implement. The void pointer may be set to any value and is never
   interpreted (or dereferenced) by the bindings logic in any way. It is passed as the first
   argument to all function calls in the trait. You may wish to use it as a pointer to your own
   internal data structure, though it may also occasionally make sense to e.g. cast a file
   descriptor into a void pointer and use it to track a socket.

   Each trait additionally contains a `free` and `clone` function pointer, which may be NULL. The
   `free` function is passed the void pointer when the object is `Drop`ed in Rust. The `clone`
   function is passed the void pointer when the object is `Clone`ed in Rust, returning a new void
   pointer for the new object.

   For example, `LDKSocketDescriptor` is mapped as follows:
   ```
   typedef struct LDKSocketDescriptor {
      void *this_arg;
      /** ... */
      uintptr_t (*send_data)(void *this_arg, LDKu8slice data, bool resume_read);
      /** ... */
      void (*disconnect_socket)(void *this_arg);
      bool (*eq)(const void *this_arg, const void *other_arg);
      uint64_t (*hash)(const void *this_arg);
      void *(*clone)(const void *this_arg);
      void (*free)(void *this_arg);
   } LDKSocketDescriptor;
   ```

 * Rust structs that implement a trait result in the generation of an `X_as_Y` function which allows
   you to use the native Rust object in place of the trait. Such generated objects are only valid as
   long as the original Rust native object is owned by a C-wrapped struct, and has not been `free`'d
   or moved as a part of a Rust function call.

 * Rust "unitary" enums are mapped simply as an equivalent C enum, however some Rust enums have
   variants which contain payloads. Such enums are mapped automatically by cbindgen as a tag which
   indicates the type and a union which holds the relevant fields for a given tag. A `X_free`
   function is provided for the enum as a whole which automatically frees the correct fields for a
   given tag, and a `Sentinel` tag is provided which causes the free function to do nothing (but
   which must never appear in an enum when accessed by Rust code). The `Sentinel` tag is used by
   the C++ wrapper classes to allow moving the ownership of an enum while invalidating the old copy.

 * Struct member functions are mapped as `Struct_function_name` and take a reference to the mapped
   struct as their first argument. Free-standing functions are mapped simply as `function_name` and
   take the relevant mapped type arguments.

   Functions may return a reference to an underlying Rust object with a mapped struct or an owned
   Rust object with the same. The mapped struct contains a flag to indicate if the poitned-to Rust
   object is owned or only a reference, and the object's corresponding free function will Do The
   Right Thing based on the flag. In order to determine the expected return type, you should
   reference the Rust documentation for the function.

   Similarly, when a function takes an `Option<RustType>` as a parameter or a return value, the C
   type is the same as if it took only `RustType`, with the `inner` field set to NULL to indicate
   None. For example, `ChannelManager_create_channel` takes an `Option<LDKUserCOnfig>` not an
   `LDKUserConfig`, but its definition is:
   ```
   MUST_USE_RES LDKCResult_NoneAPIErrorZ ChannelManager_create_channel(const LDKChannelManager *this_arg, ..., LDKUserConfig override_config);
   ```

As the bindings are auto-generated, the best resource for documentation on them is the native Rust
docs available via `cargo doc` or [docs.rs/lightning](https://docs.rs/lightning).

The memory model is largely the Rust memory model and not a native C-like memory model. Thus,
function parameters are largely only ever passed by reference or by move, with pass-by-copy
semantics only applying to primitive types. However, because the underlying types are largely
pointers, the same function signature may imply two different memory ownership semantics. Thus, you
MUST read the Rust documentation while using the C bindings. For functions which ownership is moved
to Rust, the corresponding `X_fre`e function MUST NOT be called on the object, whereas for all other
objects, `X_free` MUST be used to free resources.

LDK C++ Bindings
================

The C++ bindings available at include/lightningpp.hpp require extern "C" inclusion of lightning.h
and rust_types.h first. They represent thin wrappers around the C types which provide a few
C++-isms to make memory model correctness easier to achieve. They provide:
 * automated destructors which call the relevant `X_free` C functions,
 * move constructors both from C++ classes and the original C struct, with the original object
   cleared to ensure destruction/`X_free` calls do not cause a double-free.
 * Move semantics via the () operator, returning the original C struct and clearing the C++ object.
   This allows calls such as `C_function(cpp_object)` which works as expected with move semantics.

In general, you should prefer to use the C++ bindings if possible, as they make memory leaks and
other violations somewhat easier to avoid. Note that, because the C functions are not redefined in
C++, all functions return the C type. Thus, you must bind returned values to the equivalent C++ type
(replacing LDKX with LDK::X) to ensure the destructor is properly run. A demonstration of such usage
is available at [demo.cpp](demo.cpp).

**It is highly recommended that you test any code which relies on the C (or C++) bindings in
valgrind, MemorySanitizer, or other similar tools to ensure correctness.**

