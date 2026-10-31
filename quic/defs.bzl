load(
    "@fbsource//tools/build_defs:default_platform_defs.bzl",
    "ANDROID",
    "APPLE",
    "CXX",
    "FBCODE",
    "IOS",
    "MACOSX",
    "WINDOWS",
)
load("@fbsource//tools/build_defs:fb_xplat_cxx_binary.bzl", "fb_xplat_cxx_binary")
load("@fbsource//tools/build_defs:fb_xplat_cxx_library.bzl", "fb_xplat_cxx_library")
load("@fbsource//tools/build_defs:fb_xplat_cxx_test.bzl", "fb_xplat_cxx_test")
load("@fbsource//tools/build_defs:fbsource_utils.bzl", "is_fbcode_compatible")
load("@fbsource//tools/build_defs:selects.bzl", "selects")
load("@fbsource//tools/build_defs/dirsync:fb_dirsync_cpp_library.bzl", "fb_dirsync_cpp_library")
load("@fbsource//tools/build_defs/xplat:deps_map_utils.bzl", "deps_map_utils")
load("@fbsource//xplat/pfh/Infra_Networking_Core:DEFS.bzl", "Infra_Networking_Core")
load("@prelude//utils:buckconfig.bzl", "read_bool")

CXXFLAGS = [
    "-frtti",
    "-fexceptions",
    "-Wno-nullability-completeness",
]

FBANDROID_CXXFLAGS = [
    "-ffunction-sections",
    "-Wno-nullability-completeness",
    "-fstack-protector-strong",
] + (
    [
        "-flazy-init-all",
    ]
    if read_bool("ndk", "flazy_init_all", False)
    else []
)

FBOBJC_CXXFLAGS = [
    "-Wno-global-constructors",
    "-fstack-protector-strong",
]

WINDOWS_MSVC_CXXFLAGS = [
    "/EHs",
    "/D_ENABLE_EXTENDED_ALIGNED_STORAGE",
]

WINDOWS_CLANG_CXX_FLAGS = [
    "-Wno-deprecated-declarations",
    "-Wno-microsoft-cast",
    "-Wno-missing-braces",
    "-Wno-unused-function",
    "-Wno-undef",
    "-DBOOST_HAS_THREADS",
    "-D_ENABLE_EXTENDED_ALIGNED_STORAGE",
]

DEFAULT_APPLE_SDKS = (IOS, MACOSX)
DEFAULT_PLATFORMS = (CXX, ANDROID, APPLE, FBCODE, WINDOWS)

def _compute_include_directories():
    base_path = native.package_name()
    if base_path == "xplat/quic":
        return [".."]
    quic_path = base_path[6:]
    return ["/".join(len(quic_path.split("/")) * [".."])]

def _compute_header_namespace():
    base_path = native.package_name()
    return base_path[6:]

# fbcode's `cpp_library` never re-exports `deps`; keep that for the fbcode
# build so mvfst's private deps stay private to its consumers.
_FBCODE_LIBRARY_KWARGS = {"fbcode_reexport_all_header_dependencies": False}

def _add_fbcode_only_deps(kwargs):
    """Fold `fbcode_only_deps` / `fbcode_only_exported_deps` into the deps.

    Deps on fbcode-only projects (`fbcode//justknobs`, `fbcode//xsec_crypto`)
    cannot resolve on macOS hosts, where the fbcode cell is not usable, and
    `uquery` over the Android graph is checked with a macOS host. They are
    only added when the host can build fbcode at all, like `fbcode_deps` in
    `fb_xplat`; `select()`s are fine here.
    """
    for kind in ("deps", "exported_deps"):
        extra = kwargs.pop("fbcode_only_" + kind, None)
        if extra != None and is_fbcode_compatible():
            kwargs[kind] = kwargs.get(kind, []) + extra
    return kwargs

def fbcode_only_target_compatible_with():
    """`target_compatible_with` for a `fbcode//quic/...` alias into a rule that
    only builds for FBCODE (`mvfst_cpp_benchmark`, `tperf-xsec`).

    `fb_xplat` emits FBCODE-only rules on hosts that can build fbcode and
    nothing elsewhere, so on a Windows host the alias would point at a target
    that does not exist. Declaring the alias incompatible there lets
    `fbcode//quic/...` builds skip it, the way they skipped the fbcode-only
    `cpp_benchmark` rules before.
    """
    return [] if is_fbcode_compatible() else ["ovr_config//:none"]

def mvfst_cpp_library(name, compiler_flags = [], **kwargs):
    kwargs = _add_fbcode_only_deps(kwargs)
    fb_dirsync_cpp_library(
        name = name,
        compiler_flags = select({
            "DEFAULT": compiler_flags
            + CXXFLAGS
            + select({
                "DEFAULT": [],
                "ovr_config//os:android": FBANDROID_CXXFLAGS,
                "ovr_config//os:iphoneos": FBOBJC_CXXFLAGS,
                "ovr_config//os:macos": FBOBJC_CXXFLAGS,
                "ovr_config//os:windows": WINDOWS_CLANG_CXX_FLAGS,
            }),
            "ovr_config//compiler:msvc": WINDOWS_MSVC_CXXFLAGS,
        }),
        feature = Infra_Networking_Core,
        **(kwargs | _FBCODE_LIBRARY_KWARGS),
    )

# TODO: Turn this into an internal implementation detail
def mvfst_cxx_library(
    name,
    srcs = (),
    headers = (),
    exported_headers = (),
    raw_headers = (),
    deps = (),
    exported_deps = (),
    force_static = False,
    apple_sdks = None,
    platforms = None,
    enable_static_variant = False,
    compiler_flags = [],
    labels = (),
    header_namespace = "",
    **kwargs,
):
    """Translate a simpler declartion into the more complete library target"""

    # Set default platform settings. `()` means empty, whereas None
    # means default
    if apple_sdks == None:
        apple_sdks = DEFAULT_APPLE_SDKS
    if platforms == None:
        platforms = DEFAULT_PLATFORMS

    # We use gflags on fbcode platforms, which don't mix well when mixing static
    # and dynamic linking.
    force_static = select({
        "DEFAULT": select({
            "DEFAULT": force_static,
            "ovr_config//runtime:fbcode": False,
        }),
        "ovr_config//build_mode:arvr_mode[enabled]": force_static,
    })

    fb_xplat_cxx_library(
        name = name,
        srcs = srcs,
        header_namespace = header_namespace,
        headers = headers,
        exported_headers = exported_headers,
        raw_headers = raw_headers,
        public_include_directories = _compute_include_directories(),
        deps = deps,
        exported_deps = exported_deps,
        force_static = force_static,
        apple_sdks = apple_sdks,
        platforms = platforms,
        enable_static_variant = enable_static_variant,
        labels = list(labels),
        compiler_flags = select({
            "DEFAULT": compiler_flags
            + CXXFLAGS
            + select({
                "DEFAULT": [],
                "ovr_config//os:android": FBANDROID_CXXFLAGS,
                "ovr_config//os:iphoneos": FBOBJC_CXXFLAGS,
                "ovr_config//os:macos": FBOBJC_CXXFLAGS,
                "ovr_config//os:windows": WINDOWS_CLANG_CXX_FLAGS,
            }),
            "ovr_config//compiler:msvc": WINDOWS_MSVC_CXXFLAGS,
        }),
        windows_preferred_linkage = "static",
        visibility = kwargs.pop("visibility", ["PUBLIC"]),
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
        feature = Infra_Networking_Core,
        **(kwargs | _FBCODE_LIBRARY_KWARGS),
    )

def _convert_deps(deps, external_deps):
    return deps_map_utils.convert_to_fbsource_fp_deps(deps) + deps_map_utils.convert_to_fbsource_tp_deps(external_deps)

def _convert_deps_keep_fbcode(deps, external_deps):
    """Like `_convert_deps`, but keeps deps on fbcode-only projects.

    `convert_to_fbsource_fp_deps` drops a dep it has no xplat mapping for
    (e.g. `//common/init:init`). Rules that only build for FBCODE can take
    those as explicit `fbcode//` deps instead.
    """
    return selects.apply(deps, _keep_fbcode_deps) + deps_map_utils.convert_to_fbsource_tp_deps(external_deps)

def _keep_fbcode_deps(deps):
    converted = []
    for dep in deps:
        xplat_dep = deps_map_utils.convert_to_fbsource_fp_deps([dep])
        if xplat_dep:
            converted.extend(xplat_dep)
        elif not is_fbcode_compatible():
            # The fbcode cell is not usable on this host; the rule cannot
            # build here anyway, so do not leave an unresolvable dep behind.
            continue
        elif dep.startswith("//"):
            converted.append("fbcode" + dep)
        else:
            converted.append(dep)
    return converted

def mvfst_cpp_test(name, deps = (), external_deps = (), header_namespace = None, supports_static_listing = None, **kwargs):
    if supports_static_listing != None:
        # `cpp_unittest`-only: route it to the fbcode arm.
        kwargs["fbcode_supports_static_listing"] = supports_static_listing
    mvfst_cxx_test(
        name,
        deps = _convert_deps_keep_fbcode(deps, external_deps),
        header_namespace = header_namespace or _compute_header_namespace(),
        visibility = ["PUBLIC"],
        **kwargs,
    )

def mvfst_cxx_test(name, srcs, headers = [], deps = [], header_namespace = "", platforms = (CXX, FBCODE), **kwargs):
    fb_xplat_cxx_test(
        name = name,
        srcs = srcs,
        headers = headers,
        header_namespace = header_namespace,
        deps = deps,
        platforms = platforms,
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
        **kwargs,
    )

def mvfst_cpp_binary(name, deps = (), external_deps = (), header_namespace = None, **kwargs):
    mvfst_cxx_binary(
        name, deps = _convert_deps(deps, external_deps), header_namespace = header_namespace or _compute_header_namespace(), visibility = ["PUBLIC"], **kwargs
    )

# Binaries build for the host (CXX) and, as `<name>Fbcode`, for fbcode, which
# is what the `fbcode//quic/...` aliases resolve to.
DEFAULT_BINARY_PLATFORMS = (CXX, FBCODE)

def mvfst_cxx_binary(name, srcs, headers = [], compatible_with = [], compiler_flags = [], deps = [], header_namespace = "", platforms = DEFAULT_BINARY_PLATFORMS, **kwargs):
    fb_xplat_cxx_binary(
        name = name,
        srcs = srcs,
        headers = headers,
        header_namespace = header_namespace,
        compatible_with = compatible_with,
        compiler_flags = compiler_flags + CXXFLAGS,
        deps = deps,
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
        platforms = platforms,
        **kwargs,
    )

def mvfst_cpp_benchmark(name, deps = (), external_deps = (), header_namespace = None, **kwargs):
    # Benchmarks are only built for fbcode, like `cpp_benchmark` used to.
    mvfst_cxx_binary(
        name,
        deps = _convert_deps_keep_fbcode(deps, external_deps),
        header_namespace = header_namespace or _compute_header_namespace(),
        platforms = (FBCODE,),
        visibility = ["PUBLIC"],
        **kwargs,
    )

def mvfst_fbcode_only(rule, name, deps = (), external_deps = (), exported_deps = (), exported_external_deps = (), **kwargs):
    """Declares a target that only builds for fbcode, for deps on projects that
    have no xplat mirror (`fbcode//xsec_crypto`).

    Nothing is declared on a host that cannot build fbcode; the matching
    `fbcode//quic/...` alias is marked incompatible there with
    `fbcode_only_target_compatible_with()`. Deps without an xplat mapping are
    kept as explicit `fbcode//` targets instead of being dropped.
    """
    if not is_fbcode_compatible():
        return
    if rule == mvfst_cpp_library:
        mvfst_cxx_library(
            name,
            exported_headers = kwargs.pop("headers", ()),
            headers = kwargs.pop("private_headers", ()),
            deps = _convert_deps_keep_fbcode(deps, external_deps),
            exported_deps = _convert_deps_keep_fbcode(exported_deps, exported_external_deps),
            header_namespace = _compute_header_namespace(),
            platforms = (FBCODE,),
            visibility = ["PUBLIC"],
            **kwargs,
        )
    elif rule == mvfst_cpp_test:
        mvfst_cpp_test(name, deps = deps, external_deps = external_deps, platforms = (FBCODE,), **kwargs)
    else:
        fail("mvfst_fbcode_only: unsupported rule for {}".format(name))

def mu_cxx_library(
    name,
    srcs = (),
    headers = (),
    exported_headers = (),
    raw_headers = (),
    deps = (),
    exported_deps = (),
    force_static = False,
    apple_sdks = None,
    platforms = None,
    enable_static_variant = False,
    labels = (),
    fbandroid_labels = (),
    fbobjc_labels = (),
    header_namespace = "",
    **kwargs,
):
    """Translate a simpler declartion into the more complete library target"""

    # Set default platform settings. `()` means empty, whereas None
    # means default
    if apple_sdks == None:
        apple_sdks = DEFAULT_APPLE_SDKS
    if platforms == None:
        platforms = DEFAULT_PLATFORMS

    # We use gflags on fbcode platforms, which don't mix well when mixing static
    # and dynamic linking.
    force_static = select({
        "DEFAULT": select({
            "DEFAULT": force_static,
            "ovr_config//runtime:fbcode": False,
        }),
        "ovr_config//build_mode:arvr_mode[enabled]": force_static,
    })

    fb_xplat_cxx_library(
        name = name,
        srcs = srcs,
        header_namespace = header_namespace,
        headers = headers,
        exported_headers = exported_headers,
        raw_headers = raw_headers,
        public_include_directories = _compute_include_directories(),
        deps = deps,
        exported_deps = exported_deps,
        force_static = force_static,
        apple_sdks = apple_sdks,
        platforms = platforms,
        enable_static_variant = enable_static_variant,
        labels = list(labels),
        fbandroid_labels = list(fbandroid_labels),
        fbobjc_labels = list(fbobjc_labels),
        compiler_flags = select({
            "DEFAULT": kwargs.pop("compiler_flags", []) + CXXFLAGS,
            "config//compiler:msvc": WINDOWS_MSVC_CXXFLAGS,
        }),
        windows_compiler_flags = kwargs.pop("windows_compiler_flags", []) + CXXFLAGS + WINDOWS_CLANG_CXX_FLAGS,
        fbobjc_compiler_flags = kwargs.pop("fbobjc_compiler_flags", []) + FBOBJC_CXXFLAGS,
        fbcode_compiler_flags_override = kwargs.pop("fbcode_compiler_flags", []),
        fbandroid_compiler_flags = kwargs.pop("fbandroid_compiler_flags", []) + FBANDROID_CXXFLAGS,
        windows_preferred_linkage = "static",
        visibility = kwargs.pop("visibility", ["PUBLIC"]),
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
        feature = Infra_Networking_Core,
        **kwargs,
    )

def mu_cxx_test(name, srcs, raw_headers = [], deps = []):
    fb_xplat_cxx_test(
        name = name,
        srcs = srcs,
        raw_headers = raw_headers,
        include_directories = [
            "..",
        ],
        deps = deps,
        platforms = (CXX,),
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
    )

def mu_cxx_binary(name, srcs, raw_headers = [], deps = [], **kwargs):
    fb_xplat_cxx_binary(
        name = name,
        srcs = srcs,
        raw_headers = raw_headers,
        compiler_flags = kwargs.pop("compiler_flags", []) + CXXFLAGS,
        include_directories = [
            "..",
        ],
        deps = deps,
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
        platforms = (CXX,),
    )
