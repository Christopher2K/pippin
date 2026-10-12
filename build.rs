//! Generates FFI bindings for the small slice of FFmpeg (libavcodec /
//! libavutil) the video decoder uses. Bindings are produced against the
//! installed headers so struct layouts always match the linked libraries.

use std::env;
use std::path::PathBuf;

fn main() {
    let mut include_paths = Vec::new();
    for lib in ["libavcodec", "libavutil"] {
        let found = pkg_config::Config::new()
            .probe(lib)
            .unwrap_or_else(|e| panic!("pkg-config could not find {lib}: {e}"));
        include_paths.extend(found.include_paths);
    }

    let mut builder = bindgen::Builder::default()
        .header_contents(
            "ffmpeg.h",
            "#include <libavcodec/avcodec.h>\n\
             #include <libavutil/hwcontext.h>\n\
             #include <libavutil/imgutils.h>\n\
             #include <libavutil/pixdesc.h>\n\
             #include <libavutil/log.h>\n",
        )
        .allowlist_function("avcodec_.*")
        .allowlist_function("av_packet_.*")
        .allowlist_function("av_frame_.*")
        .allowlist_function("av_hwdevice_.*")
        .allowlist_function("av_hwframe_transfer_data")
        .allowlist_function("av_buffer_.*")
        .allowlist_function("av_new_packet")
        .allowlist_function("av_malloc")
        .allowlist_function("av_mallocz")
        .allowlist_function("av_free")
        .allowlist_function("av_strerror")
        .allowlist_function("av_get_pix_fmt_name")
        .allowlist_function("av_log_set_level")
        .allowlist_type("AVPixelFormat")
        .allowlist_type("AVHWDeviceType")
        .allowlist_type("AVColorSpace")
        .allowlist_type("AVColorRange")
        .allowlist_var("AV_INPUT_BUFFER_PADDING_SIZE")
        .allowlist_var("AV_CODEC_FLAG_.*")
        .allowlist_var("AV_CODEC_FLAG2_.*")
        .allowlist_var("FF_THREAD_.*")
        .allowlist_var("AV_LOG_.*")
        .allowlist_var("AV_FRAME_FLAG_.*")
        .allowlist_var("AVERROR_.*")
        .constified_enum_module("AVPixelFormat")
        .constified_enum_module("AVHWDeviceType")
        .constified_enum_module("AVCodecID")
        .layout_tests(false)
        .generate_comments(false);
    for p in &include_paths {
        builder = builder.clang_arg(format!("-I{}", p.display()));
    }
    let bindings = builder.generate().expect("bindgen failed for FFmpeg headers");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("ffmpeg.rs");
    bindings.write_to_file(out).expect("writing FFmpeg bindings");
}
