# macshare

A native Linux client for macOS Screen Sharing's high-performance mode:
HEVC 4:4:4 video over SRTP, with the Mac's virtual display sized to the
client window.

## Features

- **High-performance mode.** Uses the same protocol as Apple's Screen
  Sharing app: SRP authentication, an encrypted control channel, and tiled
  HEVC over SRTP.
- **Auto-resolution.** The host's virtual display follows the window. After
  you stop resizing for 500 ms, the client asks the Mac for a display whose
  backing pixels match the window's physical pixels (capped at 3840×2160).
  The default scale is 2× (Retina) on HiDPI screens and 1× otherwise; use
  `--scale` to override. `--no-auto-resize` turns this off.
- **Clipboard.** Plain text is shared both ways. Host changes are pushed to
  the client; local changes are picked up by polling. Works on X11 and on
  Wayland via `wlr-data-control` / `ext-data-control`.
- **Native cursor.** The Mac's cursor shapes become local cursors, so
  pointer movement has no round-trip lag.
- **Hardware decoding.** CUDA (NVDEC), then VAAPI, then multithreaded
  software decoding. The stream is HEVC 4:4:4, which NVIDIA (Turing and
  later) and Intel (Ice Lake and later) decode in hardware; most AMD GPUs
  only decode 4:2:0. A hardware decoder that rejects the stream, emits
  nothing, or leaves libavcodec decoding in software is dropped for the
  next one. `--decoder auto|cuda|vaapi|software` picks one (`--no-hw` is
  `software`); `--vaapi-device` or `MACSHARE_VAAPI_DEVICE` picks the render
  node, e.g. `/dev/dri/renderD129`. Decoded planes go to the GPU as-is
  (NV12/NV24 and packed VUYX included) and are converted in the shader.
  `--codec h264` asks for H.264 4:2:0 in one tile instead, which more GPUs
  decode in hardware, at some cost in colour fidelity.
- **Loss recovery.** NACKs (retried once), with frames that have holes held
  briefly for the retransmission; keyframe requests, long-term-reference
  acks, and stall detection. `--hold auto` (default) stops holding once 20
  holds in a row go unfilled, since a host that doesn't retransmit makes
  each hold pure delay; `on`/`off` fix it. `--after-loss idr` (default) drops
  pictures until the next keyframe, freezing the picture; `conceal` keeps
  decoding what arrived, so it keeps moving but smeared until then.

## Experiments

`--stats-json stats.jsonl` appends one JSON object per second: the
operating point and what the host answered (canvas, LTR, per-tile picture
rate), packet and byte rates, per-tile loss before and after repair and
jitter, NACKs and how fast retransmissions arrive, holds, keyframe requests
by kind and by cause, keyframe sizes, recovery time per loss outage, frozen
and concealed time, decode times, presented frames and round trip. Each field is
documented in `src/session/metrics.rs`.

For switching levers mid-session without a GUI, set
`MACSHARE_CONTROL_FIFO=/tmp/macshare.ctl` (created as a FIFO if missing) and
write commands to it, e.g. `echo 'hold off' > /tmp/macshare.ctl`:
`render_scale 1|0.5`, `fps 60|30`, `recovery fir|pli|fir+pli`,
`hold auto|on|off`, `ltr on|off`, `after_loss idr|conceal`, `keyframe`
(ask for one now) and `restart` (reconnect with the current settings; with
`--no-reconnect` it exits instead). `recovery` (the keyframe request kind;
default fir+pli), `ltr` (long-term references; default on, always off with `--codec h264`) and `fps`
(default 60) have no command-line flags: they are experiment knobs that
made no measurable difference on a lossy link, because the Mac doesn't
retransmit. `recovery`, `hold` and `after_loss` apply at once;
`render_scale` re-requests the display like a resize; `fps` and `ltr`
re-offer the media session on the open connection.

## Requirements

- FFmpeg development libraries (`libavcodec`, `libavutil`) and `clang`
  (for bindgen) at build time.
- A Vulkan, GL, or other wgpu-supported GPU.
- Optional, for hardware decoding: an FFmpeg built with CUDA/NVDEC (NVIDIA
  driver) and/or VAAPI support, plus a VAAPI driver: `intel-media-driver`
  on Intel, Mesa's `radeonsi` on AMD, or `libva-nvidia-driver` on NVIDIA.
  `vainfo` (from `libva-utils`) lists what the driver decodes; look for
  `VAProfileHEVCMain444`.
- On the Mac: System Settings → General → Sharing → Screen Sharing enabled
  for the account you log in with.
- UDP ports 5900 and 5901 free locally. The host sends media to them.
- A large socket receive buffer. Video bursts overflow the kernel default:

  ```sh
  sudo sysctl -w net.core.rmem_max=33554432
  ```

## Usage

```sh
cargo build --release
./target/release/macshare my-mac.local -u alice          # prompts for password
MACSHARE_PASSWORD=... ./target/release/macshare 10.0.0.5 -u alice --session alt
pass show mac | ./target/release/macshare my-mac.local -u alice --password-stdin
```

The password is taken from `--password`/`MACSHARE_PASSWORD`, then
`--password-stdin`, then the desktop keyring (Secret Service, keyed by
`user@host:port`), then an interactive prompt. Saving is opt-in: right after the password prompt you are asked
`Save password to keyring? [y/N]` (it is stored only once the Mac accepts it), and `--save-password` saves any working
password without asking. A stored password the host rejects is removed so the
next run prompts.
`--forget-password` deletes the stored entry and exits.

Without a terminal (e.g. launched from a `.desktop` file), a missing host,
user or password is asked for in a small connect dialog instead; the host and
user are prefilled from the command line. A password already in the keyring
skips the dialog. Its "Save password in keyring" box is off by default and
replaces the terminal `[y/N]` question. A rejected password brings the dialog
back with an error. `--dialog` always shows it.

`--session share` (default) shares the logged-in console user's screen.
`--session alt` logs in to a separate virtual session as the authenticating
user.

Keyboard: Super is ⌘ Command and Alt is ⌥ Option. Use `--swap-ctrl-cmd` to
make Ctrl act as Command. Keys are sent as the characters your layout
produces.

Logging: `-v` for debug, `-vv` for trace, or `RUST_LOG=...`. Passwords and
clipboard contents are never logged.

## Architecture

```
src/
  proto/      control-channel protocol (pure, no I/O except handshake)
    auth        SRP-3072 / RSA1 authentication
    handshake   connect → session select → encryption → media offer/answer
    record      AES-CBC + HMAC record layer for the control channel
    messages    RFB message builders and framebuffer-update parsing
    offers      0x1c media offer and answer parsing
    clipboard   0x1f rich pasteboard messages
  rtp/        media transport (pure)
    srtp        SRTP/SRTCP (AES-CM + HMAC-SHA1-80)
    rtcp        RR/SR, FIR/PLI, NACK, LTR acks
    stats       RFC 3550 receiver statistics (loss, jitter) for RRs
    hevc        RFC 7798 depayloading with DONL
    assembler   access-unit assembly, SSRC → tile mapping
  video/      libavcodec decoder (bindgen FFI, CUDA, VAAPI or software)
  session/    threads tying it together
    mod         Session handle, shared state, startup
    control     encrypted TCP reader: cursor, layout, clipboard, answers
    media       video-rx, decoder, ctrl-rx, feedback threads
  clipboard   local ⇄ host text mirroring
  ui/         winit window, wgpu YUV renderer, input and keymap
```

The session uses plain threads and channels, not an async runtime. The UI
receives `session::Event`s through the winit event loop. Decoded pictures go
through a latest-picture-per-tile `FrameStore`, so a slow display drops
frames instead of building a queue.

## Limitations

- No audio. The offer sets the audio gate off, so the host only sends a
  silent keepalive.
- Text-only clipboard. No images or files.
- IPv4 only. One client per machine, because the media ports are fixed.
- Only tested by unit tests and interop vectors so far; not yet run against
  a real Mac.

## Tests

```sh
cargo test
```

`src/interop_tests.rs` checks byte-for-byte compatibility with vectors
generated by the iShareScreen reference implementation. Decoder tests run
real HEVC streams through every backend that opens here and check the
output matches software decoding. The last two streams are optional; a
hardware backend must refuse them rather than show garbage:

```sh
ffmpeg -f lavfi -i testsrc2=size=1280x720 -frames:v 30 -c:v libx265 -pix_fmt yuv444p -f hevc /tmp/t444.hevc
ffmpeg -f lavfi -i testsrc2=size=1280x720 -frames:v 30 -c:v libx265 -pix_fmt yuv420p -f hevc /tmp/t420.hevc
ffmpeg -f lavfi -i testsrc2=size=1280x720 -frames:v 30 -c:v libx265 -pix_fmt yuv444p10le -f hevc /tmp/t444p10.hevc
ffmpeg -f lavfi -i testsrc2=size=8448x256 -frames:v 30 -c:v libx265 -pix_fmt yuv420p -f hevc /tmp/twide.hevc
ffmpeg -f lavfi -i testsrc2=size=1280x720 -frames:v 30 -c:v libx264 -pix_fmt yuv420p -f h264 /tmp/t264.h264
MACSHARE_TEST_HEVC_DIR=/tmp cargo test --release -- --ignored --skip bench
```

## Credits

macshare builds directly on
[iShareScreen](https://github.com/renegadelink/iShareScreen) by
[renegadelink](https://github.com/renegadelink). Their work reverse-engineered
Apple's high-performance Screen Sharing protocol. Everything macshare knows
about the wire protocol comes from studying their implementation and
documentation. That includes the handshake and authentication, the media
offer and answer, tiled HEVC over SRTP, the keyframe and long-term-reference
feedback the host responds to, the cursor and display-layout encodings, and
the clipboard format. Many of their empirical findings appear here as
constants and comments. The interop tests use vectors generated by their
code.

macshare is a separate implementation in Rust with its own architecture.
Bugs in it are ours, not theirs.

## License

AGPL-3.0-or-later, the same license as iShareScreen. See [LICENSE](LICENSE).
