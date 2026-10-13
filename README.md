# pippin

pippin is a high-performance remote desktop client for the high performance
mode of macOS Screen Sharing. Apple normally only offers that mode between
two Macs; pippin brings it to Linux.

There's nothing to install on the Mac. Turn on Screen Sharing and connect,
and you get sharp HEVC 4:4:4 video with the Mac's display resized to fit
your window, plus the Mac's sound. Text and images copy and paste in both
directions, the cursor is drawn locally so it never lags behind your
mouse, and video is decoded on the GPU whenever possible.

## Quick start

High-performance mode needs an Apple silicon Mac running macOS Sonoma or
later. On the Mac, turn on System Settings → General → Sharing → Screen
Sharing. Then install pippin on Linux and run:

```sh
pippin my-mac.local -u alice
```

## Installing

On Arch, install [`pippin`](https://aur.archlinux.org/packages/pippin)
(latest release) or [`pippin-git`](https://aur.archlinux.org/packages/pippin-git)
(latest commit) from the AUR:

```sh
yay -S pippin
```

Everywhere else, install with cargo. You'll need Rust 1.95 or newer
(distro packages are often older; use [rustup](https://rustup.rs)), plus
clang, pkg-config, FFmpeg's development headers and ALSA:

```sh
# Debian 13 / Ubuntu 24.04
sudo apt install build-essential pkg-config clang libclang-dev libavcodec-dev libavutil-dev libasound2-dev
# Fedora
sudo dnf install gcc pkgconf-pkg-config clang clang-devel libavcodec-free-devel libavutil-free-devel alsa-lib-devel

cargo install --locked --git https://github.com/jonesy827/pippin
```

cargo installs only the binary. To launch pippin from your desktop's app
menu, also install the desktop entry and icon from a checkout of this repo:

```sh
install -Dm644 assets/pippin.desktop ~/.local/share/applications/pippin.desktop
install -Dm644 assets/pippin.svg ~/.local/share/icons/hicolor/scalable/apps/pippin.svg
```

To run it you'll need a GPU that wgpu supports (Vulkan or GL), and UDP
ports 5900 and 5901 free. For sound, install
libfdk-aac (`pacman -S libfdk-aac`, `apt install libfdk-aac2` or
`dnf install fdk-aac`). Without it, pippin runs fine but silently.

## Passwords

pippin checks these places for your password, in order:

1. `--password` or the `PIPPIN_PASSWORD` environment variable
2. stdin, if you pass `--password-stdin`
3. your desktop keyring
4. a prompt

```sh
pass show mac | ./target/release/pippin my-mac.local -u alice --password-stdin
```

If you typed the password at a prompt, pippin asks whether to save it to
the keyring (or saves it straight away with `--save-password`). It won't
ask if no keyring is running. `--forget-password` removes a saved password.

When there's no terminal, for example when launched from a `.desktop` file,
pippin shows a small connect dialog instead of prompting. `--dialog`
shows it even from a terminal.

## Options

| Option | |
|---|---|
| `--session share\|alt` | Share the logged-in user's screen (default), or log in to a separate session |
| `--scale N` | Display scale. Defaults to 2× on HiDPI screens and 1× otherwise |
| `--no-auto-resize` | Keep the Mac's display at a fixed size instead of following the window |
| `--render-scale 0.5` | On a 2× window, stream a quarter of the pixels: slightly softer text for much less bandwidth |
| `--decoder auto\|cuda\|vaapi\|software` | Choose the video decoder. `--vaapi-device` picks the render node |
| `--after-loss idr\|conceal` | After packet loss, freeze until the next keyframe (default), or keep going with a smeared picture |
| `--no-audio` | Don't play the Mac's sound, and ask the Mac not to send it |
| `--swap-ctrl-cmd` | Use Ctrl as ⌘. By default Super is ⌘ and Alt is ⌥ |
| `-v`, `-vv` | Debug or trace logging. Passwords and clipboard contents are never logged |

## Hardware decoding

The Mac only sends HEVC 4:4:4, which not every GPU can decode. NVIDIA
Turing or newer (through CUDA) and Intel Ice Lake or newer (through VAAPI)
can. AMD GPUs can't, so pippin falls back to software decoding there; it
works fine but uses more CPU. To check your VAAPI driver, look for
`VAProfileHEVCMain444` in the output of `vainfo`.

By default pippin tries CUDA first, then VAAPI, then software, moving on
to the next if one fails.

## Slow and lossy networks

The Mac never resends lost video packets, so each lost packet means
waiting for a whole new keyframe. At 1% packet loss the picture is frozen
about half the time, and none of the protocol's settings made a difference
in our testing.

Two options do help:

- `--render-scale 0.5` uses much less bandwidth and makes keyframes
  smaller.
- `--after-loss conceal` keeps the picture moving after a loss. It looks
  smeared until the next keyframe arrives, but it isn't frozen.

## 4K

When you switch to 4K, the decoder can take a few seconds to catch up.
In the meantime incoming video piles up in the kernel (we've measured
around 670 KB). If your system still has the default UDP receive buffer
limit, raise it so frames aren't dropped:

```sh
sudo sysctl -w net.core.rmem_max=8388608
```

## Limitations

- Copy and paste works for text and images, but not files.
- Linux only, on Wayland or X11.
- IPv4 only, and only one copy of pippin per machine, because the media
  ports are fixed.

## Development

```sh
cargo test
```

`src/interop_tests.rs` checks the wire format byte for byte against
vectors from the reference implementation. The decoder tests are marked
`--ignored` because they need sample HEVC streams in
`PIPPIN_TEST_HEVC_DIR`. You can make these with ffmpeg's `testsrc2` and
`libx265`; `src/video/decoder.rs` lists the files it expects.

For network experiments:

- `--stats-json FILE` writes a line of stats every second. The fields are
  described in `src/session/metrics.rs`.
- Set `PIPPIN_CONTROL_FIFO=/tmp/pippin.ctl` to change settings while
  a session is running, e.g. `echo 'render_scale 0.5' > /tmp/pippin.ctl`.
  The commands are `render_scale`, `after_loss`, `hold`, `recovery`, `ltr`,
  `fps`, `keyframe` and `restart`, and they're documented in
  `src/session/operating.rs`.

The AUR packages live in `packaging/aur/`. After tagging a release, bump
`pkgver` in `packaging/aur/pippin/PKGBUILD`, then run `updpkgsums` and
`makepkg --printsrcinfo > .SRCINFO` before pushing it to the AUR.

## Credits

pippin stands on the shoulders of
[iShareScreen](https://github.com/renegadelink/iShareScreen), which 
reverse-engineered Apple's high-performance Screen Sharing protocol. 
pippin is a separate implementation written in Rust.

## License

AGPL-3.0-or-later, the same as iShareScreen. See [LICENSE](LICENSE).
