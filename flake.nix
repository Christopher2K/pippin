{
  description = "Linux client for macOS high-performance Screen Sharing";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "pippin";
            version = "0.1.0";

            src = ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            nativeBuildInputs = with pkgs; [
              pkg-config
              clang # bindgen needs clang to parse the FFmpeg headers
              makeWrapper
            ];

            buildInputs = with pkgs; [
              ffmpeg # libavcodec + libavutil
              alsa-lib # cpal audio
              libxkbcommon
            ];

            env.LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";

            # Libraries loaded at runtime via dlopen (wgpu/winit/wl-clipboard-rs).
            postInstall = ''
              install -Dm644 assets/pippin.desktop -t $out/share/applications
              install -Dm644 assets/pippin.svg -t $out/share/icons/hicolor/scalable/apps
              wrapProgram $out/bin/pippin \
                --prefix LD_LIBRARY_PATH : ${pkgs.lib.makeLibraryPath (with pkgs; [
                  vulkan-loader
                  libGL
                  wayland
                  libxkbcommon
                ])}
            '';

            meta = with pkgs.lib; {
              description = "Linux client for macOS high-performance Screen Sharing";
              homepage = "https://github.com/jonesy827/pippin";
              license = licenses.agpl3Plus;
              mainProgram = "pippin";
              platforms = platforms.linux;
            };
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              cargo
              rustc
              clippy
              rustfmt
              rust-analyzer

              pkg-config
              clang
              ffmpeg
              alsa-lib
              libxkbcommon
            ];

            env.LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";

            # Let wgpu/winit find GPU and windowing libraries in dev builds.
            env.LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (
              with pkgs;
              [
                vulkan-loader
                libGL
                wayland
                libxkbcommon
              ]
            );
          };
        }
      );
    };
}
