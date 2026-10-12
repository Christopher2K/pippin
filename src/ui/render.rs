//! Draws the decoded canvas: three R8 planes converted to RGB in a
//! fragment shader, letterboxed into the window.

use std::sync::Arc;

use anyhow::{Context, Result};
use winit::window::Window;

use crate::video::decoder::{Picture, PlaneRef};

const SHADER: &str = r#"
@group(0) @binding(0) var y_tex: texture_2d<f32>;
@group(0) @binding(1) var u_tex: texture_2d<f32>;
@group(0) @binding(2) var v_tex: texture_2d<f32>;
@group(0) @binding(3) var samp: sampler;

struct Out {
    @builtin(position) pos: vec4<f32>,
    @location(0) uv: vec2<f32>,
};

// One triangle covering the viewport.
@vertex
fn vs(@builtin(vertex_index) i: u32) -> Out {
    let p = vec2<f32>(f32((i << 1u) & 2u), f32(i & 2u));
    var o: Out;
    o.pos = vec4<f32>(p * 2.0 - 1.0, 0.0, 1.0);
    o.uv = vec2<f32>(p.x, 1.0 - p.y);
    return o;
}

// BT.709, full range.
fn rgb_at(i: Out) -> vec4<f32> {
    let y = textureSample(y_tex, samp, i.uv).r;
    let cb = textureSample(u_tex, samp, i.uv).r - 0.5;
    let cr = textureSample(v_tex, samp, i.uv).r - 0.5;
    let rgb = vec3<f32>(
        y + 1.5748 * cr,
        y - 0.187324 * cb - 0.468124 * cr,
        y + 1.8556 * cb,
    );
    return vec4<f32>(clamp(rgb, vec3<f32>(0.0), vec3<f32>(1.0)), 1.0);
}

@fragment
fn fs(i: Out) -> @location(0) vec4<f32> {
    return rgb_at(i);
}

// The last picture, dimmed while the session is reconnecting.
@fragment
fn fs_dim(i: Out) -> @location(0) vec4<f32> {
    let c = rgb_at(i);
    return vec4<f32>(c.rgb * 0.35, 1.0);
}
"#;

struct Planes {
    width: u32,
    height: u32,
    chroma: (u32, u32),
    textures: [wgpu::Texture; 3],
    bind_group: wgpu::BindGroup,
}

/// Where the canvas lands in the window, in physical pixels.
#[derive(Clone, Copy, Debug, Default)]
pub struct Viewport {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

pub struct Renderer {
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    config: wgpu::SurfaceConfiguration,
    view_format: wgpu::TextureFormat,
    pipeline: wgpu::RenderPipeline,
    dim_pipeline: wgpu::RenderPipeline,
    dimmed: bool,
    layout: wgpu::BindGroupLayout,
    sampler: wgpu::Sampler,
    planes: Option<Planes>,
    /// Canvas size announced by the host; tiles stack into this.
    canvas: Option<(u32, u32)>,
}

impl Renderer {
    pub fn new(instance: &wgpu::Instance, window: Arc<Window>) -> Result<Self> {
        let size = window.inner_size();
        let surface = instance.create_surface(window).context("creating surface")?;
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: Some(&surface),
            ..Default::default()
        }))
        .context("no GPU adapter for this window")?;
        tracing::info!("GPU: {} ({:?})", adapter.get_info().name, adapter.get_info().backend);
        let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
            label: Some("macshare"),
            required_limits: wgpu::Limits::downlevel_defaults().using_resolution(adapter.limits()),
            ..Default::default()
        }))
        .context("creating GPU device")?;

        let caps = surface.get_capabilities(&adapter);
        // An 8-bit format; float formats would be treated as linear light.
        let format = caps
            .formats
            .iter()
            .copied()
            .find(|f| {
                matches!(f.remove_srgb_suffix(), wgpu::TextureFormat::Bgra8Unorm | wgpu::TextureFormat::Rgba8Unorm)
            })
            .unwrap_or(caps.formats[0]);
        // The shader outputs gamma-encoded RGB already; render through a
        // non-sRGB view so it isn't encoded twice.
        let view_format = format.remove_srgb_suffix();
        let present_mode = if caps.present_modes.contains(&wgpu::PresentMode::Mailbox) {
            wgpu::PresentMode::Mailbox
        } else {
            wgpu::PresentMode::Fifo
        };
        let config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format,
            width: size.width.max(1),
            height: size.height.max(1),
            present_mode,
            desired_maximum_frame_latency: 1,
            alpha_mode: caps.alpha_modes[0],
            color_space: wgpu::SurfaceColorSpace::Auto,
            view_formats: if view_format != format { vec![view_format] } else { vec![] },
        };
        surface.configure(&device, &config);

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("yuv"),
            source: wgpu::ShaderSource::Wgsl(SHADER.into()),
        });
        let tex_entry = |binding| wgpu::BindGroupLayoutEntry {
            binding,
            visibility: wgpu::ShaderStages::FRAGMENT,
            ty: wgpu::BindingType::Texture {
                sample_type: wgpu::TextureSampleType::Float { filterable: true },
                view_dimension: wgpu::TextureViewDimension::D2,
                multisampled: false,
            },
            count: None,
        };
        let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("planes"),
            entries: &[
                tex_entry(0),
                tex_entry(1),
                tex_entry(2),
                wgpu::BindGroupLayoutEntry {
                    binding: 3,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
            ],
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("yuv"),
            bind_group_layouts: &[Some(&layout)],
            immediate_size: 0,
        });
        let make_pipeline = |fs| device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some(fs),
            layout: Some(&pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: Some("vs"),
                compilation_options: Default::default(),
                buffers: &[],
            },
            primitive: wgpu::PrimitiveState::default(),
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: Some(fs),
                compilation_options: Default::default(),
                targets: &[Some(view_format.into())],
            }),
            multiview_mask: None,
            cache: None,
        });
        let pipeline = make_pipeline("fs");
        let dim_pipeline = make_pipeline("fs_dim");
        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("planes"),
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..Default::default()
        });
        Ok(Self {
            surface,
            device,
            queue,
            config,
            view_format,
            pipeline,
            dim_pipeline,
            dimmed: false,
            layout,
            sampler,
            planes: None,
            canvas: None,
        })
    }

    pub fn resize(&mut self, width: u32, height: u32) {
        if width == 0 || height == 0 {
            return;
        }
        self.config.width = width;
        self.config.height = height;
        self.surface.configure(&self.device, &self.config);
    }

    pub fn set_canvas(&mut self, width: u32, height: u32) {
        self.canvas = Some((width, height));
        if self.planes.as_ref().is_some_and(|p| p.width != width || p.height != height) {
            // Recreated at the new size by the next picture.
            self.planes = None;
        }
    }

    /// Darkens the canvas, e.g. while the session is down.
    pub fn set_dimmed(&mut self, dimmed: bool) {
        self.dimmed = dimmed;
    }

    /// Size of the drawn image in stream pixels (the pointer coordinate space).
    pub fn image_size(&self) -> Option<(u32, u32)> {
        self.planes.as_ref().map(|p| (p.width, p.height)).or(self.canvas)
    }

    fn make_planes(&self, width: u32, height: u32, chroma: (u32, u32)) -> Planes {
        let tex = |label, w: u32, h: u32| {
            let t = self.device.create_texture(&wgpu::TextureDescriptor {
                label: Some(label),
                size: wgpu::Extent3d { width: w, height: h, depth_or_array_layers: 1 },
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format: wgpu::TextureFormat::R8Unorm,
                usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
                view_formats: &[],
            });
            // Black until the first picture for each tile arrives.
            let fill = if label == "y" { 0x00 } else { 0x80 };
            self.queue.write_texture(
                t.as_image_copy(),
                &vec![fill; (w * h) as usize],
                wgpu::TexelCopyBufferLayout { offset: 0, bytes_per_row: Some(w), rows_per_image: None },
                wgpu::Extent3d { width: w, height: h, depth_or_array_layers: 1 },
            );
            t
        };
        let textures = [tex("y", width, height), tex("u", chroma.0, chroma.1), tex("v", chroma.0, chroma.1)];
        let views: Vec<_> = textures.iter().map(|t| t.create_view(&Default::default())).collect();
        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("planes"),
            layout: &self.layout,
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: wgpu::BindingResource::TextureView(&views[0]) },
                wgpu::BindGroupEntry { binding: 1, resource: wgpu::BindingResource::TextureView(&views[1]) },
                wgpu::BindGroupEntry { binding: 2, resource: wgpu::BindingResource::TextureView(&views[2]) },
                wgpu::BindGroupEntry { binding: 3, resource: wgpu::BindingResource::Sampler(&self.sampler) },
            ],
        });
        Planes { width, height, chroma, textures, bind_group }
    }

    /// Copies one tile's picture into the canvas textures.
    pub fn upload(&mut self, tile: usize, pic: &Picture) {
        if pic.width == 0 || pic.height == 0 {
            return;
        }
        let tile = tile as u32;
        let height = match self.canvas {
            Some((_, h)) => h,
            None => pic.height * (tile + 1),
        };
        let chroma_h = (height as u64 * pic.chroma_height as u64).div_ceil(pic.height as u64) as u32;
        let chroma = (pic.chroma_width, chroma_h);
        let fits = self
            .planes
            .as_ref()
            .is_some_and(|p| p.width == pic.width && p.height == height && p.chroma == chroma);
        if !fits {
            tracing::debug!("canvas textures {}x{} (chroma {}x{})", pic.width, height, chroma.0, chroma.1);
            self.planes = Some(self.make_planes(pic.width, height, chroma));
        }
        let planes = self.planes.as_ref().unwrap();
        let write = |t: &wgpu::Texture, plane: PlaneRef, w: u32, h: u32, tex_h: u32| {
            let y0 = tile * h;
            if y0 >= tex_h {
                return;
            }
            let rows = h.min(tex_h - y0);
            self.queue.write_texture(
                wgpu::TexelCopyTextureInfo {
                    texture: t,
                    mip_level: 0,
                    origin: wgpu::Origin3d { x: 0, y: y0, z: 0 },
                    aspect: wgpu::TextureAspect::All,
                },
                &plane.data[..((rows - 1) * plane.stride + w) as usize],
                wgpu::TexelCopyBufferLayout { offset: 0, bytes_per_row: Some(plane.stride), rows_per_image: None },
                wgpu::Extent3d { width: w, height: rows, depth_or_array_layers: 1 },
            );
        };
        write(&planes.textures[0], pic.plane(0), pic.width, pic.height, planes.height);
        write(&planes.textures[1], pic.plane(1), pic.chroma_width, pic.chroma_height, planes.chroma.1);
        write(&planes.textures[2], pic.plane(2), pic.chroma_width, pic.chroma_height, planes.chroma.1);
    }

    /// The letterboxed rectangle the canvas occupies.
    pub fn viewport(&self) -> Option<Viewport> {
        let (iw, ih) = self.image_size()?;
        let (ww, wh) = (self.config.width as f32, self.config.height as f32);
        let s = (ww / iw as f32).min(wh / ih as f32);
        let (w, h) = (iw as f32 * s, ih as f32 * s);
        Some(Viewport { x: ((ww - w) / 2.0).floor(), y: ((wh - h) / 2.0).floor(), w, h })
    }

    pub fn render(&mut self) {
        let frame = match self.surface.get_current_texture() {
            wgpu::CurrentSurfaceTexture::Success(f) | wgpu::CurrentSurfaceTexture::Suboptimal(f) => f,
            wgpu::CurrentSurfaceTexture::Outdated | wgpu::CurrentSurfaceTexture::Lost => {
                self.surface.configure(&self.device, &self.config);
                return;
            }
            _ => return,
        };
        let view = frame.texture.create_view(&wgpu::TextureViewDescriptor {
            format: Some(self.view_format),
            ..Default::default()
        });
        let mut enc = self.device.create_command_encoder(&Default::default());
        {
            let mut pass = enc.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("canvas"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    depth_slice: None,
                    resolve_target: None,
                    ops: wgpu::Operations { load: wgpu::LoadOp::Clear(wgpu::Color::BLACK), store: wgpu::StoreOp::Store },
                })],
                ..Default::default()
            });
            if let (Some(p), Some(vp)) = (&self.planes, self.viewport())
                && vp.w >= 1.0 && vp.h >= 1.0 {
                    pass.set_viewport(vp.x, vp.y, vp.w, vp.h, 0.0, 1.0);
                    pass.set_pipeline(if self.dimmed { &self.dim_pipeline } else { &self.pipeline });
                    pass.set_bind_group(0, &p.bind_group, &[]);
                    pass.draw(0..3, 0..1);
                }
        }
        self.queue.submit([enc.finish()]);
        self.queue.present(frame);
    }
}
