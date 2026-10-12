//! The viewer window: renders the remote canvas, forwards input and keeps
//! the host's virtual display sized to the window.

mod keymap;
mod render;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use winit::application::ApplicationHandler;
use winit::dpi::{LogicalSize, PhysicalPosition, PhysicalSize};
use winit::event::{ElementState, KeyEvent, MouseButton, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::keyboard::{KeyCode, ModifiersState, PhysicalKey};
use winit::platform::modifier_supplement::KeyEventExtModifierSupplement;
use winit::window::{CursorIcon, CustomCursor, Window, WindowId};

use crate::proto::messages::{BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, BTN_SCROLL_DOWN, BTN_SCROLL_UP, DisplayRequest};
use crate::session::{Config, CursorShape, Event, EventSink, Session};
use render::Renderer;

/// Settle time before asking the host to follow a window resize; each
/// request restarts the host's encoder.
const RESIZE_DEBOUNCE: Duration = Duration::from_millis(500);
/// Pixels of smooth scrolling per wheel tick.
const SCROLL_PIXELS_PER_TICK: f64 = 40.0;

pub struct Options {
    pub title: String,
    /// Initial window size in logical pixels.
    pub size: (u32, u32),
    /// Backing scale to request; `None` follows the window's scale factor.
    pub scale: Option<f64>,
    pub auto_resize: bool,
    pub swap_ctrl_cmd: bool,
}

struct ProxySink(EventLoopProxy<Event>);

impl EventSink for ProxySink {
    fn emit(&self, event: Event) {
        let _ = self.0.send_event(event);
    }
}

struct App {
    cfg: Config,
    opts: Options,
    proxy: EventLoopProxy<Event>,
    instance: wgpu::Instance,
    window: Option<Arc<Window>>,
    renderer: Option<Renderer>,
    session: Option<Session>,
    /// Error that ended the session, reported after the window closes.
    error: Option<String>,

    last_request: Option<DisplayRequest>,
    resize_due: Option<Instant>,

    cursor_pos: Option<PhysicalPosition<f64>>,
    buttons: u8,
    scroll_accum: f64,
    modifiers: ModifiersState,
    /// Keysym sent for each held physical key, so releases match presses
    /// even if modifiers changed in between.
    pressed: HashMap<KeyCode, u32>,
    cursors: HashMap<u32, CustomCursor>,
}

impl App {
    fn display_request(&self, size: PhysicalSize<u32>, scale_factor: f64) -> DisplayRequest {
        let scale = self.opts.scale.unwrap_or(if scale_factor >= 1.5 { 2.0 } else { 1.0 });
        DisplayRequest::for_pixels(size.width, size.height, scale)
    }

    fn send_resize(&mut self) {
        let (Some(w), Some(s)) = (&self.window, &self.session) else { return };
        let req = self.display_request(w.inner_size(), w.scale_factor());
        if self.last_request != Some(req) {
            self.last_request = Some(req);
            s.resize(req);
        }
    }

    /// Window position → canvas pixel, clamped to the canvas.
    fn canvas_point(&self, pos: PhysicalPosition<f64>) -> Option<(u16, u16)> {
        let r = self.renderer.as_ref()?;
        let vp = r.viewport()?;
        let (iw, ih) = r.image_size()?;
        let x = ((pos.x as f32 - vp.x) / vp.w * iw as f32).clamp(0.0, iw.saturating_sub(1) as f32);
        let y = ((pos.y as f32 - vp.y) / vp.h * ih as f32).clamp(0.0, ih.saturating_sub(1) as f32);
        Some((x as u16, y as u16))
    }

    fn send_pointer(&self, buttons: u8) {
        if let (Some(s), Some(pos)) = (&self.session, self.cursor_pos)
            && let Some((x, y)) = self.canvas_point(pos) {
                s.pointer(buttons, x, y);
            }
    }

    fn scroll(&mut self, ticks: f64) {
        self.scroll_accum += ticks;
        while self.scroll_accum.abs() >= 1.0 {
            let up = self.scroll_accum > 0.0;
            self.scroll_accum -= if up { 1.0 } else { -1.0 };
            // Each press/release pair is one wheel click on the host.
            self.send_pointer(self.buttons | if up { BTN_SCROLL_UP } else { BTN_SCROLL_DOWN });
            self.send_pointer(self.buttons);
        }
    }

    fn key(&mut self, ev: &KeyEvent) {
        let Some(s) = &self.session else { return };
        let PhysicalKey::Code(code) = ev.physical_key else { return };
        let down = ev.state == ElementState::Pressed;
        if !down {
            if let Some(ks) = self.pressed.remove(&code) {
                s.key(false, ks);
            }
            return;
        }
        let m = self.modifiers;
        let shortcut = m.control_key() || m.alt_key() || m.super_key();
        let logical = if shortcut { ev.key_without_modifiers() } else { ev.logical_key.clone() };
        let Some(ks) = keymap::keysym(ev.physical_key, &logical, self.opts.swap_ctrl_cmd) else {
            return;
        };
        if let Some(prev) = self.pressed.insert(code, ks)
            && prev != ks {
                s.key(false, prev);
            }
        s.key(true, ks);
    }

    /// Releases everything we hold on the host, e.g. when focus is lost
    /// mid-shortcut and the release would never arrive.
    fn release_all(&mut self) {
        if let Some(s) = &self.session {
            for (_, ks) in self.pressed.drain() {
                s.key(false, ks);
            }
        }
        if self.buttons != 0 {
            self.buttons = 0;
            self.send_pointer(0);
        }
    }

    fn set_cursor(&mut self, el: &ActiveEventLoop, c: CursorShape) {
        let Some(w) = &self.window else { return };
        if let Some(cur) = self.cursors.get(&c.cache_id)
            && c.rgba.is_none() {
                w.set_cursor(cur.clone());
                return;
            }
        let Some(rgba) = c.rgba else {
            w.set_cursor(CursorIcon::Default);
            return;
        };
        if c.width == 0 || c.height == 0 {
            w.set_cursor_visible(false);
            return;
        }
        w.set_cursor_visible(true);
        let hot = (c.hotspot.0.min(c.width - 1), c.hotspot.1.min(c.height - 1));
        match CustomCursor::from_rgba(rgba.to_vec(), c.width, c.height, hot.0, hot.1) {
            Ok(src) => {
                let cur = el.create_custom_cursor(src);
                if self.cursors.len() >= 64 {
                    self.cursors.clear();
                }
                self.cursors.insert(c.cache_id, cur.clone());
                w.set_cursor(cur);
            }
            Err(e) => tracing::debug!("cursor image rejected: {e}"),
        }
    }

    fn fail(&mut self, el: &ActiveEventLoop, msg: String) {
        self.error = Some(msg);
        el.exit();
    }
}

impl ApplicationHandler<Event> for App {
    fn resumed(&mut self, el: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let attrs = Window::default_attributes()
            .with_title(format!("{} — connecting…", self.opts.title))
            .with_inner_size(LogicalSize::new(self.opts.size.0, self.opts.size.1));
        let window = match el.create_window(attrs) {
            Ok(w) => Arc::new(w),
            Err(e) => return self.fail(el, format!("creating window: {e}")),
        };
        match Renderer::new(&self.instance, window.clone()) {
            Ok(r) => self.renderer = Some(r),
            Err(e) => return self.fail(el, format!("{e:#}")),
        }
        let req = self.display_request(window.inner_size(), window.scale_factor());
        self.last_request = Some(req);
        self.window = Some(window);
        self.session = Some(Session::start(self.cfg.clone(), req, Arc::new(ProxySink(self.proxy.clone()))));
    }

    fn user_event(&mut self, el: &ActiveEventLoop, event: Event) {
        match event {
            Event::Connected => {
                if let Some(w) = &self.window {
                    w.set_title(&self.opts.title);
                }
                // The window may have been resized while connecting.
                if self.opts.auto_resize {
                    self.send_resize();
                }
            }
            Event::Frame => {
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
            }
            Event::Canvas { width, height } => {
                tracing::info!("canvas {width}x{height}");
                if let Some(r) = &mut self.renderer {
                    r.set_canvas(width, height);
                }
            }
            Event::Cursor(c) => self.set_cursor(el, c),
            Event::Closed(reason) => {
                self.error = reason;
                el.exit();
            }
        }
    }

    fn window_event(&mut self, el: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::CloseRequested => el.exit(),
            WindowEvent::Resized(size) => {
                if let Some(r) = &mut self.renderer {
                    r.resize(size.width, size.height);
                }
                if self.opts.auto_resize && size.width > 0 && size.height > 0 {
                    self.resize_due = Some(Instant::now() + RESIZE_DEBOUNCE);
                }
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
            }
            WindowEvent::ScaleFactorChanged { .. } => {
                if self.opts.auto_resize {
                    self.resize_due = Some(Instant::now() + RESIZE_DEBOUNCE);
                }
            }
            WindowEvent::RedrawRequested => {
                if let (Some(r), Some(s)) = (&mut self.renderer, &self.session) {
                    for (tile, pic) in s.frames().take() {
                        r.upload(tile, &pic);
                    }
                }
                if let Some(r) = &mut self.renderer {
                    r.render();
                }
            }
            WindowEvent::Focused(false) => self.release_all(),
            WindowEvent::ModifiersChanged(m) => self.modifiers = m.state(),
            WindowEvent::KeyboardInput { event, is_synthetic: false, .. } => self.key(&event),
            WindowEvent::CursorMoved { position, .. } => {
                self.cursor_pos = Some(position);
                self.send_pointer(self.buttons);
            }
            WindowEvent::MouseInput { state, button, .. } => {
                let bit = match button {
                    MouseButton::Left => BTN_LEFT,
                    MouseButton::Right => BTN_RIGHT,
                    MouseButton::Middle => BTN_MIDDLE,
                    _ => return,
                };
                match state {
                    ElementState::Pressed => self.buttons |= bit,
                    ElementState::Released => self.buttons &= !bit,
                }
                self.send_pointer(self.buttons);
            }
            WindowEvent::MouseWheel { delta, .. } => {
                let ticks = match delta {
                    MouseScrollDelta::LineDelta(_, y) => y as f64,
                    MouseScrollDelta::PixelDelta(p) => p.y / SCROLL_PIXELS_PER_TICK,
                };
                self.scroll(ticks);
            }
            _ => {}
        }
    }

    fn about_to_wait(&mut self, el: &ActiveEventLoop) {
        match self.resize_due {
            Some(due) if Instant::now() >= due => {
                self.resize_due = None;
                self.send_resize();
                el.set_control_flow(ControlFlow::Wait);
            }
            Some(due) => el.set_control_flow(ControlFlow::WaitUntil(due)),
            None => el.set_control_flow(ControlFlow::Wait),
        }
    }

    fn exiting(&mut self, _el: &ActiveEventLoop) {
        if let Some(s) = self.session.take() {
            s.shutdown();
        }
    }
}

/// Runs the viewer until the window closes or the session ends.
pub fn run(cfg: Config, opts: Options) -> Result<()> {
    let event_loop = EventLoop::<Event>::with_user_event().build()?;
    let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::new_with_display_handle_from_env(Box::new(
        event_loop.owned_display_handle(),
    )));
    let mut app = App {
        cfg,
        opts,
        proxy: event_loop.create_proxy(),
        instance,
        window: None,
        renderer: None,
        session: None,
        error: None,
        last_request: None,
        resize_due: None,
        cursor_pos: None,
        buttons: 0,
        scroll_accum: 0.0,
        modifiers: ModifiersState::empty(),
        pressed: HashMap::new(),
        cursors: HashMap::new(),
    };
    event_loop.run_app(&mut app)?;
    if let Some(s) = app.session.take() {
        s.shutdown();
    }
    match app.error {
        Some(e) => anyhow::bail!(e),
        None => Ok(()),
    }
}
