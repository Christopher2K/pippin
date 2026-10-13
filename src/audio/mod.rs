//! The Mac's sound: AAC-ELD decoding and playback.
//!
//! The session's `ctrl-rx` thread decodes each packet and pushes the PCM
//! into a [`Player`], which plays it on the default output device through
//! a small jitter buffer. The device is opened when sound starts and closed
//! after a few seconds of silence, since the host keeps sending silent
//! packets whenever nothing is playing.

pub mod aac;

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{FromSample, SampleFormat, SizedSample};
use crossbeam_channel::{Receiver, Sender};
use parking_lot::Mutex;

use aac::{CHANNELS, SAMPLE_RATE};

/// Audio buffered before playback starts or resumes after an underrun.
/// Covers network jitter and the gap between packets (10 ms each).
const TARGET: Duration = Duration::from_millis(40);
/// Above this much buffered audio, the excess is dropped so a stall never
/// replays late audio and clock drift between the Mac and the sound card
/// can't build up delay.
const MAX_BUFFERED: Duration = Duration::from_millis(100);
/// Close the device after this long without sound.
const IDLE_CLOSE: Duration = Duration::from_secs(5);
/// Device period we ask for: 10 ms.
const PERIOD_FRAMES: u32 = 480;

fn samples(d: Duration) -> usize {
    (d.as_micros() as usize * SAMPLE_RATE as usize / 1_000_000) * CHANNELS
}

/// Interleaved samples waiting to be played.
#[derive(Default)]
struct Jitter {
    queue: VecDeque<i16>,
    /// Playing (rather than refilling after an underrun).
    primed: bool,
    last_sound: Option<Instant>,
    underruns: u64,
    dropped: u64,
}

impl Jitter {
    fn push(&mut self, pcm: &[i16]) {
        self.queue.extend(pcm);
        if self.queue.len() > samples(MAX_BUFFERED) {
            let excess = self.queue.len() - samples(TARGET);
            self.queue.drain(..excess);
            self.dropped += excess as u64;
        }
    }

    fn pull<T: SizedSample + FromSample<i16>>(&mut self, out: &mut [T]) {
        if !self.primed && self.queue.len() >= samples(TARGET) {
            self.primed = true;
        }
        let mut n = 0;
        if self.primed {
            n = out.len().min(self.queue.len());
            for (o, s) in out.iter_mut().zip(self.queue.drain(..n)) {
                *o = T::from_sample(s);
            }
            if n < out.len() {
                self.primed = false;
                self.underruns += 1;
            }
        }
        out[n..].fill(T::EQUILIBRIUM);
    }
}

struct Inner {
    jitter: Mutex<Jitter>,
    /// The output thread has (or is opening) a stream.
    running: AtomicBool,
    wake: Sender<()>,
}

/// Plays decoded audio. Cheap to clone; shared by every session of a run so
/// a reconnect keeps the same output thread.
#[derive(Clone)]
pub struct Player {
    inner: Arc<Inner>,
}

impl Player {
    /// Starts the output thread if audio can work at all: libfdk-aac loads
    /// and there is an output device.
    pub fn new() -> Result<Self> {
        aac::available()?;
        cpal::default_host().default_output_device().context("no audio output device")?;
        let (wake, rx) = crossbeam_channel::bounded(1);
        let inner = Arc::new(Inner { jitter: Mutex::default(), running: AtomicBool::new(false), wake });
        let weak = Arc::downgrade(&inner);
        std::thread::Builder::new()
            .name("audio-out".into())
            .spawn(move || output_thread(weak, rx))
            .context("spawning audio thread")?;
        Ok(Self { inner })
    }

    /// Queues one decoded packet of interleaved stereo.
    pub fn push(&self, pcm: &[i16]) {
        // The host sends digital silence whenever nothing plays; it's
        // indistinguishable from the underrun fill, so skip it.
        if pcm.iter().all(|&s| s == 0) {
            return;
        }
        {
            let mut j = self.inner.jitter.lock();
            j.push(pcm);
            j.last_sound = Some(Instant::now());
        }
        if !self.inner.running.swap(true, Ordering::AcqRel) {
            let _ = self.inner.wake.try_send(());
        }
    }

    /// Drops anything buffered, e.g. when the session it came from ends.
    pub fn flush(&self) {
        let mut j = self.inner.jitter.lock();
        j.queue.clear();
        j.primed = false;
    }
}

/// Opens the device when sound starts and closes it once it stops. Owns
/// the stream because cpal streams can't move between threads. Exits when
/// the last [`Player`] is dropped.
fn output_thread(inner: std::sync::Weak<Inner>, wake: Receiver<()>) {
    let mut warned = false;
    while wake.recv().is_ok() {
        let Some(shared) = inner.upgrade() else { return };
        match open_stream(shared.clone()) {
            Ok(stream) => {
                tracing::debug!("audio output opened");
                loop {
                    std::thread::sleep(Duration::from_millis(250));
                    let j = shared.jitter.lock();
                    if j.last_sound.is_none_or(|t| t.elapsed() > IDLE_CLOSE) {
                        tracing::debug!("audio output closed ({} underruns, {} samples dropped)", j.underruns, j.dropped);
                        break;
                    }
                }
                drop(stream);
            }
            Err(e) if !warned => {
                tracing::warn!("no sound: {e:#}");
                warned = true;
            }
            Err(e) => tracing::debug!("audio output: {e:#}"),
        }
        {
            let mut j = shared.jitter.lock();
            j.queue.clear();
            j.primed = false;
        }
        shared.running.store(false, Ordering::Release);
        // Pushes that saw `running` still set while we were closing didn't
        // wake us; their sound would sit unplayed until the next one.
        if shared.jitter.lock().last_sound.is_some_and(|t| t.elapsed() < IDLE_CLOSE)
            && !shared.running.swap(true, Ordering::AcqRel)
        {
            let _ = shared.wake.try_send(());
        }
    }
}

fn open_stream(inner: Arc<Inner>) -> Result<cpal::Stream> {
    let device = cpal::default_host().default_output_device().context("no audio output device")?;
    let rate = cpal::SampleRate(SAMPLE_RATE);
    let supported = device
        .supported_output_configs()?
        .filter(|c| c.channels() as usize == CHANNELS && c.min_sample_rate() <= rate && rate <= c.max_sample_rate())
        .max_by_key(|c| match c.sample_format() {
            SampleFormat::F32 => 2,
            SampleFormat::I16 => 1,
            _ => 0,
        })
        .context("the output device doesn't do 48 kHz stereo")?
        .with_sample_rate(rate);
    let mut config = supported.config();
    if let cpal::SupportedBufferSize::Range { min, max } = supported.buffer_size() {
        config.buffer_size = cpal::BufferSize::Fixed(PERIOD_FRAMES.clamp(*min, *max));
    }
    let stream = match supported.sample_format() {
        SampleFormat::F32 => build::<f32>(&device, &config, inner)?,
        SampleFormat::I16 => build::<i16>(&device, &config, inner)?,
        f => return Err(anyhow!("unsupported sample format {f}")),
    };
    stream.play()?;
    Ok(stream)
}

fn build<T: SizedSample + FromSample<i16>>(
    device: &cpal::Device,
    config: &cpal::StreamConfig,
    inner: Arc<Inner>,
) -> Result<cpal::Stream> {
    Ok(device.build_output_stream(
        config,
        move |out: &mut [T], _| inner.jitter.lock().pull(out),
        |e| tracing::debug!("audio stream: {e}"),
        None,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_for_target_then_plays() {
        let mut j = Jitter::default();
        let packet = vec![1000i16; 480 * CHANNELS];
        let mut out = vec![0f32; 240 * CHANNELS];
        j.push(&packet);
        j.pull(&mut out);
        assert!(out.iter().all(|&s| s == 0.0), "plays before the buffer reaches the target");
        for _ in 0..3 {
            j.push(&packet);
        }
        j.pull(&mut out);
        assert!(out.iter().all(|&s| s > 0.0));
    }

    #[test]
    fn underrun_refills_before_resuming() {
        let mut j = Jitter::default();
        let packet = vec![1000i16; 480 * CHANNELS];
        for _ in 0..4 {
            j.push(&packet);
        }
        let mut out = vec![0f32; 2000 * CHANNELS];
        j.pull(&mut out);
        assert_eq!(j.underruns, 1);
        assert!(out[..1920 * CHANNELS].iter().all(|&s| s > 0.0));
        assert!(out[1920 * CHANNELS..].iter().all(|&s| s == 0.0));
        j.push(&packet);
        j.pull(&mut out[..2]);
        assert_eq!(out[0], 0.0, "resumed with less than the target buffered");
    }

    #[test]
    fn backlog_is_trimmed_to_target() {
        let mut j = Jitter::default();
        let packet = vec![1i16; 480 * CHANNELS];
        for _ in 0..11 {
            j.push(&packet);
        }
        assert_eq!(j.queue.len(), samples(TARGET));
    }
}

#[cfg(test)]
mod device_tests {
    use super::*;

    /// Needs a sound device; plays inaudible (±1 LSB) samples.
    #[test]
    #[ignore]
    fn plays_on_default_device() {
        let p = Player::new().unwrap();
        let packet: Vec<i16> = (0..480 * CHANNELS).map(|i| if i % 4 < 2 { 1 } else { -1 }).collect();
        for _ in 0..100 {
            p.push(&packet);
            std::thread::sleep(Duration::from_millis(10));
        }
        let j = p.inner.jitter.lock();
        assert!(p.inner.running.load(Ordering::Acquire));
        assert!(j.queue.len() <= samples(MAX_BUFFERED), "device isn't consuming: {}", j.queue.len());
        eprintln!("buffered {} samples, {} underruns, {} dropped", j.queue.len(), j.underruns, j.dropped);
    }
}
