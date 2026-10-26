//! Mouse-wheel scrolling that eases out instead of stopping dead: each notch adds distance, released over about
//! 0.3 s. Touchpads (point deltas) pass through as they are.

use eframe::egui::{Context, Event, Modifiers, MouseWheelUnit, RawInput, TouchPhase, Vec2};

/// How far a wheel notch scrolls, in points: about three lines, as on KDE and GNOME (egui's own is 40).
const NOTCH: f32 = 60.0;
/// The glide's time constant in seconds: 95 % of a notch is out after three of these.
const TAU: f32 = 0.09;

#[derive(Default)]
pub struct Glide {
    /// distance still to scroll
    left: Vec2,
    /// a glide was started (egui saw a Start) and not yet ended
    active: bool,
    modifiers: Modifiers,
}

impl Glide {
    /// Takes the wheel notches out of `input` and puts back this frame's share of the distance, as touchpad-style
    /// point scrolling (Start, Move…, End), which egui applies as it comes.
    pub fn hook(&mut self, ctx: &Context, input: &mut RawInput) {
        let mut fresh = Vec2::ZERO;
        input.events.retain(|e| match e {
            Event::MouseWheel {
                unit: MouseWheelUnit::Line,
                delta,
                modifiers,
                ..
            } => {
                fresh += *delta * NOTCH;
                self.modifiers = *modifiers;
                false
            }
            _ => true,
        });
        // turning the wheel the other way stops the glide at once
        if fresh.dot(self.left) < 0.0 {
            self.left = Vec2::ZERO;
        }
        self.left += fresh;
        let wheel = |delta, phase| Event::MouseWheel {
            unit: MouseWheelUnit::Point,
            delta,
            phase,
            modifiers: self.modifiers,
        };
        if self.left == Vec2::ZERO {
            if std::mem::take(&mut self.active) {
                input.events.push(wheel(Vec2::ZERO, TouchPhase::End));
            }
            return;
        }
        if !std::mem::replace(&mut self.active, true) {
            input.events.push(wheel(Vec2::ZERO, TouchPhase::Start));
        }
        let dt = input.predicted_dt.clamp(1.0 / 240.0, 1.0 / 20.0);
        let step = if self.left.length() < 0.5 {
            self.left
        } else {
            self.left * (1.0 - (-dt / TAU).exp())
        };
        self.left -= step;
        input.events.push(wheel(step, TouchPhase::Move));
        ctx.request_repaint();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eframe::egui::vec2;

    fn wheel(unit: MouseWheelUnit, delta: Vec2) -> Event {
        Event::MouseWheel {
            unit,
            delta,
            phase: TouchPhase::Move,
            modifiers: Modifiers::NONE,
        }
    }

    /// Runs `frames` frames at 60 fps, `first` going into the first; returns each frame's events after the hook.
    fn run(glide: &mut Glide, first: Vec<Event>, frames: usize) -> Vec<Vec<Event>> {
        let ctx = eframe::egui::Context::default();
        let mut events = first;
        (0..frames)
            .map(|_| {
                let mut input = RawInput {
                    events: std::mem::take(&mut events),
                    predicted_dt: 1.0 / 60.0,
                    ..Default::default()
                };
                glide.hook(&ctx, &mut input);
                input.events
            })
            .collect()
    }

    fn moved(events: &[Event]) -> f32 {
        events
            .iter()
            .map(|e| {
                if let Event::MouseWheel {
                    unit: MouseWheelUnit::Point,
                    delta,
                    ..
                } = e
                {
                    delta.y
                } else {
                    0.0
                }
            })
            .sum()
    }

    #[test]
    fn a_notch_glides_its_distance_out_over_a_few_frames() {
        let mut g = Glide::default();
        let frames = run(
            &mut g,
            vec![wheel(MouseWheelUnit::Line, vec2(0.0, -1.0))],
            40,
        );
        let steps: Vec<f32> = frames.iter().map(|f| moved(f)).collect();
        assert!(
            (steps.iter().sum::<f32>() + NOTCH).abs() < 0.01,
            "the whole notch arrives: {steps:?}"
        );
        assert!(steps[0].abs() < NOTCH / 2.0, "not all at once");
        assert!(
            steps.windows(2).take(10).all(|w| w[1].abs() <= w[0].abs()),
            "it slows down: {steps:?}"
        );
        assert!(steps[12].abs() > 0.0, "still moving 0.2 s later");
        assert!(
            frames.iter().flatten().any(|e| matches!(
                e,
                Event::MouseWheel {
                    phase: TouchPhase::End,
                    ..
                }
            )),
            "and then it stops"
        );
    }

    #[test]
    fn touchpad_scrolling_passes_through() {
        let mut g = Glide::default();
        let pad = wheel(MouseWheelUnit::Point, vec2(0.0, -3.0));
        let frames = run(&mut g, vec![pad.clone()], 3);
        assert_eq!(frames[0], vec![pad]);
        assert!(frames[1].is_empty() && frames[2].is_empty());
    }
}
