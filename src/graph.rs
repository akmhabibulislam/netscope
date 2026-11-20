use gtk4::cairo::Context;
use gtk4::prelude::*;
use gtk4::DrawingArea;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

pub type BandwidthGraph = BandwidthWaveform;

#[derive(Clone)]
pub struct BandwidthWaveform {
    pub area: DrawingArea,
    rx_history: Arc<Mutex<VecDeque<f64>>>,
    tx_history: Arc<Mutex<VecDeque<f64>>>,
}

impl BandwidthWaveform {
    pub fn widget(&self) -> &DrawingArea {
        &self.area
    }
    pub fn new() -> Self {
        let area = DrawingArea::new();
        area.set_content_height(140);
        area.set_hexpand(true);

        // Pre-fill 60 intervals
        let mut initial_rx = VecDeque::with_capacity(60);
        let mut initial_tx = VecDeque::with_capacity(60);
        for _ in 0..60 {
            initial_rx.push_back(0.0);
            initial_tx.push_back(0.0);
        }

        let rx_history = Arc::new(Mutex::new(initial_rx));
        let tx_history = Arc::new(Mutex::new(initial_tx));

        let rx_clone = rx_history.clone();
        let tx_clone = tx_history.clone();

        area.set_draw_func(move |_, cr, width, height| {
            Self::draw_chart(cr, width as f64, height as f64, &rx_clone, &tx_clone);
        });

        Self {
            area,
            rx_history,
            tx_history,
        }
    }

    pub fn push_sample(&self, rx_bps: f64, tx_bps: f64) {
        if let Ok(mut rx) = self.rx_history.lock() {
            if rx.len() >= 60 {
                rx.pop_front();
            }
            rx.push_back(rx_bps);
        }

        if let Ok(mut tx) = self.tx_history.lock() {
            if tx.len() >= 60 {
                tx.pop_front();
            }
            tx.push_back(tx_bps);
        }

        self.area.queue_draw();
    }

    fn draw_chart(
        cr: &Context,
        width: f64,
        height: f64,
        rx_history: &Arc<Mutex<VecDeque<f64>>>,
        tx_history: &Arc<Mutex<VecDeque<f64>>>,
    ) {
        let rx: Vec<f64> = rx_history
            .lock()
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default();
        let tx: Vec<f64> = tx_history
            .lock()
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default();

        if rx.is_empty() || tx.is_empty() {
            return;
        }

        // Deep obsidian background
        cr.set_source_rgb(0.043, 0.051, 0.067); // #0B0D11
        let _ = cr.paint();

        // Subtle architectural grid
        cr.set_source_rgba(0.12, 0.14, 0.19, 0.5);
        cr.set_line_width(1.0);
        for i in 1..4 {
            let y = (height / 4.0) * (i as f64);
            cr.move_to(0.0, y);
            cr.line_to(width, y);
            let _ = cr.stroke();
        }

        let max_val = rx
            .iter()
            .chain(tx.iter())
            .cloned()
            .fold(100_000.0, f64::max);
        let n = rx.len().max(1);
        let step_x = width / (n as f64 - 1.0).max(1.0);

        // Download: Emerald Green (#10B981) with Bézier spline smoothing
        cr.set_source_rgba(0.06, 0.72, 0.51, 0.95);
        cr.set_line_width(2.0);
        Self::draw_spline(cr, &rx, step_x, height, max_val);
        let _ = cr.stroke();

        // Upload: Accent Blue (#3E7BFA) with Bézier spline smoothing
        cr.set_source_rgba(0.24, 0.48, 0.98, 0.95);
        cr.set_line_width(2.0);
        Self::draw_spline(cr, &tx, step_x, height, max_val);
        let _ = cr.stroke();

        // Dynamic Peak Indicator Badge
        let peak_mbps = (max_val * 8.0) / 1_000_000.0;
        cr.set_source_rgba(0.65, 0.70, 0.80, 0.85);
        cr.set_font_size(10.0);
        cr.move_to(width - 90.0, 16.0);
        let _ = cr.show_text(&format!("Peak: {:.1} Mbps", peak_mbps));
    }

    /// Renders points as a continuous cubic Bézier curve for smooth waveform visuals
    fn draw_spline(cr: &Context, data: &[f64], step_x: f64, height: f64, max_val: f64) {
        if data.is_empty() {
            return;
        }

        let points: Vec<(f64, f64)> = data
            .iter()
            .enumerate()
            .map(|(i, &val)| {
                let x = i as f64 * step_x;
                let y = height - (val / max_val) * (height - 25.0) - 8.0;
                (x, y)
            })
            .collect();

        cr.move_to(points[0].0, points[0].1);
        for i in 0..points.len() - 1 {
            let p0 = if i > 0 { points[i - 1] } else { points[i] };
            let p1 = points[i];
            let p2 = points[i + 1];
            let p3 = if i + 2 < points.len() {
                points[i + 2]
            } else {
                p2
            };

            // Catmull-Rom to Cubic Bézier control points
            let cp1_x = p1.0 + (p2.0 - p0.0) / 6.0;
            let cp1_y = p1.1 + (p2.1 - p0.1) / 6.0;
            let cp2_x = p2.0 - (p3.0 - p1.0) / 6.0;
            let cp2_y = p2.1 - (p3.1 - p1.1) / 6.0;

            cr.curve_to(cp1_x, cp1_y, cp2_x, cp2_y, p2.0, p2.1);
        }
    }
}

impl Default for BandwidthWaveform {
    fn default() -> Self {
        Self::new()
    }
}
