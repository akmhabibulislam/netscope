use gtk4::cairo::Context;
use gtk4::prelude::*;
use gtk4::DrawingArea;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone)]
pub struct BandwidthGraph {
    drawing_area: DrawingArea,
    rx_history: Rc<RefCell<Vec<f64>>>,
    tx_history: Rc<RefCell<Vec<f64>>>,
}

impl BandwidthGraph {
    pub fn new() -> Self {
        let drawing_area = DrawingArea::new();
        drawing_area.set_content_height(160);
        drawing_area.set_hexpand(true);
        drawing_area.add_css_class("card");

        let rx_history = Rc::new(RefCell::new(vec![0.0; 60]));
        let tx_history = Rc::new(RefCell::new(vec![0.0; 60]));

        let rx_clone = rx_history.clone();
        let tx_clone = tx_history.clone();

        drawing_area.set_draw_func(move |_area, cr, width, height| {
            Self::draw_graph(cr, width as f64, height as f64, &rx_clone.borrow(), &tx_clone.borrow());
        });

        Self {
            drawing_area,
            rx_history,
            tx_history,
        }
    }

    pub fn widget(&self) -> &DrawingArea {
        &self.drawing_area
    }

    pub fn push_sample(&self, rx_bps: f64, tx_bps: f64) {
        {
            let mut rx = self.rx_history.borrow_mut();
            if rx.len() >= 60 {
                rx.remove(0);
            }
            rx.push(rx_bps);

            let mut tx = self.tx_history.borrow_mut();
            if tx.len() >= 60 {
                tx.remove(0);
            }
            tx.push(tx_bps);
        }
        self.drawing_area.queue_draw();
    }

    fn draw_graph(cr: &Context, width: f64, height: f64, rx: &[f64], tx: &[f64]) {
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

        let max_val = rx.iter().chain(tx.iter()).cloned().fold(100_000.0, f64::max);
        let n = rx.len().max(1);
        let step_x = width / (n as f64 - 1.0).max(1.0);

        // Download: Emerald Green (#10B981)
        cr.set_source_rgba(0.06, 0.72, 0.51, 0.95);
        cr.set_line_width(2.0);
        for (i, &val) in rx.iter().enumerate() {
            let x = i as f64 * step_x;
            let y = height - (val / max_val) * (height - 25.0) - 8.0;
            if i == 0 {
                cr.move_to(x, y);
            } else {
                cr.line_to(x, y);
            }
        }
        let _ = cr.stroke();

        // Upload: Accent Blue (#3E7BFA)
        cr.set_source_rgba(0.24, 0.48, 0.98, 0.95);
        cr.set_line_width(2.0);
        for (i, &val) in tx.iter().enumerate() {
            let x = i as f64 * step_x;
            let y = height - (val / max_val) * (height - 25.0) - 8.0;
            if i == 0 {
                cr.move_to(x, y);
            } else {
                cr.line_to(x, y);
            }
        }
        let _ = cr.stroke();

        // Status Header & Metrics
        cr.set_source_rgb(0.60, 0.64, 0.71);
        cr.set_font_size(11.0);
        cr.move_to(12.0, 20.0);
        let max_kbps = max_val / 8000.0;
        let _ = cr.show_text(&format!("Peak Bandwidth: {:.1} KB/s   ● Download   ● Upload", max_kbps));
    }
}
