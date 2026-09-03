//! Render both tray renderings with the mock-up's data to PNGs for a visual
//! check: `cargo run --example widget_probe` → target/widget-{dark,light}.png
//! (the macOS menu-bar pill, at 2× pixels; the menu bar shows it at half
//! size) and target/badge-{16,32}-{dark,light}.png (the Windows
//! notification-area badge, at both sizes a tray asks for).

use tickover::menubar::{render, render_badge, ProviderRow, WindowStat};

fn rows() -> Vec<ProviderRow> {
    vec![
        ProviderRow {
            label: "Cx".into(),
            five_hour: Some(WindowStat {
                used_percent: 9.0,
                time_progress: Some(0.55),
            }),
            weekly: Some(WindowStat {
                used_percent: 32.0,
                time_progress: Some(0.83),
            }),
        },
        ProviderRow {
            label: "Cl".into(),
            five_hour: Some(WindowStat {
                used_percent: 94.0,
                time_progress: Some(0.55),
            }),
            weekly: Some(WindowStat {
                used_percent: 23.0,
                time_progress: Some(0.6),
            }),
        },
    ]
}

fn main() {
    for (dark, path) in [
        (true, "target/widget-dark.png"),
        (false, "target/widget-light.png"),
    ] {
        match render(&rows(), dark, 2.0) {
            Some(img) => {
                img.save(path).expect("save png");
                println!("{}x{} -> {path}", img.width(), img.height());
            }
            None => eprintln!("no system monospace font found — widget unavailable"),
        }
    }
    // The badge draws no text, so unlike the pill it has nothing to fail on
    // for want of a font — a `None` here can only mean there were no rows.
    // Both the sizes a notification area actually asks for: 16 at 100%
    // scaling and 32 at 200%. The badge is drawn at whichever it is given
    // rather than resampled into it, so both are worth looking at.
    for px in [16u32, 32] {
        for (dark, name) in [(true, "dark"), (false, "light")] {
            let path = format!("target/badge-{px}-{name}.png");
            if let Some(img) = render_badge(&rows(), dark, px) {
                img.save(&path).expect("save png");
                println!("{}x{} -> {path}", img.width(), img.height());
            }
        }
    }
}
