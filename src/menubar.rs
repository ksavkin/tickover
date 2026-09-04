//! Menu-bar widget renderer.
//!
//! Draws the compact quota widget shown next to the clock as one RGBA image
//! (macOS renders the tray icon at a fixed 18 pt height, so we rasterize at
//! 2× for retina and let AppKit scale it down):
//!
//! ```text
//! ⌾ Cx ▂▂ 91/68 · Cl ▂▂ 6/77
//! ```
//!
//! One line, at most two providers, joined by a middle dot. Per provider:
//! label, two stacked mini bars (5-hour on top, weekly below; fill = used,
//! tick = elapsed window time), then the `%used-5h/%used-week` pair, both
//! severity-coloured. Light and dark palettes follow the menu bar theme.
//!
//! Pure image code — no UI toolkit deps — so it lives in the library and is
//! unit-testable. Text is rasterized with the system monospace font; when no
//! font can be loaded `render` returns `None` and the caller falls back to a
//! plain-text tray title.

use std::sync::OnceLock;

use ab_glyph::{point, Font, FontVec, PxScale, ScaleFont};
use image::RgbaImage;

/// One quota window as shown in the widget.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowStat {
    pub used_percent: f64,
    /// Elapsed fraction of the window (0..1) for the playhead tick, if known.
    pub time_progress: Option<f32>,
}

/// One provider row ("Cx" / "Cl").
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderRow {
    pub label: String,
    pub five_hour: Option<WindowStat>,
    pub weekly: Option<WindowStat>,
}

// ── Palette ──────────────────────────────────────────────────────────────────

struct Palette {
    chip: [u8; 4],
    border: [u8; 4],
    ink: [u8; 4],
    faint: [u8; 4],
    track: [u8; 4],
    playhead: [u8; 4],
    ok: [u8; 4],
    warn: [u8; 4],
    crit: [u8; 4],
}

fn palette(dark: bool) -> Palette {
    if dark {
        Palette {
            chip: [0x14, 0x17, 0x1c, 0xff],
            border: [0x3a, 0x40, 0x4a, 0xff],
            ink: [0xe7, 0xea, 0xf0, 0xff],
            faint: [0x8f, 0x98, 0xa6, 0xff],
            track: [0x2f, 0x34, 0x3c, 0xff],
            playhead: [0xff, 0xff, 0xff, 0xff],
            ok: [0x3d, 0xdc, 0x97, 0xff],
            warn: [0xf4, 0xb7, 0x40, 0xff],
            crit: [0xf2, 0x6d, 0x6d, 0xff],
        }
    } else {
        Palette {
            chip: [0xf5, 0xf5, 0xf7, 0xff],
            border: [0xc9, 0xcc, 0xd2, 0xff],
            ink: [0x1c, 0x1e, 0x21, 0xff],
            faint: [0x6b, 0x73, 0x80, 0xff],
            // Dark track on the light chip too, as in the reference design.
            track: [0x2f, 0x34, 0x3c, 0xff],
            playhead: [0xff, 0xff, 0xff, 0xff],
            ok: [0x14, 0xb8, 0x77, 0xff],
            warn: [0xc9, 0x86, 0x0a, 0xff],
            crit: [0xe5, 0x48, 0x4d, 0xff],
        }
    }
}

/// The two percentages at which a window changes colour: amber from
/// [`WARN_AT`], red from [`CRIT_AT`].
///
/// Public, and the only Rust definition, because there was nearly a third: the
/// panel has its own copy in `ui/theme.slint` (`Theme.sev`) — Slint cannot read
/// a Rust constant, so that one is kept honest by
/// `the_panel_colours_at_the_same_two_numbers_this_module_does` below rather
/// than by the compiler. Public so anything else that needs to know where the
/// colour changes reads these instead of redefining the numbers.
pub const WARN_AT: f64 = 70.0;
/// See [`WARN_AT`].
pub const CRIT_AT: f64 = 90.0;

/// Which of the three bands a consumed percentage falls in. The colour is per
/// window and comes from that window's own number — nothing here aggregates.
///
/// An enum and not a `&'static str`: matching a string with a `_` arm is a
/// compiler that has stopped helping — rename `"crit"` in one place and
/// every window in the menu bar turns mint, quietly, with the build and
/// every test still green. Exhaustive matching is the whole point of having
/// a type here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Band {
    Ok,
    Warn,
    Crit,
}

impl Band {
    /// The band's short name, useful for logging or a diagnostic.
    pub fn as_str(self) -> &'static str {
        match self {
            Band::Ok => "ok",
            Band::Warn => "warn",
            Band::Crit => "crit",
        }
    }
}

/// See [`Band`].
fn severity_band(used: f64) -> Band {
    if used >= CRIT_AT {
        Band::Crit
    } else if used >= WARN_AT {
        Band::Warn
    } else {
        Band::Ok
    }
}

impl Palette {
    fn sev(&self, used: f64) -> [u8; 4] {
        match severity_band(used) {
            Band::Crit => self.crit,
            Band::Warn => self.warn,
            Band::Ok => self.ok,
        }
    }
}

// ── Font ─────────────────────────────────────────────────────────────────────

/// System monospace font, loaded once. `None` when no candidate exists.
fn font() -> Option<&'static FontVec> {
    static FONT: OnceLock<Option<FontVec>> = OnceLock::new();
    FONT.get_or_init(|| {
        let candidates: &[&str] = if cfg!(target_os = "macos") {
            &[
                "/System/Library/Fonts/Menlo.ttc",
                "/System/Library/Fonts/Monaco.ttf",
                "/System/Library/Fonts/SFNSMono.ttf",
            ]
        } else if cfg!(target_os = "windows") {
            &["C:\\Windows\\Fonts\\consola.ttf"]
        } else {
            &[
                "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
                "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
            ]
        };
        for path in candidates {
            if let Ok(bytes) = std::fs::read(path) {
                if let Ok(f) = FontVec::try_from_vec_and_index(bytes, 0) {
                    return Some(f);
                }
            }
        }
        None
    })
    .as_ref()
}

// ── Raster helpers ───────────────────────────────────────────────────────────

fn blend(img: &mut RgbaImage, x: i32, y: i32, c: [u8; 4], coverage: f32) {
    if x < 0 || y < 0 || x >= img.width() as i32 || y >= img.height() as i32 {
        return;
    }
    let a = coverage.clamp(0.0, 1.0) * (c[3] as f32 / 255.0);
    if a <= 0.0 {
        return;
    }
    let p = img.get_pixel_mut(x as u32, y as u32);
    for i in 0..3 {
        p[i] = (c[i] as f32 * a + p[i] as f32 * (1.0 - a)).round() as u8;
    }
    p[3] = (255.0 * a + p[3] as f32 * (1.0 - a)).round() as u8;
}

/// Anti-aliased rounded-rectangle fill (signed-distance coverage).
fn fill_rrect(img: &mut RgbaImage, x: f32, y: f32, w: f32, h: f32, r: f32, c: [u8; 4]) {
    let r = r.min(w / 2.0).min(h / 2.0).max(0.0);
    let (cx, cy) = (x + w / 2.0, y + h / 2.0);
    let (hx, hy) = (w / 2.0 - r, h / 2.0 - r);
    for py in y.floor() as i32..=(y + h).ceil() as i32 {
        for px in x.floor() as i32..=(x + w).ceil() as i32 {
            let dx = (px as f32 + 0.5 - cx).abs() - hx;
            let dy = (py as f32 + 0.5 - cy).abs() - hy;
            let outside = (dx.max(0.0).powi(2) + dy.max(0.0).powi(2)).sqrt();
            let inside = dx.max(dy).min(0.0);
            let dist = outside + inside - r;
            blend(img, px, py, c, 0.5 - dist);
        }
    }
}

fn text_width(f: &FontVec, px: f32, s: &str) -> f32 {
    let scaled = f.as_scaled(PxScale::from(px));
    let mut w = 0.0;
    let mut prev = None;
    for ch in s.chars() {
        let id = f.glyph_id(ch);
        if let Some(p) = prev {
            w += scaled.kern(p, id);
        }
        w += scaled.h_advance(id);
        prev = Some(id);
    }
    w
}

fn draw_text(
    img: &mut RgbaImage,
    f: &FontVec,
    px: f32,
    x: f32,
    baseline: f32,
    s: &str,
    c: [u8; 4],
) {
    let scaled = f.as_scaled(PxScale::from(px));
    let mut cursor = x;
    let mut prev = None;
    for ch in s.chars() {
        let id = f.glyph_id(ch);
        if let Some(p) = prev {
            cursor += scaled.kern(p, id);
        }
        let glyph = id.with_scale_and_position(PxScale::from(px), point(cursor, baseline));
        if let Some(og) = f.outline_glyph(glyph) {
            let b = og.px_bounds();
            og.draw(|gx, gy, cov| {
                blend(
                    img,
                    b.min.x as i32 + gx as i32,
                    b.min.y as i32 + gy as i32,
                    c,
                    cov,
                );
            });
        }
        cursor += scaled.h_advance(id);
        prev = Some(id);
    }
}

/// The gauge glyph from the tray template asset, tinted with `ink`.
fn draw_gauge(img: &mut RgbaImage, x: f32, y: f32, size: u32, ink: [u8; 4]) {
    static GAUGE: OnceLock<Option<RgbaImage>> = OnceLock::new();
    let Some(src) = GAUGE
        .get_or_init(|| {
            image::load_from_memory(include_bytes!("../assets/tray-icon-template@2x.png"))
                .ok()
                .map(|i| i.into_rgba8())
        })
        .as_ref()
    else {
        return;
    };
    let scaled = image::imageops::resize(src, size, size, image::imageops::FilterType::CatmullRom);
    for (sx, sy, p) in scaled.enumerate_pixels() {
        let cov = p[3] as f32 / 255.0;
        blend(img, x as i32 + sx as i32, y as i32 + sy as i32, ink, cov);
    }
}

// ── Widget ───────────────────────────────────────────────────────────────────

/// The pill shows how much of a window is USED — the same quantity as the
/// bar beside it, the caption in the panel and the severity colour. It used
/// to show what was left, so a glance at the menu bar and a glance at the
/// panel gave two different numbers for one window, and the bar and the
/// number next to it disagreed. Bare number — the `5h/wk` pair carries its
/// own separator.
fn used_num(w: &Option<WindowStat>) -> String {
    match w {
        Some(s) => format!("{:.0}", used_fraction(s) * 100.0),
        None => "--".to_string(),
    }
}

/// A window's used percentage as a 0..1 fraction, with anything the caller
/// could not have meant folded away: a percentage outside 0..100 (a provider
/// over its own limit, or a manifest reading the wrong field) and a
/// not-a-number. Everything drawn from a reading goes through here, so the
/// bar, the tick and the figure can never disagree with each other or ask for
/// a coordinate that isn't a number.
fn used_fraction(stat: &WindowStat) -> f32 {
    if !stat.used_percent.is_finite() {
        return 0.0;
    }
    (stat.used_percent.clamp(0.0, 100.0) / 100.0) as f32
}

/// The elapsed-time playhead as a 0..1 fraction, same treatment.
fn time_fraction(stat: &WindowStat) -> Option<f32> {
    stat.time_progress
        .filter(|t| t.is_finite())
        .map(|t| t.clamp(0.0, 1.0))
}

/// Cheap change-detection key: same key ⇒ the rendered image would be
/// identical (percent rounded, playhead in 2 % steps, theme).
pub fn cache_key(rows: &[ProviderRow], dark: bool) -> String {
    use std::fmt::Write;
    let mut k = format!("d{}", dark as u8);
    for r in rows {
        let _ = write!(k, ";{}", r.label);
        for w in [&r.five_hour, &r.weekly] {
            match w {
                Some(s) => {
                    let tick = time_fraction(s)
                        .map(|p| (p * 50.0).round() as i32)
                        .unwrap_or(-1);
                    let _ = write!(k, ",{:.0}:{}", used_fraction(s) * 100.0, tick);
                }
                None => k.push_str(",-"),
            }
        }
    }
    k
}

/// Poor-man's bold: draw twice with a small horizontal offset. Avoids
/// guessing face indices inside font collections.
fn draw_text_bold(
    img: &mut RgbaImage,
    f: &FontVec,
    px: f32,
    x: f32,
    baseline: f32,
    s: &str,
    c: [u8; 4],
) {
    draw_text(img, f, px, x, baseline, s, c);
    draw_text(img, f, px, x + px * 0.05, baseline, s, c);
}

/// Render the widget: a single-line pill
/// `⌾ Cx ▂▂ 91/68 · Cl ▂▂ 6/77` — per provider: label, two stacked mini
/// bars (5-hour on top, weekly below; fill = used, tick = elapsed time) and
/// the `%used-5h / %used-week` pair, each severity-coloured. `rows` beyond
/// the first two are dropped — the pill shows only the first two providers,
/// by order, and has no room for more.
/// `scale` is the pixel density (2.0 for retina). Returns `None` when there
/// is nothing to draw or no font is available.
pub fn render(rows: &[ProviderRow], dark: bool, scale: f32) -> Option<RgbaImage> {
    let rows: Vec<&ProviderRow> = rows.iter().take(2).collect();
    if rows.is_empty() {
        return None;
    }
    let f = font()?;
    let p = palette(dark);
    // Every dimension below is `scale` times a constant, and the result sizes
    // an allocation. A scale of zero would ask the image crate for a 0×0
    // buffer; a negative or non-finite one becomes a huge `u32` on the cast,
    // which is a request for tens of gigabytes. Neither can come from a
    // display, and both are one line to make impossible.
    let s = if scale.is_finite() {
        scale.clamp(0.5, 8.0)
    } else {
        1.0
    };

    let h = 18.0 * s;
    let pad = 5.0 * s;
    let icon = 10.0 * s;
    let label_px = 7.5 * s;
    let val_px = 8.0 * s;
    let bar_w = 17.0 * s;
    let bar_h = 2.6 * s;
    let bar_gap = 1.8 * s;
    let gap = 3.0 * s;
    let sep_w = text_width(f, label_px, "·");
    let slash_w = text_width(f, val_px, "/");

    let val_pair_w = |r: &ProviderRow| -> f32 {
        text_width(f, val_px, &used_num(&r.five_hour))
            + slash_w
            + text_width(f, val_px, &used_num(&r.weekly))
            + val_px * 0.1
    };
    let group_w = |r: &ProviderRow| -> f32 {
        let label_w = text_width(f, label_px, &r.label) + label_px * 0.05;
        label_w + gap + bar_w + gap + val_pair_w(r)
    };

    let mut w = pad + icon + 4.0 * s;
    for (i, r) in rows.iter().enumerate() {
        if i > 0 {
            w += 4.0 * s + sep_w + 4.0 * s;
        }
        w += group_w(r);
    }
    w += pad;

    let mut img = RgbaImage::new(w.ceil() as u32, h.ceil() as u32);

    // Pill: border underlay, then the plate inset by 1 pt.
    fill_rrect(&mut img, 0.0, 0.0, w, h, 5.0 * s, p.border);
    fill_rrect(&mut img, s, s, w - 2.0 * s, h - 2.0 * s, 4.4 * s, p.chip);

    draw_gauge(&mut img, pad, (h - icon) / 2.0, icon as u32, p.ink);

    let cy = h / 2.0;
    let baseline = cy + label_px * 0.36;
    let mut x = pad + icon + 4.0 * s;

    // One mini bar (track, used fill, elapsed-time tick) centred on `bcy`.
    let draw_bar = |img: &mut RgbaImage, x: f32, bcy: f32, stat: &Option<WindowStat>| {
        let by = bcy - bar_h / 2.0;
        fill_rrect(img, x, by, bar_w, bar_h, bar_h / 2.0, p.track);
        if let Some(st) = stat {
            let used = used_fraction(st);
            if used > 0.0 {
                let fw = (bar_w * used).max(bar_h);
                fill_rrect(
                    img,
                    x,
                    by,
                    fw,
                    bar_h,
                    bar_h / 2.0,
                    p.sev(used as f64 * 100.0),
                );
            }
            if let Some(t) = time_fraction(st) {
                let tick_w = 1.1 * s;
                let tick_h = bar_h + 1.8 * s;
                let tx = x + (bar_w - tick_w) * t.clamp(0.0, 1.0);
                fill_rrect(
                    img,
                    tx,
                    bcy - tick_h / 2.0,
                    tick_w,
                    tick_h,
                    0.55 * s,
                    p.playhead,
                );
            }
        }
    };

    for (i, row) in rows.iter().enumerate() {
        if i > 0 {
            x += 4.0 * s;
            draw_text(&mut img, f, label_px, x, baseline, "·", p.faint);
            x += sep_w + 4.0 * s;
        }

        draw_text_bold(&mut img, f, label_px, x, baseline, &row.label, p.ink);
        x += text_width(f, label_px, &row.label) + label_px * 0.05 + gap;

        // Stacked bars: 5-hour above, weekly below.
        draw_bar(&mut img, x, cy - (bar_h + bar_gap) / 2.0, &row.five_hour);
        draw_bar(&mut img, x, cy + (bar_h + bar_gap) / 2.0, &row.weekly);
        x += bar_w + gap;

        // Left-% pair "91/68", each half in its own severity colour.
        for (idx, stat) in [&row.five_hour, &row.weekly].into_iter().enumerate() {
            if idx > 0 {
                draw_text(&mut img, f, val_px, x, baseline, "/", p.faint);
                x += slash_w;
            }
            let text = used_num(stat);
            let color = match stat {
                Some(st) => p.sev(used_fraction(st) as f64 * 100.0),
                None => p.faint,
            };
            draw_text_bold(&mut img, f, val_px, x, baseline, &text, color);
            x += text_width(f, val_px, &text) + val_px * 0.05;
        }
    }

    Some(img)
}

/// Render the tray *badge*: the same reading as [`render`], squared off to be
/// a notification-area icon.
///
/// Windows draws a tray icon as a small square and gives it nowhere to put a
/// title — the whole arrangement the menu-bar pill is built on (a wide image
/// standing in for the status item's own text) has no counterpart there, and
/// `set_title` is simply not implemented on that platform. So the badge keeps
/// what survives at 16pt and drops what does not: one mini bar per quota
/// window, stacked and grouped by provider, fill = used and tick = elapsed —
/// the same three-ways-of-saying-one-quantity as everywhere else — while the
/// figures move to the tooltip, which is where Windows does have room for
/// them.
///
/// `px` is the icon's edge in real pixels; the layout is proportional to it,
/// so 16, 24 and 32 all come out as the same picture. `None` when there is
/// nothing to draw, matching [`render`] so the caller's fallback is one
/// branch for both. Same cap as [`render`]: only the first two of `rows` are
/// drawn, the rest dropped.
pub fn render_badge(rows: &[ProviderRow], dark: bool, px: u32) -> Option<RgbaImage> {
    let rows: Vec<&ProviderRow> = rows.iter().take(2).collect();
    if rows.is_empty() {
        return None;
    }
    // Same guard as `render`'s scale clamp, for the same reason: this number
    // sizes an allocation. Below 8px nothing legible fits anyway, and no
    // tray asks for more than 64.
    let px = px.clamp(8, 64);
    let p = palette(dark);

    // One entry per quota window, in the order they stack. `group` marks
    // which provider it belongs to, which is the only thing separating
    // Codex's pair from Claude's once there is no room for a label.
    let mut bars: Vec<(usize, &Option<WindowStat>)> = Vec::new();
    for (g, row) in rows.iter().enumerate() {
        bars.push((g, &row.five_hour));
        bars.push((g, &row.weekly));
    }
    let groups = rows.len() as f32;
    let n = bars.len() as f32;

    let size = px as f32;
    let pad = (size * 0.09).max(1.0);
    let avail = size - 2.0 * pad;
    // Bar : gap-within-a-provider : gap-between-providers = 3 : 1 : 3. Solved
    // for the unit rather than assigned in pixels, so the stack always fills
    // the icon exactly whether it holds two bars or four.
    //
    // The gap between providers has to be a whole bar, not the 2 units tried
    // first: at 16px a unit is under a pixel, so a 1-vs-2 unit difference
    // rounds away and four bars read as one undifferentiated stack rather
    // than as Codex's pair above Claude's. A full bar's worth survives the
    // rounding.
    let within = n - groups;
    let between = groups - 1.0;
    let unit = avail / (3.0 * n + within + 3.0 * between);
    let bar_h = (3.0 * unit).max(1.0);
    let bar_w = size - 2.0 * pad;

    let mut img = RgbaImage::new(px, px);
    let mut y = pad;
    let mut prev_group: Option<usize> = None;
    for (group, stat) in bars {
        if let Some(prev) = prev_group {
            y += if prev == group { unit } else { 3.0 * unit };
        }
        prev_group = Some(group);

        fill_rrect(&mut img, pad, y, bar_w, bar_h, bar_h / 2.0, p.track);
        if let Some(st) = stat {
            let used = used_fraction(st);
            if used > 0.0 {
                // Never thinner than it is tall: a 1%-used bar that rounds
                // away to nothing reads as "no data", which is a different
                // thing entirely.
                let fw = (bar_w * used).max(bar_h);
                fill_rrect(
                    &mut img,
                    pad,
                    y,
                    fw,
                    bar_h,
                    bar_h / 2.0,
                    p.sev(used as f64 * 100.0),
                );
            }
            // The elapsed-time tick, but only where there is room for it. A
            // bar under 3px tall is two or three rows of pixels, and a tick
            // drawn across one reads as a *break* in the bar rather than a
            // mark on it — it costs more than the reading it adds. That is
            // the 16pt tray at 100%, where the pair of figures in the
            // tooltip is carrying this information anyway.
            if let Some(t) = time_fraction(st).filter(|_| bar_h >= 3.0) {
                let tick_w = (size * 0.07).max(1.0);
                let tick_h = bar_h + unit;
                let tx = pad + (bar_w - tick_w) * t.clamp(0.0, 1.0);
                fill_rrect(
                    &mut img,
                    tx,
                    y + bar_h / 2.0 - tick_h / 2.0,
                    tick_w,
                    tick_h,
                    tick_w / 2.0,
                    p.playhead,
                );
            }
        }
        y += bar_h;
    }
    Some(img)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {

    /// The panel paints its bars in Slint, from `Theme.sev`, which cannot read
    /// [`WARN_AT`]/[`CRIT_AT`] — so the numbers are written twice and only this
    /// test ties them together. Without it the two drift apart in the one way
    /// nothing else would catch: silently, with both halves still compiling,
    /// the menu-bar pill turning amber at one figure and the row beneath it at
    /// another.
    ///
    /// `include_str!` rather than a path read at runtime, so the test is
    /// rebuilt when the theme changes rather than reading whatever happens to
    /// be on disk.
    #[test]
    fn the_panel_colours_at_the_same_two_numbers_this_module_does() {
        let theme = include_str!("../ui/theme.slint");
        // Whole numbers first, because the comparison below renders them as
        // integers: `WARN_AT = 70.9` against a theme still saying `pct >= 70`
        // would truncate to a match and pass, while the pill turned amber at
        // 70.9 and the row under it at 70.0 — the exact drift being guarded.
        assert_eq!(
            WARN_AT.fract(),
            0.0,
            "a fractional threshold needs a comparison that keeps it"
        );
        assert_eq!(CRIT_AT.fract(), 0.0, "likewise");
        let expected = format!(
            "return pct >= {} ? crit : pct >= {} ? warn : ok;",
            CRIT_AT as i64, WARN_AT as i64
        );
        assert!(
            theme.contains(&expected),
            "ui/theme.slint no longer decides the colour the way this module does.\n\
             expected to find: {expected}\n\
             If the thresholds moved, move WARN_AT/CRIT_AT with them; if the rule\n\
             itself changed shape, this test has to learn the new shape."
        );
    }
    use super::*;

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
                    time_progress: None,
                }),
            },
        ]
    }

    #[test]
    fn cache_key_tracks_values_and_theme() {
        let base = cache_key(&rows(), true);
        assert_eq!(base, cache_key(&rows(), true), "stable for identical input");
        assert_ne!(base, cache_key(&rows(), false), "theme is part of the key");

        let mut changed = rows();
        changed[0].five_hour.as_mut().unwrap().used_percent = 10.0;
        assert_ne!(base, cache_key(&changed, true), "used % is part of the key");

        // Sub-2% playhead movement must NOT invalidate the key (icon churn).
        let mut nudged = rows();
        nudged[0].five_hour.as_mut().unwrap().time_progress = Some(0.556);
        assert_eq!(base, cache_key(&nudged, true));
    }

    #[test]
    fn empty_rows_render_nothing() {
        assert!(render(&[], true, 2.0).is_none());
        assert!(
            render_badge(&[], true, 16).is_none(),
            "the badge answers the same way"
        );
    }

    #[test]
    fn the_badge_is_square_at_whatever_size_the_tray_asks_for() {
        // The notification area hands over its own small-icon metric — 16 at
        // 100% scaling, 24 at 150%, 32 at 200% — and the badge is drawn at
        // it rather than resampled into it, so each has to come back exact.
        for px in [16u32, 24, 32] {
            let img = render_badge(&rows(), true, px).expect("rows present");
            assert_eq!(img.dimensions(), (px, px), "asked for {px}px");
        }
    }

    #[test]
    fn an_absurd_size_is_clamped_rather_than_allocated() {
        // Same guard, and the same reason, as `render`'s scale clamp: this
        // number sizes an allocation.
        let huge = render_badge(&rows(), true, u32::MAX).expect("rows present");
        assert_eq!(huge.dimensions(), (64, 64));
        let tiny = render_badge(&rows(), true, 0).expect("rows present");
        assert_eq!(tiny.dimensions(), (8, 8));
    }

    #[test]
    fn the_stack_fills_the_icon_whether_it_holds_two_bars_or_four() {
        // The layout solves for a unit rather than assigning pixels, so the
        // bars grow to fit when there is one provider and shrink when there
        // are two — in both cases ending flush against the padding. A stack
        // that stopped short would mean a provider's windows had been
        // silently dropped for want of room.
        let rows_of = |img: &RgbaImage| -> (u32, u32) {
            let inked: Vec<u32> = (0..img.height())
                .filter(|&y| (0..img.width()).any(|x| img.get_pixel(x, y).0[3] > 0))
                .collect();
            (
                *inked.first().expect("something is drawn"),
                *inked.last().unwrap(),
            )
        };
        for rows in [&rows()[..], &rows()[..1]] {
            let img = render_badge(rows, true, 32).expect("rows present");
            let (top, bottom) = rows_of(&img);
            assert!(
                top <= 4,
                "the stack starts at the padding, not below it (got {top})"
            );
            assert!(bottom >= 27, "and ends at it (got {bottom})");
        }
    }

    #[test]
    fn a_bar_too_thin_for_a_tick_does_not_get_one() {
        // At 16px with four bars each is ~2px tall, and a tick across one
        // reads as a break in the bar. The pixel count is the check: the
        // tick is the only white in the palette, so a badge that drew one
        // would have some.
        let white = |img: &RgbaImage| {
            img.pixels()
                .filter(|p| p.0[0] > 240 && p.0[1] > 240 && p.0[2] > 240 && p.0[3] > 200)
                .count()
        };
        let small = render_badge(&rows(), true, 16).expect("rows present");
        let large = render_badge(&rows(), true, 32).expect("rows present");
        assert_eq!(white(&small), 0, "no room for a tick, so no tick");
        assert!(
            white(&large) > 0,
            "at 32px there is room and the tick is drawn"
        );
    }

    // The render path needs a real system font; macOS always has Menlo.
    #[cfg(target_os = "macos")]
    #[test]
    fn renders_single_line_pill_on_macos() {
        for dark in [true, false] {
            let img = render(&rows(), dark, 2.0).expect("system font present");
            assert_eq!(img.height(), 36, "18pt at 2x");
            assert!(img.width() > 150, "two provider groups fit on one line");
            // Pill must actually contain drawn pixels.
            assert!(img.pixels().any(|p| p[3] > 0));
        }
    }

    #[test]
    fn the_number_beside_a_bar_is_what_the_bar_shows() {
        // The widget used to print what was left while its own bar filled with
        // what was used, so the two halves of one pill disagreed — and so did
        // the menu bar and the panel.
        let stat = |used| {
            Some(WindowStat {
                used_percent: used,
                time_progress: None,
            })
        };
        assert_eq!(used_num(&stat(70.0)), "70");
        assert_eq!(used_num(&stat(0.4)), "0");
        assert_eq!(used_num(&stat(99.6)), "100");
        assert_eq!(
            used_num(&stat(120.0)),
            "100",
            "a provider over its own limit still reads 100"
        );
        assert_eq!(
            used_num(&None),
            "--",
            "a window with no reading is not 0% used"
        );
    }

    #[test]
    fn numbers_no_display_could_produce_never_reach_a_coordinate() {
        // Percentages and progress fractions arrive from a provider's JSON.
        // A NaN reaching a coordinate is a range built from NaN; a scale of
        // zero or a negative one is an allocation of nothing or of everything.
        let odd = ProviderRow {
            label: "Cx".to_string(),
            five_hour: Some(WindowStat {
                used_percent: f64::NAN,
                time_progress: Some(f32::NAN),
            }),
            weekly: Some(WindowStat {
                used_percent: -1e12,
                time_progress: Some(1e9),
            }),
        };
        assert_eq!(
            used_num(&odd.five_hour),
            "0",
            "not-a-number reads as nothing used"
        );
        assert_eq!(used_num(&odd.weekly), "0");
        assert_eq!(time_fraction(odd.five_hour.as_ref().unwrap()), None);
        assert_eq!(time_fraction(odd.weekly.as_ref().unwrap()), Some(1.0));

        // And the render itself survives every scale, including the ones no
        // display reports.
        for scale in [0.0, -4.0, f32::NAN, f32::INFINITY, 1e9, 2.0] {
            let img = render(std::slice::from_ref(&odd), true, scale);
            if let Some(img) = img {
                assert!(
                    img.width() > 0 && img.height() > 0,
                    "scale {scale} produced an empty image"
                );
                assert!(
                    img.width() < 10_000,
                    "scale {scale} produced {}px of width",
                    img.width()
                );
            }
        }
    }
}
