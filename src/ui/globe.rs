use ratatui::widgets::{Widget, Block, Borders};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Span;
use std::f64::consts::PI;

pub struct Globe<'a> {
    pub rotation: f64,
    pub connections: &'a [(f64, f64)], // Lat, Lon
    pub block: Option<Block<'a>>,
    pub style: Style,
}

impl<'a> Globe<'a> {
    pub fn new(connections: &'a [(f64, f64)]) -> Self {
        Self {
            rotation: 0.0,
            connections,
            block: None,
            style: Style::default(),
        }
    }
    
    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }
    
    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }
}

// Simplified continent points (Lat, Lon in degrees)
// A very sparse representation of the world
const LAND_POINTS: &[(f64, f64)] = &[
    // North America
    (60.0, -100.0), (50.0, -120.0), (50.0, -80.0), (40.0, -110.0), (40.0, -90.0), (30.0, -100.0), (20.0, -100.0),
    // South America
    (0.0, -60.0), (-10.0, -55.0), (-20.0, -60.0), (-40.0, -70.0), (-50.0, -70.0),
    // Europe
    (50.0, 10.0), (60.0, 30.0), (45.0, 5.0), (55.0, 20.0), (40.0, 0.0),
    // Africa
    (20.0, 10.0), (10.0, 20.0), (0.0, 20.0), (-10.0, 30.0), (-20.0, 25.0), (-30.0, 25.0),
    // Asia
    (60.0, 80.0), (50.0, 100.0), (40.0, 100.0), (30.0, 80.0), (30.0, 120.0), (20.0, 80.0), (20.0, 100.0),
    // Australia
    (-25.0, 135.0), (-30.0, 145.0),
];

impl<'a> Widget for Globe<'a> {
    fn render(mut self, area: Rect, buf: &mut Buffer) {
        if let Some(block) = self.block {
            block.render(area, buf);
        }
        
        let center_x = area.x as f64 + area.width as f64 / 2.0;
        let center_y = area.y as f64 + area.height as f64 / 2.0;
        
        // Radius: fit in height/width (terminal cells are ~2:1 usually, so scale X by 2?)
        // Actually height is the constraint usually.
        let radius = (area.height as f64 - 2.0) / 2.0;
        
        // Render Land
        for &(lat, lon) in LAND_POINTS {
            draw_point(buf, lat, lon, self.rotation, center_x, center_y, radius, '.', self.style);
        }
        
        // Render Connections (Markers)
        for &(lat, lon) in self.connections {
            // Use 'X' or 'o' for connection
            draw_point(buf, lat, lon, self.rotation, center_x, center_y, radius, 'O', self.style.fg(ratatui::style::Color::Red)); // Hardcoded Highlight
        }
    }
}

fn draw_point(buf: &mut Buffer, lat_deg: f64, lon_deg: f64, rotation: f64, cx: f64, cy: f64, r: f64, ch: char, style: Style) {
    let lat = lat_deg.to_radians();
    let lon = lon_deg.to_radians();
    
    // 3D Coords (Y is UP in math, but we map to screen Y down)
    // Using standard mapping:
    let x = lat.cos() * lon.cos();
    let y = lat.sin();
    let z = lat.cos() * lon.sin(); // Depth?
    
    // Rotate around Y axis (which is acting as our N-S pole axis visually?)
    // Actually typically Z-up or Y-up. Let's assume consistent frame.
    // If we rotate longitude, that's rotation around Y axis.
    
    let theta = rotation;
    
    // Rotate x, z
    // x' = x cos θ + z sin θ
    // z' = -x sin θ + z cos θ
    let x_rot = x * theta.cos() - z * theta.sin();
    let z_rot = x * theta.sin() + z * theta.cos();
    
    // Check if visible (z_rot > 0 implies front hemisphere usually, depending on coord system)
    // Let's assume viewer is at +z. 
    // Wait, with rotation: if `cos(lon + theta)`?
    // Let's stick to 3D transform.
    // If z_rot > 0, we draw.
    
    // Adjust logic to ensure correct "front" face.
    // If we project to x, y plane.
    
    if z_rot > 0.0 { // Or < 0.0 depending on convention. Stick to > 0 for now.
        let screen_x = cx + (x_rot * r * 2.0); // X scale (chars are approx 1/2 width of height)
        let screen_y = cy - (y * r); 
        
        let ix = screen_x.round() as u16;
        let iy = screen_y.round() as u16;
        
        if let Some(cell) = buf.cell_mut((ix, iy)) {
            cell.set_char(ch);
            cell.set_style(style);
        }
    }
}
