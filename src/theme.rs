use ratatui::style::Color;

pub struct Theme {
    pub bg: Color,
    pub surface: Color,
    pub fg: Color,
    pub primary: Color,
    pub secondary: Color,
    pub accent: Color,
    pub success: Color,
    pub error: Color,
    pub border: Color,
    pub muted: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Theme {
            // Neon Night Theme
            bg: Color::Rgb(10, 10, 15),       // Almost Black
            surface: Color::Rgb(20, 20, 30),  // Dark Overlay
            fg: Color::Rgb(240, 240, 255),    // Bright White-ish
            primary: Color::Rgb(0, 245, 255), // Electric Cyan
            secondary: Color::Rgb(255, 0, 255), // Neon Magenta
            accent: Color::Rgb(120, 100, 255),  // Electric Purple
            success: Color::Rgb(0, 255, 127),  // Spring Green
            error: Color::Rgb(255, 50, 80),     // Bright Red
            border: Color::Rgb(60, 60, 80),     // Muted Blue-Grey
            muted: Color::Rgb(100, 100, 120),   // Grey text
        }
    }
}

pub const THEME: Theme = Theme {
    bg: Color::Rgb(10, 10, 15),
    surface: Color::Rgb(20, 20, 30),
    fg: Color::Rgb(240, 240, 255),
    primary: Color::Rgb(0, 245, 255),
    secondary: Color::Rgb(255, 0, 255),
    accent: Color::Rgb(120, 100, 255),
    success: Color::Rgb(0, 255, 127),
    error: Color::Rgb(255, 50, 80),
    border: Color::Rgb(60, 60, 80),
    muted: Color::Rgb(100, 100, 120),
};
