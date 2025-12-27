use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, BorderType, Clear, Dataset, Chart, Axis, GraphType},
    symbols,
    Frame,
};



use crate::app::{App, CurrentScreen};
use crate::theme::THEME;
use crate::tools::dns::DnsResult;

// Define zones for hit testing (could be expanded)
#[derive(Clone, Copy, Debug)]
pub enum UiZone {
    Tab(usize),
    PingInput,
    PingStartStop,
    DnsInput,
    DnsTypeNext,
}

pub fn ui(f: &mut Frame, app: &mut App) {
    let size = f.area();
    // Global Background
    let bg_block = Block::default().style(Style::default().bg(THEME.bg));
    f.render_widget(bg_block, size);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(1), // Top Bar (Logo + Tabs)
                Constraint::Min(1),    // Main Content
                Constraint::Length(1), // Status Bar
            ]
            .as_ref(),
        )
        .split(size);
    debug_assert_eq!(chunks.len(), 3, "Main layout should have 3 chunks");

    // --- Header ---
    let header_area = chunks[0];
    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(10), Constraint::Min(1)].as_ref())
        .split(header_area);
    debug_assert_eq!(header_chunks.len(), 2);

    // Logo
    let logo_style = Style::default().fg(THEME.primary).add_modifier(Modifier::BOLD);
    f.render_widget(Paragraph::new(" NETOPS ").style(logo_style).bg(THEME.surface), header_chunks[0]);

    // Custom Tabs
    let tabs = ["D", "P", "N", "S", "M", "R", "A", "C"]; // Short codes
    let tab_names = ["Dash", "Ping", "DNS", "Sniff", "MTR", "Scan", "Arp", "Conns"];
    
    let current_idx = match app.current_screen {
        CurrentScreen::Dashboard => 0,
        CurrentScreen::Ping => 1,
        CurrentScreen::Dns => 2,
        CurrentScreen::Sniffer => 3,
        CurrentScreen::Mtr => 4,
        CurrentScreen::Nmap => 5,
        CurrentScreen::ArpScan => 6,
        CurrentScreen::Connections => 7,
    };

    let mut tab_spans = vec![];
    for (i, (code, name)) in tabs.iter().zip(tab_names.iter()).enumerate() {
        let is_selected = i == current_idx;
        let (bg, fg) = if is_selected {
            (THEME.primary, THEME.bg)
        } else {
            (THEME.surface, THEME.muted)
        };
        
        tab_spans.push(Span::styled(format!(" {} ", code), Style::default().fg(fg).bg(bg).add_modifier(Modifier::BOLD)));
        tab_spans.push(Span::styled(format!("{} ", name), Style::default().fg(if is_selected { THEME.primary } else { THEME.muted }).bg(THEME.surface)));
        tab_spans.push(Span::raw(" "));
    }
    
    f.render_widget(Paragraph::new(Line::from(tab_spans)).alignment(ratatui::layout::Alignment::Left).bg(THEME.surface), header_chunks[1]);

    // --- Main Content ---
    let content_area = chunks[1];
    // Add a subtle padding or margin if needed, but full bleed looks modern.
    // Let's verify each render function handles its own blocks.
    
    match app.current_screen {
        CurrentScreen::Dashboard => render_dashboard(f, app, content_area),
        CurrentScreen::Ping => render_ping(f, app, content_area),
        CurrentScreen::Dns => render_dns(f, app, content_area),
        CurrentScreen::Sniffer => render_sniffer(f, app, content_area),
        CurrentScreen::Mtr => render_mtr(f, app, content_area),
        CurrentScreen::Nmap => render_nmap(f, app, content_area),
        CurrentScreen::ArpScan => render_arpscan(f, app, content_area),
        CurrentScreen::Connections => render_connections(f, app, content_area),
    }

    // --- Footer ---
    let footer_area = chunks[2];
    let footer_text = Line::from(vec![
        Span::styled(" Q ", Style::default().bg(THEME.error).fg(THEME.bg).add_modifier(Modifier::BOLD)),
        Span::styled(" Quit ", Style::default().fg(THEME.muted).bg(THEME.surface)),
        Span::raw(" "),
        Span::styled(" TAB ", Style::default().bg(THEME.secondary).fg(THEME.bg).add_modifier(Modifier::BOLD)),
        Span::styled(" Next ", Style::default().fg(THEME.muted).bg(THEME.surface)),
    ]);
    f.render_widget(Paragraph::new(footer_text).bg(THEME.surface), footer_area);

    if app.show_help {
        render_help(f, app, size);
    }
    
    if app.show_options {
        render_options(f, app, size);
    }
}

fn render_options(f: &mut Frame, app: &App, area: Rect) {
    let opts = app.get_tool_options();
    if opts.is_empty() { return; }
    
    let height = (opts.len() as u16) + 4;
    let width = 60;
    
    let popup_area = Rect {
        x: area.width.saturating_sub(width) / 2,
        y: area.height.saturating_sub(height) / 2,
        width,
        height,
    };
    
    f.render_widget(Clear, popup_area);
    
    let block = Block::default()
        .title(" Select Option (Enter to Insert) ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(THEME.accent))
        .bg(THEME.bg);
        
    f.render_widget(block.clone(), popup_area);
    
    let inner = block.inner(popup_area);
    
    let items: Vec<ListItem> = opts.iter().enumerate().map(|(i, (flag, desc, _))| {
        let style = if i == app.options_scroll {
            Style::default().fg(THEME.bg).bg(THEME.accent).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(THEME.fg)
        };
        
        ListItem::new(Line::from(vec![
            Span::styled(format!(" {:<5} ", flag), style),
            Span::styled(format!(" {}", desc), style),
        ]))
    }).collect();
    
    let list = List::new(items);
    f.render_widget(list, inner);
}

fn render_help(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(THEME.primary))
        .bg(THEME.bg); 
        
    // Calculate centered rect
    let popup_area = Rect {
        x: area.width.saturating_sub(70) / 2,
        y: area.height.saturating_sub(26) / 2,
        width: 70,
        height: 26,
    };
    
    f.render_widget(Clear, popup_area);
    
    let mut text = vec![
        Line::from(vec![Span::styled(" Global Keys ", Style::default().fg(THEME.accent).add_modifier(Modifier::BOLD))]),
        Line::from(" [Alt + 1-8]     Switch Tab (Dash/Ping/DNS...)"),
        Line::from(" [Shift + Key]   Legacy Switch (D,P,N...)"),
        Line::from(" [H] or [?]      Toggle Help"),
        Line::from(" [Ctrl+F]        Tool Options/Flags"),
        Line::from(" [Q]             Quit"),
        Line::from(""),
    ];
    
    let tool_specific = match app.current_screen {
        CurrentScreen::Dashboard => vec![
            " Dashboard ",
            " Overview of network traffic and connectivity.",
            " - Top Left:  Real-time WAN I/O bandwidth.",
            " - Top Right: Active connection count.",
            " - Bot Left:  Interface status.",
            " - Bot Right: Top 5 Remote ASNs (Organizations).",
        ],
        CurrentScreen::Ping => vec![
            " Ping Tool ",
            " [Enter]  Start Ping to target",
            " [Esc]    Stop Ping",
            " ",
            " Features:",
            " - Real-time Latency Graph (Bottom)",
            " - Live Statistics (Min/Avg/Max/Loss)",
            " - Flags: -i <sec> -s <bytes> -c <count>",
        ],
        CurrentScreen::Dns => vec![
            " DNS Resolver ",
            " [Enter]  Resolve Domain",
            " [Tab]    Cycle Record Type (A -> AAAA -> MX...)",
            " ",
            " Returns detailed records including TTL.",
        ],
        CurrentScreen::Sniffer => vec![
            " Packet Sniffer ",
            " [Enter]      Start/Stop Capture",
            " [Left/Right] Select Interface",
            " [Filter]     BPF Syntax (e.g. 'tcp port 80')",
            " ",
            " Displays: Time, Protocol, Source, Dest, Length, Info",
        ],
        CurrentScreen::Mtr => vec![
            " My Traceroute (MTR) ",
            " [Enter]    Start Trace",
            " [Esc]      Stop",
            " [Up/Down]  Select Hop to view Latency Graph",
            " ",
            " Shows path to target with loss & jitter per hop.",
        ],
        CurrentScreen::Nmap => vec![
            " Port Scanner ",
            " [Enter]  Start Scan",
            " [Esc]    Stop/Detach",
            " ",
            " Useful Flags (Ctrl+F):",
            " -p 80,443   Specific ports",
            " -F          Fast scan (top 100 ports)",
            " -sV         Service Version detection",
        ],
        CurrentScreen::ArpScan => vec![
            " Arp Scanner ",
            " [Enter]  Start Scan",
            " [Esc]    Stop",
            " ",
            " automatically scans local network if no args given.",
            " -l: Localnet (default)",
            " -I: Interface (e.g. -I en0)",
            " ",
            " View switches to Table composed of IP, MAC to Vendor.",
        ],
        CurrentScreen::Connections => vec![
            " Active Connections ",
            " Monitors live socket connections.",
            " ",
            " - [Table] Real-time list of remote peers.",
            " - [Map]   World map showing peer locations.",
            " - Shows ASN (ISP/Org) for each IP.",
        ],
    };
    
    text.push(Line::from(Span::styled(tool_specific[0], Style::default().fg(THEME.primary).add_modifier(Modifier::BOLD))));
    for line in tool_specific.iter().skip(1) {
        text.push(Line::from(*line));
    }

    f.render_widget(Paragraph::new(text).block(block).alignment(ratatui::layout::Alignment::Center), popup_area);
}

// ... render_dashboard, render_ping, render_dns, render_sniffer ...

fn render_mtr(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)].as_ref())
        .split(area);

    // Controls
    let _status_color = if app.mtr_active { THEME.success } else { THEME.muted };
    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if app.mtr_active { THEME.primary } else { THEME.border }))
        .title(Span::styled(" TARGET ", Style::default().fg(THEME.fg)));
    f.render_widget(Paragraph::new(app.mtr_input.value()).block(input_block).style(Style::default().fg(THEME.primary)), chunks[0]);
    if !app.mtr_active {
         f.set_cursor_position((chunks[0].x + app.mtr_input.visual_cursor() as u16 + 1, chunks[0].y + 1));
    }

    // MTR Content
    let content_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
        .split(chunks[1]);

    // Results Table
    use ratatui::widgets::{Table, Row};
    let header_cells = ["Hop", "Host", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst", "Jit"]
        .iter().map(|h| ratatui::widgets::Cell::from(*h).style(Style::default().fg(THEME.muted).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).style(Style::default().bg(THEME.surface)).height(1);

    let rows = app.mtr_hops.iter().map(|hop| {
        let loss_color = if hop.loss >= 10.0 { THEME.error } else if hop.loss > 0.0 { THEME.secondary } else { THEME.success };
        let lat_color = if hop.last > 100 { THEME.error } else if hop.last > 50 { THEME.secondary } else { THEME.primary };
        
        let cells = vec![
            ratatui::widgets::Cell::from(format!("{:02}", hop.ttl)),
            ratatui::widgets::Cell::from(hop.host.clone()),
            ratatui::widgets::Cell::from(format!("{:.1}%", hop.loss)).style(Style::default().fg(loss_color)),
            ratatui::widgets::Cell::from(format!("{}", hop.sent)),
            ratatui::widgets::Cell::from(format!("{}ms", hop.last)).style(Style::default().fg(lat_color)),
            ratatui::widgets::Cell::from(format!("{}ms", hop.avg)),
            ratatui::widgets::Cell::from(format!("{}ms", hop.best)),
            ratatui::widgets::Cell::from(format!("{}ms", hop.jitter)),
        ];
        Row::new(cells).style(Style::default().fg(THEME.fg))
    });

    let table = Table::new(rows, [
        Constraint::Length(4), Constraint::Length(25), Constraint::Length(8),
        Constraint::Length(6), Constraint::Length(8), Constraint::Length(8),
        Constraint::Length(8), Constraint::Length(8), Constraint::Length(8)
    ].as_ref())
    .header(header)
    .row_highlight_style(Style::default().bg(THEME.secondary).fg(THEME.bg).add_modifier(Modifier::BOLD)) // Assuming selection added to theme or reuse primary
    .highlight_symbol(">"); 
    // Wait, Theme doesn't have selection. I'll use primary.
    // .highlight_style(Style::default().bg(THEME.primary).fg(THEME.bg));

    f.render_stateful_widget(table, content_chunks[0], &mut app.mtr_table_state);

    // Graph for Selected Hop
    if let Some(hop) = app.mtr_hops.get(app.mtr_selected_hop) {
        let history: Vec<(f64, f64)> = hop.history.iter().enumerate().map(|(i,&v)| (i as f64, v as f64)).collect();
        let max_lat = hop.history.iter().max().unwrap_or(&100).max(&50) * 2;
        
        let chart = Chart::new(vec![
            Dataset::default().marker(symbols::Marker::Braille).graph_type(GraphType::Line).style(Style::default().fg(THEME.primary)).data(&history)
        ])
        .block(Block::default().title(format!(" Latency: {} ", hop.host)).borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(THEME.border)))
        .x_axis(Axis::default().bounds([0.0, 100.0]).style(Style::default().fg(THEME.muted)))
        .y_axis(Axis::default().bounds([0.0, max_lat as f64]).style(Style::default().fg(THEME.muted)));
        f.render_widget(chart, content_chunks[1]);
    } else {
        f.render_widget(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).style(Style::default().fg(THEME.muted)), content_chunks[1]);
    }
}

// ... render_dashboard, render_ping, render_dns ...

fn render_sniffer(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)].as_ref())
        .split(area);

    // Controls
    let current = app.interfaces.get(app.selected_interface_index).map(|i| i.name.as_str()).unwrap_or("None");
    let (status_text, status_col) = if app.sniffer_active { ("CAPTURING", THEME.success) } else { ("IDLE", THEME.muted) };
    
    let info_text = Line::from(vec![
        Span::raw(" Interface: "),
        Span::styled(current, Style::default().fg(THEME.primary).add_modifier(Modifier::BOLD)),
        Span::raw("  Status: "),
        Span::styled(status_text, Style::default().fg(status_col).add_modifier(Modifier::BOLD)),
    ]);
    
    f.render_widget(Paragraph::new(info_text).block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(THEME.border)).title(" Sniffer ")), chunks[0]);
    
    // Controls 2 (Filter)
    let filter_area = Rect { x: chunks[0].x + 40, y: chunks[0].y, width: chunks[0].width.saturating_sub(40), height: 3 };
    let filter_block = Block::default().title(" Filter ").borders(Borders::LEFT);
    f.render_widget(Paragraph::new(app.sniffer_filter_input.value()).block(filter_block).style(Style::default().fg(THEME.fg)), filter_area);
    
    if !app.sniffer_active {
         f.set_cursor_position((
            filter_area.x + 1 + app.sniffer_filter_input.visual_cursor() as u16,
            filter_area.y + 1
        ));
    }

    // Table
    use ratatui::widgets::{Table, Row};
    let header = Row::new(["Time", "Proto", "Source", "Dest", "Len", "Info"].iter().map(|h| ratatui::widgets::Cell::from(*h).style(Style::default().fg(THEME.muted).add_modifier(Modifier::BOLD))))
        .style(Style::default().bg(THEME.surface)).height(1);

    let rows = app.sniffer_packets.iter().rev().take(50).map(|p| {
        let proto_color = match p.protocol.as_str() {
            "TCP" => Color::Cyan,
            "UDP" => Color::Yellow,
            "ICMP" => Color::Magenta,
            _ => THEME.fg,
        };
        
        Row::new(vec![
            ratatui::widgets::Cell::from(p.time.clone()).style(Style::default().fg(THEME.muted)),
            ratatui::widgets::Cell::from(p.protocol.clone()).style(Style::default().fg(proto_color)),
            ratatui::widgets::Cell::from(p.source.clone()),
            ratatui::widgets::Cell::from(p.destination.clone()),
            ratatui::widgets::Cell::from(p.length.clone()),
            ratatui::widgets::Cell::from(p.info.clone()),
        ]).style(Style::default().fg(THEME.fg))
    });

    let table = Table::new(rows, [
        Constraint::Length(10), Constraint::Length(6), Constraint::Length(20),
        Constraint::Length(20), Constraint::Length(6), Constraint::Min(10)
    ].as_ref()).header(header);
    
    f.render_widget(table, chunks[1]);
}

fn render_nmap(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)].as_ref())
        .split(area);

    let input_border_color = if app.nmap_active { THEME.success } else { THEME.border };
    let input_block = Block::default()
        .title(" Nmap Target/Args ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(input_border_color));
    
    let input = Paragraph::new(app.nmap_input.value()).block(input_block).style(Style::default().fg(THEME.fg));
    f.render_widget(input, chunks[0]);

    if !app.nmap_active {
         f.set_cursor_position((
            chunks[0].x + app.nmap_input.visual_cursor() as u16 + 1,
            chunks[0].y + 1,
        ));
    }

    let output_block = Block::default()
        .title(" Scan Results ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(THEME.border));
        
    let items: Vec<ListItem> = app.nmap_output.iter().map(|line| {
        ListItem::new(Line::from(line.clone()))
    }).collect();
    
    // Auto-scroll to bottom if running? implementation for List scrolling usually requires ListState (TODO)
    // For now simple list.
    let list = List::new(items).block(output_block).style(Style::default().fg(THEME.fg));
    f.render_widget(list, chunks[1]);
}

fn render_arpscan(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)].as_ref())
        .split(area);

    let input_border_color = if app.arpscan_active { THEME.success } else { THEME.border };
    let input_block = Block::default()
        .title(" ArpScan Args ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(input_border_color));
    
    let input = Paragraph::new(app.arpscan_input.value()).block(input_block).style(Style::default().fg(THEME.fg));
    f.render_widget(input, chunks[0]);

    if !app.arpscan_active {
         f.set_cursor_position((
            chunks[0].x + app.arpscan_input.visual_cursor() as u16 + 1,
            chunks[0].y + 1,
        ));
    }

    // Results Table or Raw Output
    let results_area = chunks[1];
    
    if app.arpscan_results.is_empty() {
        // Show raw output if no structured results yet (e.g. startup or error)
        let output_block = Block::default()
            .title(" Log Output ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(THEME.border));
            
        let items: Vec<ListItem> = app.arpscan_output.iter().rev().take(50).map(|line| {
            ListItem::new(Line::from(line.clone()))
        }).collect();
        
        f.render_widget(List::new(items).block(output_block).style(Style::default().fg(THEME.muted)), results_area);
    } else {
        use ratatui::widgets::{Table, Row};
        
        let count = app.arpscan_results.len();
        let title = format!(" Scan Results ({}) ", count);
        
        let header = Row::new(["IP Address", "MAC Address", "Vendor"].iter().map(|h| ratatui::widgets::Cell::from(*h).style(Style::default().fg(THEME.primary).add_modifier(Modifier::BOLD))))
            .style(Style::default().bg(THEME.surface)).height(1);

        let rows = app.arpscan_results.iter().map(|entry| {
            Row::new(vec![
                ratatui::widgets::Cell::from(entry.ip.clone()),
                ratatui::widgets::Cell::from(entry.mac.clone()).style(Style::default().fg(THEME.secondary)),
                ratatui::widgets::Cell::from(entry.vendor.clone()),
            ]).style(Style::default().fg(THEME.fg))
        });

        let table = Table::new(rows, [
            Constraint::Length(16),
            Constraint::Length(20),
            Constraint::Min(20)
        ].as_ref())
        .header(header)
        .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).title(title).border_style(Style::default().fg(THEME.border)));
        
        f.render_widget(table, results_area);
    }
}

fn render_connections(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area);
        
    use ratatui::widgets::{Table, Row};
    
    let header_cells = ["Remote IP", "ASN", "Organization", "Protocol", "Packets", "Last Seen"]
        .iter()
        .map(|h| ratatui::widgets::Cell::from(*h).style(Style::default().fg(THEME.primary).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).style(Style::default().bg(THEME.bg)).height(1).bottom_margin(0);
    
    // Sort connections by time (most recent first)
    let mut connections: Vec<&crate::app::ConnectionInfo> = app.active_connections.values().collect();
    connections.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    
    let rows = connections.iter().map(|c| {
        let time_since = std::time::Instant::now().duration_since(c.last_seen).as_secs();
        let time_str = if time_since < 60 {
            format!("{}s ago", time_since)
        } else {
             format!("{}m ago", time_since / 60)
        };
        
        let cells = vec![
            ratatui::widgets::Cell::from(c.remote_ip.to_string()),
            ratatui::widgets::Cell::from(format!("AS{}", c.asn_num)).style(Style::default().fg(THEME.secondary)),
            ratatui::widgets::Cell::from(c.asn_org.clone()),
            ratatui::widgets::Cell::from(c.protocol.clone()),
            ratatui::widgets::Cell::from(format!("{}", c.packet_count)),
            ratatui::widgets::Cell::from(time_str),
        ];
        Row::new(cells).style(Style::default().fg(THEME.fg))
    });
    
    let table = Table::new(rows, [
        Constraint::Length(16), // IP
        Constraint::Length(10), // ASN
        Constraint::Min(20),    // Org (reduced)
        Constraint::Length(6),  // Proto
        Constraint::Length(7), // Packets
        Constraint::Length(10), // Last Seen
    ].as_ref())
    .header(header)
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).title(" Active Connections ").border_style(Style::default().fg(THEME.border)));
    
    f.render_widget(table, chunks[0]);
    
    // Map Rendering
    let mut locs = vec![];
    for c in connections {
        if let Some((lat, lon)) = c.location {
             // Map expects (lon, lat)
            locs.push((lon, lat));
        }
    }
    
    let map_block = Block::default()
        .title(" World Map ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(THEME.accent));
        
    use ratatui::widgets::canvas::{Canvas, Map, MapResolution, Points};
    
    let canvas = Canvas::default()
        .block(map_block)
        .x_bounds([-225.0, 225.0])
        .y_bounds([-90.0, 90.0])
        .paint(|ctx| {
            ctx.draw(&Map {
                color: THEME.primary,
                resolution: MapResolution::High,
            });
             ctx.layer();
            ctx.draw(&Points {
                coords: &locs,
                color: THEME.error,
            });
        });
        
    f.render_widget(canvas, chunks[1]);
}

fn render_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Min(10)
        ].as_ref())
        .split(area);

    let row1 = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(chunks[0]);
        
    let row2 = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(chunks[1]);

    // Helper to create a unified chart block
    let draw_chart = |f: &mut Frame, area: Rect, title: &str, data: &[(f64, f64)], data2: Option<&[(f64, f64)]>, color: Color, color2: Option<Color>, value_text: Vec<(&str, String, Color)>| {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(THEME.border))
            .bg(THEME.bg)
            .title(Span::styled(format!(" {} ", title), Style::default().fg(THEME.fg).add_modifier(Modifier::BOLD)));
        
        let inner_area = block.inner(area);
        f.render_widget(block, area);

        // Stats Overlay (Top Right)
        let mut stats_spans = vec![];
        for (label, val, col) in value_text {
            stats_spans.push(Span::styled(val, Style::default().fg(col).add_modifier(Modifier::BOLD)));
            stats_spans.push(Span::raw(" "));
            stats_spans.push(Span::styled(label, Style::default().fg(THEME.muted)));
            stats_spans.push(Span::raw("  "));
        }
        f.render_widget(Paragraph::new(Line::from(stats_spans)).alignment(ratatui::layout::Alignment::Right), Rect { x: area.x + 2, y: area.y + 1, width: area.width - 4, height: 1 });

        // Chart
        let chart_area = Rect { x: inner_area.x, y: inner_area.y + 2, width: inner_area.width, height: inner_area.height - 2 };
        let mut datasets = vec![
            Dataset::default()
                .marker(symbols::Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(color))
                .data(data)
        ];
        if let Some(d2) = data2 {
            if let Some(c2) = color2 {
                 datasets.push(
                    Dataset::default()
                        .marker(symbols::Marker::Braille)
                        .graph_type(GraphType::Line)
                        .style(Style::default().fg(c2))
                        .data(d2)
                 );
            }
        }
        
        // Dynamic Y-Bound
        let max_val = data.iter().chain(data2.unwrap_or(&[]).iter()).map(|(_, v)| v.abs()).fold(0.0f64, |a, b| a.max(b)).max(1.0) * 1.2;
        let min_val = if data2.is_some() { -max_val } else { 0.0 };

        let chart = Chart::new(datasets)
            .x_axis(Axis::default().bounds([0.0, 100.0]).style(Style::default().fg(THEME.muted)))
            .y_axis(Axis::default().bounds([min_val, max_val]).style(Style::default().fg(THEME.muted)));
        
        f.render_widget(chart, chart_area);
    };

    // 1. Internet Bandwidth (Mirrored)
    let wan_rx_val = *app.wan_rx_history.back().unwrap_or(&0.0);
    let wan_tx_val = *app.wan_tx_history.back().unwrap_or(&0.0);
    let wan_rx_data: Vec<(f64, f64)> = app.wan_rx_history.iter().enumerate().map(|(i, &v)| (i as f64, v)).collect();
    let wan_tx_data: Vec<(f64, f64)> = app.wan_tx_history.iter().enumerate().map(|(i, &v)| (i as f64, -v)).collect();

    let stats_wan = vec![
        ("↓", format!("{:.1} Mbps", wan_rx_val), THEME.primary),
        ("↑", format!("{:.1} Mbps", wan_tx_val), THEME.secondary),
    ];
    draw_chart(f, row1[0], "Internet Traffic", &wan_rx_data, Some(&wan_tx_data), THEME.primary, Some(THEME.secondary), stats_wan);

    // 2. Active Connections
    let conn_val = *app.connection_count_history.back().unwrap_or(&0);
    let conn_data: Vec<(f64, f64)> = app.connection_count_history.iter().enumerate().map(|(i, &v)| (i as f64, v as f64)).collect();

    let stats_conn = vec![
        ("Active", format!("{}", conn_val), THEME.success),
    ];
    draw_chart(f, row1[1], "Total Connections", &conn_data, None, THEME.success, None, stats_conn);

    // 3. Latency
    let lat_val = *app.db_ping_history.back().unwrap_or(&0);
    let lat_data: Vec<(f64, f64)> = app.db_ping_history.iter().enumerate().map(|(i, &v)| (i as f64, v as f64)).collect();
    let stats_lat = vec![
        ("ms", format!("{}", lat_val), if lat_val > 100 { THEME.error } else { THEME.primary }),
    ];
    draw_chart(f, row2[0], "Ping Latency (1.1.1.1)", &lat_data, None, THEME.primary, None, stats_lat);

    // 4. Jitter
    let jit_val = *app.db_jitter_history.back().unwrap_or(&0);
    let jit_data: Vec<(f64, f64)> = app.db_jitter_history.iter().enumerate().map(|(i, &v)| (i as f64, v as f64)).collect();
     let stats_jit = vec![
        ("ms", format!("{}", jit_val), THEME.accent),
    ];
    draw_chart(f, row2[1], "Jitter", &jit_data, None, THEME.accent, None, stats_jit);

    // -- Bottom Section: Interfaces & Top ASNs --
    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(chunks[2]);

    // Interfaces List
    let list_area = bottom_chunks[0];
    let block = Block::default()
        .borders(Borders::TOP | Borders::RIGHT)
        .border_style(Style::default().fg(THEME.border))
        .bg(THEME.bg)
        .title(Span::styled(" Interfaces ", Style::default().fg(THEME.muted)));
    
    let items: Vec<ListItem> = app.interfaces.iter().map(|i| {
        let name_color = if i.is_up() { THEME.success } else { THEME.error };
        let status = if i.is_up() { "●" } else { "○" };
        let ips = i.ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ");
        
        // Compact view
        let content = Line::from(vec![
            Span::styled(format!(" {} ", status), Style::default().fg(name_color)),
            Span::styled(format!("{:<8}", i.name), Style::default().fg(THEME.fg).add_modifier(Modifier::BOLD)),
            Span::styled(ips, Style::default().fg(THEME.secondary)),
        ]);
        ListItem::new(content).bg(THEME.bg)
    }).collect();
    
    f.render_widget(List::new(items).block(block), list_area);

    // Top ASNs
    let asn_area = bottom_chunks[1];
    let block_asn = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(THEME.border))
        .bg(THEME.bg)
        .title(Span::styled(" Top ASNs ", Style::default().fg(THEME.muted)));

    // Count ASNs
    use std::collections::HashMap;
    let mut asn_counts: HashMap<String, usize> = HashMap::new();
    for c in app.active_connections.values() {
        if !c.asn_org.is_empty() && c.asn_org != "Unknown" {
             *asn_counts.entry(c.asn_org.clone()).or_insert(0) += 1;
        }
    }
    let mut asn_vec: Vec<(&String, &usize)> = asn_counts.iter().collect();
    asn_vec.sort_by(|a, b| b.1.cmp(a.1));

    let asn_items: Vec<ListItem> = asn_vec.iter().take(5).map(|(org, count)| {
        ListItem::new(Line::from(vec![
            Span::styled(format!(" {:<3} ", count), Style::default().fg(THEME.primary).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{}", org), Style::default().fg(THEME.fg)),
        ]))
    }).collect();

    f.render_widget(List::new(asn_items).block(block_asn), asn_area);
}

fn render_ping(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)].as_ref())
        .split(area);

    let input_border = if app.is_pinging { THEME.success } else { THEME.border };
    let input_block = Block::default()
        .title(" Target URL/IP ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(input_border));
    
    f.render_widget(Paragraph::new(app.ping_input.value()).block(input_block).style(Style::default().fg(THEME.fg)), chunks[0]);
    
    if !app.is_pinging {
        f.set_cursor_position((chunks[0].x + app.ping_input.visual_cursor() as u16 + 1, chunks[0].y + 1));
    }

    // Ping Content: List + Stats + Graph
    let content_area = chunks[1];
    
    // Split Top (List+Stats) and Bottom (Graph)
    let content_split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(content_area);

    let top_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)].as_ref())
        .split(content_split[0]);

    // Results List
    let list_area = top_split[0];
    let items: Vec<ListItem> = app.ping_history.iter().rev().map(|res| {
         match res {
            Ok(r) => {
                ListItem::new(Line::from(vec![
                    Span::styled(format!("seq={:<3}", r.seq), Style::default().fg(THEME.muted)),
                    Span::raw(" "),
                    Span::styled(format!("ttl={:<3}", r.ttl), Style::default().fg(THEME.muted)),
                    Span::raw(" "),
                    Span::styled(format!("{:.2}ms", r.time.as_secs_f64() * 1000.0), Style::default().fg(THEME.success).add_modifier(Modifier::BOLD)),
                ]))
            },
            Err(e) => ListItem::new(Span::styled(format!("Error: {}", e), Style::default().fg(THEME.error))),
        }
    }).collect();

    let list_block = Block::default()
        .title(" Echo Replies ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(THEME.border));
        
    f.render_widget(List::new(items).block(list_block).style(Style::default().fg(THEME.fg)), list_area);

    // Stats Logic
    let stats_area = top_split[1];
    let mut min = 9999.0;
    let mut max = 0.0;
    let mut avg = 0.0;
    let mut count = 0;
    let mut loss = 0;
    let mut total = 0;
    
    // We iterate history to calc stats. 
    // Note: app.ping_history is limited to 50 items. 
    // This gives "Recent Stats" which is good.
    for res in &app.ping_history {
        total += 1;
        match res {
            Ok(r) => {
                let t = r.time.as_secs_f64() * 1000.0;
                if t < min { min = t; }
                if t > max { max = t; }
                avg += t;
                count += 1;
            },
            Err(_) => {
                loss += 1;
            }
        }
    }
    if count > 0 { avg /= count as f64; } else { min = 0.0; }
    let loss_pct = if total > 0 { (loss as f64 / total as f64) * 100.0 } else { 0.0 };

    let stats_block = Block::default()
        .title(" Recent Stats ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(THEME.secondary));
    
    let stats_text = vec![
        Line::from(vec![Span::raw("Sent: "), Span::styled(format!("{}", total), Style::default().fg(THEME.fg).add_modifier(Modifier::BOLD))]),
        Line::from(vec![Span::raw("Loss: "), Span::styled(format!("{:.1}%", loss_pct), Style::default().fg(if loss > 0 { THEME.error } else { THEME.success }))]),
        Line::from(""),
        Line::from(vec![Span::raw("Min:  "), Span::styled(format!("{:.1}ms", min), Style::default().fg(THEME.primary))]),
        Line::from(vec![Span::raw("Avg:  "), Span::styled(format!("{:.1}ms", avg), Style::default().fg(THEME.primary).add_modifier(Modifier::BOLD))]),
        Line::from(vec![Span::raw("Max:  "), Span::styled(format!("{:.1}ms", max), Style::default().fg(THEME.primary))]),
    ];
    
    f.render_widget(Paragraph::new(stats_text).block(stats_block), stats_area);


    // Graph
    let ping_data: Vec<(f64, f64)> = app.ping_rtt_history.iter().enumerate().map(|(i, &v)| (i as f64, v)).collect();
    let ping_max = app.ping_rtt_history.iter().max_by(|a, b| a.total_cmp(b)).unwrap_or(&100.0).max(50.0) * 2.0;

    let chart = Chart::new(vec![
        Dataset::default().marker(symbols::Marker::Braille).graph_type(GraphType::Line).style(Style::default().fg(THEME.primary)).data(&ping_data)
    ])
    .block(Block::default().title(" RTT History ").borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(THEME.border)))
    .x_axis(Axis::default().bounds([0.0, 100.0]).style(Style::default().fg(THEME.muted)))
    .y_axis(Axis::default().bounds([0.0, ping_max as f64]).style(Style::default().fg(THEME.muted)));
    
    f.render_widget(chart, content_split[1]);
}

fn render_dns(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(3), Constraint::Min(1)].as_ref())
        .split(area);

    let input_block = Block::default().title(" Domain ").borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(THEME.border));
    f.render_widget(Paragraph::new(app.dns_input.value()).block(input_block).style(Style::default().fg(THEME.fg)), chunks[0]);

    // Type Selector
    let types = vec!["A", "AAAA", "MX", "TXT", "NS"];
    let mut type_spans = vec![];
    let selected_type = match app.dns_record_type {
        hickory_resolver::proto::rr::RecordType::A => "A",
        hickory_resolver::proto::rr::RecordType::AAAA => "AAAA",
        hickory_resolver::proto::rr::RecordType::MX => "MX",
        hickory_resolver::proto::rr::RecordType::TXT => "TXT",
        hickory_resolver::proto::rr::RecordType::NS => "NS",
        _ => "Unknown",
    };

    for t in types {
        let is_selected = t == selected_type;
        type_spans.push(Span::styled(format!(" {} ", t), if is_selected { Style::default().bg(THEME.primary).fg(THEME.bg).add_modifier(Modifier::BOLD) } else { Style::default().fg(THEME.muted).bg(THEME.surface) }));
        type_spans.push(Span::raw(" "));
    }
    f.render_widget(Paragraph::new(Line::from(type_spans)).block(Block::default().title(" Record Type ").borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(THEME.border))), chunks[1]);

    // Results
    let res_block = Block::default().title(" Results ").borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(THEME.border));
    if let Some(res) = &app.dns_result {
        match res {
            Ok(r) => {
                let lines: Vec<ListItem> = match r {
                    DnsResult::A(recs) => recs.iter().map(|r| ListItem::new(format!("{} (TTL: {}s)", r.value, r.ttl))).collect(),
                    DnsResult::AAAA(recs) => recs.iter().map(|r| ListItem::new(format!("{} (TTL: {}s)", r.value, r.ttl))).collect(),
                    DnsResult::MX(recs) => recs.iter().map(|r| ListItem::new(format!("{} (TTL: {}s)", r.value, r.ttl))).collect(),
                    DnsResult::TXT(recs) => recs.iter().map(|r| ListItem::new(format!("{} (TTL: {}s)", r.value, r.ttl))).collect(),
                    DnsResult::NS(recs) => recs.iter().map(|r| ListItem::new(format!("{} (TTL: {}s)", r.value, r.ttl))).collect(),
                };
                f.render_widget(List::new(lines).block(res_block).style(Style::default().fg(THEME.success)), chunks[2]);
            },
            Err(e) => {
                f.render_widget(Paragraph::new(format!("Error: {}", e)).style(Style::default().fg(THEME.error)).block(res_block), chunks[2]);
            }
        }
    } else {
        f.render_widget(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).title(" Results ").style(Style::default().fg(THEME.muted)), chunks[2]);
    }
}
