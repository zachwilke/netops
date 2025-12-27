use std::{io, time::Duration};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

mod app;
mod ui;
mod tools;
mod theme;

use app::{App, CurrentScreen};

#[tokio::main]
async fn main() -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = App::new();
    app.start_background_tasks();

    // Run app
    let res = run_app(&mut terminal, &mut app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    Ok(())
}

use tui_input::backend::crossterm::EventHandler;

async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<()> {
    let tick_rate = Duration::from_millis(50);
    let mut last_tick = std::time::Instant::now();

    loop {
        terminal.draw(|f| ui::ui(f, app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            let evt = event::read()?;
            match evt {
                Event::Key(key) => {
                    // Quick Tab Switching (Alt + 1-8)
                    if key.modifiers.contains(event::KeyModifiers::ALT) {
                        match key.code {
                            KeyCode::Char('1') => { app.current_screen = CurrentScreen::Dashboard; continue; }
                            KeyCode::Char('2') => { app.current_screen = CurrentScreen::Ping; continue; }
                            KeyCode::Char('3') => { app.current_screen = CurrentScreen::Dns; continue; }
                            KeyCode::Char('4') => { app.current_screen = CurrentScreen::Sniffer; continue; }
                            KeyCode::Char('5') => { app.current_screen = CurrentScreen::Mtr; continue; }
                            KeyCode::Char('6') => { app.current_screen = CurrentScreen::Nmap; continue; }
                            KeyCode::Char('7') => { app.current_screen = CurrentScreen::ArpScan; continue; }
                            KeyCode::Char('8') => { app.current_screen = CurrentScreen::Connections; continue; }
                            _ => {}
                        }
                    }

                    if app.show_options {
                         if key.kind == KeyEventKind::Press {
                             match key.code {
                                 KeyCode::Esc => app.show_options = false,
                                 KeyCode::Up => {
                                     if app.options_scroll > 0 {
                                         app.options_scroll -= 1;
                                     }
                                 }
                                 KeyCode::Down => {
                                     let count = app.get_tool_options().len();
                                     if count > 0 && app.options_scroll < count - 1 {
                                         app.options_scroll += 1;
                                     }
                                 }
                                 KeyCode::Enter => {
                                     // Insert and close
                                     let opts = app.get_tool_options();
                                     if let Some((_, _, template)) = opts.get(app.options_scroll) {
                                         let val = template.to_string();
                                         // Append to active input
                                         match app.current_screen {
                                             CurrentScreen::Ping => {
                                                 // TuiInput doesn't have direct append string method easily exposed as "type chars", 
                                                 // but it handles KeyEvents. 
                                                 // Or we can assume we can convert string to events?
                                                 // Actually tui-input `handle_event` only takes events.
                                                 // But we can just create events? 
                                                 // Or better: accessing the value and replacing it is hard with just `Input`.
                                                 // `tui-input` 0.8+ allows `with_value`.
                                                 // Let's check `Cargo.toml`. `tui-input` = "0.8.0".
                                                 // Actually checking view lines: `use tui_input::Input;`
                                                 // Wait, modifying the input value directly?
                                                 // `app.ping_input` is `Input`.
                                                 // `Input` struct usually has `value()` accessor and maybe builder?
                                                 // If not, simulating keys is safest.
                                                 for c in val.chars() {
                                                     app.ping_input.handle_event(&Event::Key(crossterm::event::KeyEvent::new(KeyCode::Char(c), crossterm::event::KeyModifiers::NONE)));
                                                 }
                                             }
                                             CurrentScreen::Mtr => {
                                                  for c in val.chars() {
                                                     app.mtr_input.handle_event(&Event::Key(crossterm::event::KeyEvent::new(KeyCode::Char(c), crossterm::event::KeyModifiers::NONE)));
                                                 }
                                             }
                                             CurrentScreen::Nmap => {
                                                  for c in val.chars() {
                                                     app.nmap_input.handle_event(&Event::Key(crossterm::event::KeyEvent::new(KeyCode::Char(c), crossterm::event::KeyModifiers::NONE)));
                                                 }
                                              }
                                              CurrentScreen::ArpScan => {
                                                  for c in val.chars() {
                                                     app.arpscan_input.handle_event(&Event::Key(crossterm::event::KeyEvent::new(KeyCode::Char(c), crossterm::event::KeyModifiers::NONE)));
                                                  }
                                              }
                                              _ => {}
                                         }
                                     }
                                     app.show_options = false;
                                 }
                                 _ => {}
                             }
                         }
                         continue;
                    }

                     // Help Overlay Logic
                    if app.show_help {
                        if key.kind == KeyEventKind::Press {
                            app.show_help = false;
                        }
                        // Consume all events when help is showing
                        continue;
                    }

                     if key.kind == KeyEventKind::Press {
                        let mut handled = false;
                        match key.code {
                            KeyCode::Char('Q') => {
                                app.quit();
                                handled = true;
                            }
                            KeyCode::Char('D') if key.modifiers.contains(event::KeyModifiers::SHIFT) => {
                                app.current_screen = CurrentScreen::Dashboard;
                                handled = true;
                            }
                            KeyCode::Char('P') if key.modifiers.contains(event::KeyModifiers::SHIFT) => {
                                app.current_screen = CurrentScreen::Ping;
                                handled = true;
                            }
                            KeyCode::Char('N') if key.modifiers.contains(event::KeyModifiers::SHIFT) => {
                                app.current_screen = CurrentScreen::Dns;
                                handled = true;
                            }
                            KeyCode::Char('S') if key.modifiers.contains(event::KeyModifiers::SHIFT) => {
                                app.current_screen = CurrentScreen::Sniffer;
                                handled = true;
                            }
                            KeyCode::Char('M') if key.modifiers.contains(event::KeyModifiers::SHIFT) => {
                                app.current_screen = CurrentScreen::Mtr;
                                handled = true;
                            }
                            KeyCode::Char('R') if key.modifiers.contains(event::KeyModifiers::SHIFT) => {
                                app.current_screen = CurrentScreen::Nmap;
                                handled = true;
                            }
                             KeyCode::Char('A') if key.modifiers.contains(event::KeyModifiers::SHIFT) => {
                                app.current_screen = CurrentScreen::ArpScan;
                                handled = true;
                            }
                            KeyCode::Char('C') if key.modifiers.contains(event::KeyModifiers::SHIFT) => {
                                app.current_screen = CurrentScreen::Connections;
                                handled = true;
                            }
                            KeyCode::Char('?') | KeyCode::Char('H') => {
                                app.show_help = true;
                                handled = true;
                            }
                            KeyCode::Char('f') => {
                                if key.modifiers.contains(event::KeyModifiers::CONTROL) {
                                    app.show_options = !app.show_options;
                                    app.options_scroll = 0;
                                    handled = true;
                                }
                            }
                            _ => {}
                        }

                        // Screen specific keys
                        if !handled {
                            match app.current_screen {
                                CurrentScreen::Ping => {
                                    match key.code {
                                        KeyCode::Enter => {
                                            app.start_ping();
                                        }
                                        KeyCode::Esc => {
                                            app.stop_ping();
                                        }
                                        _ => {
                                            if !app.is_pinging {
                                                app.ping_input.handle_event(&Event::Key(key));
                                            }
                                        }
                                    }
                                }
                                CurrentScreen::Dns => {
                                    match key.code {
                                        KeyCode::Enter => {
                                            app.start_dns_lookup();
                                        }
                                        KeyCode::Tab => {
                                            app.next_dns_record_type();
                                        }
                                        _ => {
                                            app.dns_input.handle_event(&Event::Key(key));
                                        }
                                    }
                                }
                                CurrentScreen::Sniffer => {
                                    match key.code {
                                        KeyCode::Enter => {
                                            if app.sniffer_active {
                                                app.stop_sniffer();
                                            } else {
                                                app.start_sniffer();
                                            }
                                        }
                                        KeyCode::Esc => {
                                            if app.sniffer_active {
                                                 app.stop_sniffer();
                                            }
                                        }
                                        KeyCode::Left => {
                                            if app.selected_interface_index > 0 {
                                                app.selected_interface_index -= 1;
                                            }
                                        }
                                        KeyCode::Right => {
                                            if app.selected_interface_index < app.interfaces.len().saturating_sub(1) {
                                                app.selected_interface_index += 1;
                                            }
                                        }
                                        _ => {
                                            if !app.sniffer_active {
                                                app.sniffer_filter_input.handle_event(&Event::Key(key));
                                            }
                                        }
                                    }
                                }
                                CurrentScreen::Mtr => {
                                    match key.code {
                                        KeyCode::Enter => {
                                            app.start_mtr();
                                        }
                                        KeyCode::Esc => {
                                            app.stop_mtr();
                                        }
                                        KeyCode::Up => {
                                            if app.mtr_selected_hop > 0 {
                                                app.mtr_selected_hop -= 1;
                                                app.mtr_table_state.select(Some(app.mtr_selected_hop));
                                            }
                                        }
                                        KeyCode::Down => {
                                            if app.mtr_selected_hop < app.mtr_hops.len().saturating_sub(1) {
                                                app.mtr_selected_hop += 1;
                                                app.mtr_table_state.select(Some(app.mtr_selected_hop));
                                            }
                                        }
                                        _ => {
                                            if !app.mtr_active {
                                                app.mtr_input.handle_event(&Event::Key(key));
                                            }
                                        }
                                    }

                                }
                                CurrentScreen::Nmap => {
                                    match key.code {
                                        KeyCode::Enter => {
                                            app.start_nmap();
                                        }
                                        KeyCode::Esc => {
                                            app.stop_nmap();
                                        }
                                        _ => {
                                            if !app.nmap_active {
                                                app.nmap_input.handle_event(&Event::Key(key));
                                            }
                                        }
                                    }
                                }
                                CurrentScreen::ArpScan => {
                                    match key.code {
                                        KeyCode::Enter => {
                                            app.start_arpscan();
                                        }
                                        KeyCode::Esc => {
                                            app.stop_arpscan();
                                        }
                                        _ => {
                                            if !app.arpscan_active {
                                                app.arpscan_input.handle_event(&Event::Key(key));
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                },
                _ => {}
            }
        }

        if last_tick.elapsed() >= tick_rate {
             app.tick().await;
             last_tick = std::time::Instant::now();
        }

        if app.should_quit {
            return Ok(());
        }
    }
}
