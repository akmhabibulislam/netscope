use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow, Box as GtkBox, Button, HeaderBar, Label, Orientation, Paned, Stack, StackSidebar};
use libadwaita as adw;
use netscope_core::Protocol;
use netscope_dns::DnsInspector;
use netscope_network::collector::NetworkCollector;
use netscope_network::diagnostics::DiagnosticsEngine;
use netscope_security::SecurityRuleEngine;
use netscope_storage::StorageManager;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use tokio::runtime::Runtime;

pub fn run_application() {
    let app = Application::builder()
        .application_id("org.netscope.NetScope")
        .build();

    app.connect_startup(|_| {
        adw::init().ok();
        load_css();
    });

    app.connect_activate(build_ui);
    app.run();
}

fn load_css() {
    let provider = gtk4::CssProvider::new();
    let css_data = include_str!("../resources/styles/netscope.css");
    provider.load_from_data(css_data);

    if let Some(display) = gtk4::gdk::Display::default() {
        gtk4::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}

fn build_ui(app: &Application) {
    let rt = Arc::new(Runtime::new().unwrap());
    let collector = NetworkCollector::new();
    let storage = StorageManager::new(None).unwrap_or_else(|_| StorageManager::new_in_memory().unwrap());
    let rule_engine = Rc::new(RefCell::new(SecurityRuleEngine::new(vec![], vec![])));

    let window = ApplicationWindow::builder()
        .application(app)
        .title("NetScope — Linux Network Intelligence")
        .default_width(1150)
        .default_height(750)
        .build();

    let header_bar = HeaderBar::new();
    let title_label = Label::new(Some("NetScope"));
    title_label.add_css_class("heading");
    header_bar.set_title_widget(Some(&title_label));
    window.set_titlebar(Some(&header_bar));

    let paned = Paned::new(Orientation::Horizontal);
    paned.set_wide_handle(true);

    let stack = Stack::new();
    stack.set_transition_type(gtk4::StackTransitionType::Crossfade);
    stack.set_transition_duration(150);

    let sidebar = StackSidebar::new();
    sidebar.set_stack(&stack);
    sidebar.set_width_request(200);

    // 1. Dashboard View
    let (dash_view, update_dash) = create_dashboard_page(&collector, &storage, rt.clone());
    stack.add_titled(&dash_view, Some("dashboard"), "Dashboard");

    // 2. Connections View
    let (conn_view, update_conn) = create_connections_page(&collector, rt.clone());
    stack.add_titled(&conn_view, Some("connections"), "Connections");

    // 3. Processes View
    let (proc_view, update_proc) = create_processes_page(&collector, rt.clone());
    stack.add_titled(&proc_view, Some("processes"), "Processes");

    // 4. DNS Monitor View
    let (dns_view, update_dns) = create_dns_page(rt.clone());
    stack.add_titled(&dns_view, Some("dns"), "DNS Monitor");

    // 5. Diagnostics View
    let diag_view = create_diagnostics_page(rt.clone());
    stack.add_titled(&diag_view, Some("diagnostics"), "Diagnostics");

    // 6. Security View
    let (sec_view, update_sec) = create_security_page(&collector, rule_engine.clone(), &storage, rt.clone());
    stack.add_titled(&sec_view, Some("security"), "Security & Alerts");

    // 7. Settings View
    let settings_view = create_settings_page();
    stack.add_titled(&settings_view, Some("settings"), "Settings");

    paned.set_start_child(Some(&sidebar));
    paned.set_end_child(Some(&stack));
    paned.set_position(220);

    window.set_child(Some(&paned));
    window.present();

    // Initial load
    update_dash();
    update_conn();
    update_proc();
    update_dns();
    update_sec();

    // Periodic timer (1.5 seconds) for real-time monitoring
    glib::timeout_add_local(std::time::Duration::from_millis(1500), move || {
        update_dash();
        update_sec();
        glib::ControlFlow::Continue
    });
}

fn create_card(title: &str, value_label: &Label) -> GtkBox {
    let card = GtkBox::new(Orientation::Vertical, 6);
    card.add_css_class("card");

    let t_lbl = Label::new(Some(title));
    t_lbl.add_css_class("stat-label");
    t_lbl.set_halign(gtk4::Align::Start);

    value_label.add_css_class("stat-value");
    value_label.set_halign(gtk4::Align::Start);

    card.append(&t_lbl);
    card.append(value_label);
    card
}

fn create_dashboard_page(
    collector: &NetworkCollector,
    storage: &StorageManager,
    rt: Arc<Runtime>,
) -> (GtkBox, Rc<dyn Fn()>) {
    let container = GtkBox::new(Orientation::Vertical, 16);
    container.add_css_class("view-container");

    let header_box = GtkBox::new(Orientation::Horizontal, 12);
    let title = Label::new(Some("Network Overview"));
    title.add_css_class("title-1");
    header_box.append(&title);
    container.append(&header_box);

    // Stats Grid
    let grid_box = GtkBox::new(Orientation::Horizontal, 12);
    grid_box.set_homogeneous(true);

    let iface_val = Label::new(Some("Scanning..."));
    let iface_card = create_card("Active Interface", &iface_val);

    let rx_val = Label::new(Some("0.00 KB/s"));
    rx_val.add_css_class("accent-green");
    let rx_card = create_card("Download Speed", &rx_val);

    let tx_val = Label::new(Some("0.00 KB/s"));
    tx_val.add_css_class("accent-blue");
    let tx_card = create_card("Upload Speed", &tx_val);

    let total_val = Label::new(Some("0 MB"));
    let total_card = create_card("Total Transferred", &total_val);

    grid_box.append(&iface_card);
    grid_box.append(&rx_card);
    grid_box.append(&tx_card);
    grid_box.append(&total_card);
    container.append(&grid_box);

    // Interface Details Card
    let iface_details_box = GtkBox::new(Orientation::Vertical, 8);
    iface_details_box.add_css_class("card");
    let iface_detail_title = Label::new(Some("INTERFACE DETAILS"));
    iface_detail_title.add_css_class("stat-label");
    iface_detail_title.set_halign(gtk4::Align::Start);
    let iface_detail_content = Label::new(Some("IP: - | MAC: - | MTU: - | Status: -"));
    iface_detail_content.set_halign(gtk4::Align::Start);
    iface_details_box.append(&iface_detail_title);
    iface_details_box.append(&iface_detail_content);
    container.append(&iface_details_box);

    // Live Telemetry Summary
    let summary_box = GtkBox::new(Orientation::Vertical, 8);
    summary_box.add_css_class("card");
    let summary_title = Label::new(Some("SYSTEM TELEMETRY SUMMARY"));
    summary_title.add_css_class("stat-label");
    summary_title.set_halign(gtk4::Align::Start);
    let summary_content = Label::new(Some("Resolvers: 127.0.0.53 | Default Gateway: Calculating..."));
    summary_content.set_halign(gtk4::Align::Start);
    summary_box.append(&summary_title);
    summary_box.append(&summary_content);
    container.append(&summary_box);

    let col_clone = collector.clone();
    let storage_clone = storage.clone();

    let update_fn: Rc<dyn Fn()> = Rc::new(move || {
        let col = col_clone.clone();
        let st = storage_clone.clone();
        let (sample, ifaces) = rt.block_on(async {
            let s = col.collect_bandwidth_sample().await;
            let ifs = col.poll_interfaces().await;
            (s, ifs)
        });

        let _ = st.insert_bandwidth_sample(&sample);

        let if_name = sample.active_interface.clone().unwrap_or_else(|| "lo".to_string());
        iface_val.set_text(&if_name);

        let rx_kbps = sample.rx_speed_bps / 8000.0;
        let tx_kbps = sample.tx_speed_bps / 8000.0;
        rx_val.set_text(&format!("{:.2} KB/s", rx_kbps));
        tx_val.set_text(&format!("{:.2} KB/s", tx_kbps));

        let total_mb = (sample.rx_bytes_total + sample.tx_bytes_total) as f64 / (1024.0 * 1024.0);
        total_val.set_text(&format!("{:.2} MB", total_mb));

        if let Some(active) = ifaces.iter().find(|i| i.name == if_name) {
            let ip_str = active.ipv4_addresses.join(", ");
            let mac_str = active.mac_address.as_deref().unwrap_or("N/A");
            iface_detail_content.set_text(&format!(
                "IPv4: {} | MAC: {} | MTU: {} | State: {} | Packets Rx/Tx: {}/{}",
                if ip_str.is_empty() { "N/A" } else { &ip_str },
                mac_str,
                active.mtu,
                active.oper_state,
                active.stats.rx_packets,
                active.stats.tx_packets
            ));
        }

        let routes = DiagnosticsEngine::get_routing_table();
        let gw = routes.iter().find(|r| r.destination == "0.0.0.0").map(|r| r.gateway.as_str()).unwrap_or("None");
        let resolvers = DnsInspector::get_system_resolvers().join(", ");
        summary_content.set_text(&format!(
            "Default Gateway: {} | System DNS Resolvers: {} | Active Monitoring: Enabled",
            gw, resolvers
        ));
    });

    (container, update_fn)
}

fn create_connections_page(
    collector: &NetworkCollector,
    rt: Arc<Runtime>,
) -> (GtkBox, Rc<dyn Fn()>) {
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.add_css_class("view-container");

    let top_bar = GtkBox::new(Orientation::Horizontal, 12);
    let title = Label::new(Some("Active Network Connections"));
    title.add_css_class("title-1");
    top_bar.append(&title);

    let refresh_btn = Button::with_label("Refresh");
    top_bar.append(&refresh_btn);
    container.append(&top_bar);

    let scrolled = gtk4::ScrolledWindow::new();
    scrolled.set_vexpand(true);

    let list_box = gtk4::ListBox::new();
    list_box.add_css_class("card");
    scrolled.set_child(Some(&list_box));
    container.append(&scrolled);

    let col_clone = collector.clone();
    let rt_clone = rt.clone();
    let list_clone = list_box.clone();

    let update_fn: Rc<dyn Fn()> = Rc::new(move || {
        let col = col_clone.clone();
        let conns = rt_clone.block_on(async { col.poll_connections().await });

        // Clear existing children
        while let Some(child) = list_clone.first_child() {
            list_clone.remove(&child);
        }

        for conn in conns.into_iter().take(100) {
            let row = GtkBox::new(Orientation::Horizontal, 14);
            row.set_margin_top(6);
            row.set_margin_bottom(6);
            row.set_margin_start(12);
            row.set_margin_end(12);

            let proto_lbl = Label::new(Some(&conn.protocol.to_string()));
            proto_lbl.add_css_class("badge");
            proto_lbl.add_css_class(if conn.protocol == Protocol::Tcp { "badge-info" } else { "badge-warning" });

            let local_lbl = Label::new(Some(&format!("{}:{}", conn.local_addr, conn.local_port)));
            local_lbl.set_width_chars(22);
            local_lbl.set_halign(gtk4::Align::Start);

            let arrow = Label::new(Some("→"));
            arrow.add_css_class("accent-blue");

            let remote_lbl = Label::new(Some(&format!("{}:{}", conn.remote_addr, conn.remote_port)));
            remote_lbl.set_width_chars(22);
            remote_lbl.set_halign(gtk4::Align::Start);

            let state_lbl = Label::new(Some(&conn.state.to_string()));
            state_lbl.set_width_chars(14);
            state_lbl.add_css_class("badge");
            state_lbl.add_css_class(if conn.state == netscope_core::ConnectionState::Established {
                "badge-success"
            } else if conn.state == netscope_core::ConnectionState::Listen {
                "badge-info"
            } else {
                "badge-warning"
            });

            let proc_str = conn.process.as_ref().map(|p| format!("{} (PID: {})", p.name, p.pid)).unwrap_or_else(|| "-".to_string());
            let proc_lbl = Label::new(Some(&proc_str));
            proc_lbl.set_halign(gtk4::Align::Start);
            proc_lbl.set_hexpand(true);

            row.append(&proto_lbl);
            row.append(&local_lbl);
            row.append(&arrow);
            row.append(&remote_lbl);
            row.append(&state_lbl);
            row.append(&proc_lbl);

            list_clone.append(&row);
        }
    });

    let update_clone = update_fn.clone();
    refresh_btn.connect_clicked(move |_| {
        update_clone();
    });

    (container, update_fn)
}

fn create_processes_page(
    collector: &NetworkCollector,
    rt: Arc<Runtime>,
) -> (GtkBox, Rc<dyn Fn()>) {
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.add_css_class("view-container");

    let title = Label::new(Some("Per-Process Network Usage"));
    title.add_css_class("title-1");
    container.append(&title);

    let scrolled = gtk4::ScrolledWindow::new();
    scrolled.set_vexpand(true);

    let list_box = gtk4::ListBox::new();
    list_box.add_css_class("card");
    scrolled.set_child(Some(&list_box));
    container.append(&scrolled);

    let col_clone = collector.clone();
    let rt_clone = rt.clone();
    let list_clone = list_box.clone();

    let update_fn: Rc<dyn Fn()> = Rc::new(move || {
        let col = col_clone.clone();
        let conns = rt_clone.block_on(async { col.poll_connections().await });

        let mut proc_map: std::collections::HashMap<String, (u32, usize, Vec<Protocol>, Option<std::path::PathBuf>)> = std::collections::HashMap::new();

        for conn in conns {
            if let Some(p) = conn.process {
                let entry = proc_map.entry(p.name).or_insert((p.pid, 0, Vec::new(), p.exe_path));
                entry.1 += 1;
                if !entry.2.contains(&conn.protocol) {
                    entry.2.push(conn.protocol);
                }
            }
        }

        while let Some(child) = list_clone.first_child() {
            list_clone.remove(&child);
        }

        for (name, (pid, count, protos, path)) in proc_map {
            let row = GtkBox::new(Orientation::Horizontal, 14);
            row.set_margin_top(8);
            row.set_margin_bottom(8);
            row.set_margin_start(12);
            row.set_margin_end(12);

            let pid_badge = Label::new(Some(&format!("PID {}", pid)));
            pid_badge.add_css_class("badge");
            pid_badge.add_css_class("badge-info");

            let name_lbl = Label::new(Some(&name));
            name_lbl.add_css_class("heading");
            name_lbl.set_width_chars(18);
            name_lbl.set_halign(gtk4::Align::Start);

            let sockets_lbl = Label::new(Some(&format!("{} open sockets", count)));
            sockets_lbl.set_width_chars(16);
            sockets_lbl.set_halign(gtk4::Align::Start);

            let protos_str = protos.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
            let protos_lbl = Label::new(Some(&protos_str));
            protos_lbl.set_width_chars(12);

            let path_str = path.map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| "-".to_string());
            let path_lbl = Label::new(Some(&path_str));
            path_lbl.set_halign(gtk4::Align::Start);
            path_lbl.set_hexpand(true);
            path_lbl.add_css_class("dim-label");

            row.append(&pid_badge);
            row.append(&name_lbl);
            row.append(&sockets_lbl);
            row.append(&protos_lbl);
            row.append(&path_lbl);

            list_clone.append(&row);
        }
    });

    (container, update_fn)
}

fn create_dns_page(rt: Arc<Runtime>) -> (GtkBox, Rc<dyn Fn()>) {
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.add_css_class("view-container");

    let title = Label::new(Some("DNS Diagnostics & History"));
    title.add_css_class("title-1");
    container.append(&title);

    let resolvers_box = GtkBox::new(Orientation::Horizontal, 10);
    resolvers_box.add_css_class("card");
    let res_lbl = Label::new(Some("Configured Resolvers: 127.0.0.53"));
    res_lbl.set_halign(gtk4::Align::Start);
    resolvers_box.append(&res_lbl);
    container.append(&resolvers_box);

    let query_box = GtkBox::new(Orientation::Horizontal, 8);
    let entry = gtk4::Entry::new();
    entry.set_placeholder_text(Some("Enter domain to query, e.g. archlinux.org..."));
    entry.set_hexpand(true);
    let query_btn = Button::with_label("Resolve Domain");
    query_btn.add_css_class("suggested-action");
    query_box.append(&entry);
    query_box.append(&query_btn);
    container.append(&query_box);

    let result_card = GtkBox::new(Orientation::Vertical, 6);
    result_card.add_css_class("card");
    let result_title = Label::new(Some("QUERY RESULT"));
    result_title.add_css_class("stat-label");
    result_title.set_halign(gtk4::Align::Start);
    let result_text = Label::new(Some("Ready to query"));
    result_text.set_halign(gtk4::Align::Start);
    result_card.append(&result_title);
    result_card.append(&result_text);
    container.append(&result_card);

    let rt_clone = rt.clone();
    let res_text_clone = result_text.clone();
    let entry_clone = entry.clone();

    query_btn.connect_clicked(move |_| {
        let domain = entry_clone.text().to_string();
        if domain.is_empty() {
            return;
        }

        res_text_clone.set_text("Resolving...");
        let rt = rt_clone.clone();
        let (sender, receiver) = async_channel::bounded::<Result<netscope_core::DnsRecord, String>>(1);

        std::thread::spawn(move || {
            let res = rt.block_on(async {
                if let Ok(inspector) = DnsInspector::new() {
                    inspector.resolve(&domain, "A").await.map_err(|e| e.to_string())
                } else {
                    Err("Failed to initialize resolver".to_string())
                }
            });
            let _ = sender.send_blocking(res);
        });

        let lbl = res_text_clone.clone();
        glib::spawn_future_local(async move {
            if let Ok(res) = receiver.recv().await {
                match res {
                    Ok(rec) => {
                        lbl.set_text(&format!(
                            "Domain: {} | Answers: {} | Duration: {}ms | Resolver: {}",
                            rec.query,
                            rec.response.unwrap_or_else(|| "None".to_string()),
                            rec.duration_ms.unwrap_or(0),
                            rec.resolver
                        ));
                    }
                    Err(e) => {
                        lbl.set_text(&format!("Error: {}", e));
                    }
                }
            }
        });
    });

    let update_fn: Rc<dyn Fn()> = Rc::new(move || {
        let r = DnsInspector::get_system_resolvers().join(", ");
        res_lbl.set_text(&format!("Configured DNS Resolvers: {}", r));
    });

    (container, update_fn)
}

fn create_diagnostics_page(rt: Arc<Runtime>) -> GtkBox {
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.add_css_class("view-container");

    let title = Label::new(Some("Network Diagnostics"));
    title.add_css_class("title-1");
    container.append(&title);

    let tools_box = GtkBox::new(Orientation::Horizontal, 12);
    let ping_btn = Button::with_label("Run Ping (1.1.1.1)");
    let tcp_btn = Button::with_label("Test TCP (google.com:443)");
    let routes_btn = Button::with_label("Refresh Routes");
    tools_box.append(&ping_btn);
    tools_box.append(&tcp_btn);
    tools_box.append(&routes_btn);
    container.append(&tools_box);

    let result_box = GtkBox::new(Orientation::Vertical, 8);
    result_box.add_css_class("card");
    result_box.set_vexpand(true);
    let res_lbl = Label::new(Some("Select a diagnostic tool above to run tests."));
    res_lbl.set_halign(gtk4::Align::Start);
    res_lbl.set_valign(gtk4::Align::Start);
    result_box.append(&res_lbl);
    container.append(&result_box);

    let lbl_ping = res_lbl.clone();
    ping_btn.connect_clicked(move |_| {
        lbl_ping.set_text("Pinging 1.1.1.1 (4 packets)...");
        let (sender, receiver) = async_channel::bounded::<Result<netscope_network::diagnostics::PingResult, String>>(1);
        std::thread::spawn(move || {
            let res = DiagnosticsEngine::ping_host("1.1.1.1", 4).map_err(|e| e.to_string());
            let _ = sender.send_blocking(res);
        });

        let l = lbl_ping.clone();
        glib::spawn_future_local(async move {
            if let Ok(res) = receiver.recv().await {
                match res {
                    Ok(p) => {
                        l.set_text(&format!(
                            "Target: {}\nPackets Transmitted: {}\nPackets Received: {}\nPacket Loss: {}%\nMin Latency: {:.2} ms\nAvg Latency: {:.2} ms\nMax Latency: {:.2} ms",
                            p.target, p.transmitted, p.received, p.packet_loss_percent,
                            p.min_latency_ms.unwrap_or(0.0),
                            p.avg_latency_ms.unwrap_or(0.0),
                            p.max_latency_ms.unwrap_or(0.0)
                        ));
                    }
                    Err(e) => {
                        l.set_text(&format!("Ping failed: {}", e));
                    }
                }
            }
        });
    });

    let lbl_tcp = res_lbl.clone();
    let rt_clone = rt.clone();
    tcp_btn.connect_clicked(move |_| {
        lbl_tcp.set_text("Connecting to google.com:443 via TCP...");
        let rt = rt_clone.clone();
        let (sender, receiver) = async_channel::bounded(1);
        std::thread::spawn(move || {
            let res = rt.block_on(async {
                DiagnosticsEngine::test_tcp_port("google.com", 443, std::time::Duration::from_secs(3)).await
            });
            let _ = sender.send_blocking(res);
        });

        let l = lbl_tcp.clone();
        glib::spawn_future_local(async move {
            if let Ok(res) = receiver.recv().await {
                if res.is_reachable {
                    l.set_text(&format!("Connection Successful!\nTarget: google.com:443\nLatency: {:.2} ms", res.latency_ms.unwrap_or(0.0)));
                } else {
                    l.set_text(&format!("Connection Failed!\nError: {}", res.error.unwrap_or_default()));
                }
            }
        });
    });

    let lbl_routes = res_lbl.clone();
    routes_btn.connect_clicked(move |_| {
        let rts = DiagnosticsEngine::get_routing_table();
        let mut text = String::from("Kernel Routing Table:\n\n");
        text.push_str(&format!("{:<18} {:<18} {:<18} {:<8} {:<8}\n", "Destination", "Gateway", "Genmask", "Flags", "Iface"));
        text.push_str(&"-".repeat(70));
        text.push('\n');
        for r in rts {
            text.push_str(&format!("{:<18} {:<18} {:<18} {:<8} {:<8}\n", r.destination, r.gateway, r.genmask, r.flags, r.interface));
        }
        lbl_routes.set_text(&text);
    });

    container
}

fn create_security_page(
    collector: &NetworkCollector,
    rule_engine: Rc<RefCell<SecurityRuleEngine>>,
    storage: &StorageManager,
    rt: Arc<Runtime>,
) -> (GtkBox, Rc<dyn Fn()>) {
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.add_css_class("view-container");

    let title = Label::new(Some("Security Analysis & Threat Intelligence"));
    title.add_css_class("title-1");
    container.append(&title);

    let scrolled = gtk4::ScrolledWindow::new();
    scrolled.set_vexpand(true);

    let list_box = gtk4::ListBox::new();
    list_box.add_css_class("card");
    scrolled.set_child(Some(&list_box));
    container.append(&scrolled);

    let col_clone = collector.clone();
    let engine_clone = rule_engine.clone();
    let storage_clone = storage.clone();
    let list_clone = list_box.clone();

    let update_fn: Rc<dyn Fn()> = Rc::new(move || {
        let col = col_clone.clone();
        let conns = rt.block_on(async { col.poll_connections().await });
        let alerts = engine_clone.borrow_mut().evaluate_connections(&conns);

        for a in &alerts {
            let _ = storage_clone.insert_alert(a);
        }

        while let Some(child) = list_clone.first_child() {
            list_clone.remove(&child);
        }

        if alerts.is_empty() {
            let row = GtkBox::new(Orientation::Horizontal, 10);
            row.set_margin_top(12);
            row.set_margin_bottom(12);
            row.set_margin_start(16);
            let lbl = Label::new(Some("No active security anomalies detected. System operating normally."));
            lbl.add_css_class("accent-green");
            row.append(&lbl);
            list_clone.append(&row);
            return;
        }

        for alert in alerts {
            let row = GtkBox::new(Orientation::Vertical, 6);
            row.set_margin_top(10);
            row.set_margin_bottom(10);
            row.set_margin_start(12);
            row.set_margin_end(12);

            let header_row = GtkBox::new(Orientation::Horizontal, 10);
            let sev_badge = Label::new(Some(&alert.severity.to_string()));
            sev_badge.add_css_class("badge");
            sev_badge.add_css_class(match alert.severity {
                netscope_core::AlertSeverity::High | netscope_core::AlertSeverity::Critical => "badge-danger",
                netscope_core::AlertSeverity::Medium => "badge-warning",
                _ => "badge-info",
            });

            let t_lbl = Label::new(Some(&alert.title));
            t_lbl.add_css_class("heading");
            t_lbl.set_halign(gtk4::Align::Start);
            t_lbl.set_hexpand(true);

            let rule_lbl = Label::new(Some(&alert.rule_id));
            rule_lbl.add_css_class("dim-label");

            header_row.append(&sev_badge);
            header_row.append(&t_lbl);
            header_row.append(&rule_lbl);

            let msg_lbl = Label::new(Some(&alert.message));
            msg_lbl.set_wrap(true);
            msg_lbl.set_halign(gtk4::Align::Start);

            row.append(&header_row);
            row.append(&msg_lbl);

            list_clone.append(&row);
        }
    });

    (container, update_fn)
}

fn create_settings_page() -> GtkBox {
    let container = GtkBox::new(Orientation::Vertical, 16);
    container.add_css_class("view-container");

    let title = Label::new(Some("Application Settings"));
    title.add_css_class("title-1");
    container.append(&title);

    let card = GtkBox::new(Orientation::Vertical, 12);
    card.add_css_class("card");

    let row1 = GtkBox::new(Orientation::Horizontal, 12);
    let lbl1 = Label::new(Some("Enable External Public IP & Geolocation Lookups"));
    lbl1.set_hexpand(true);
    lbl1.set_halign(gtk4::Align::Start);
    let sw1 = gtk4::Switch::new();
    sw1.set_active(false);
    row1.append(&lbl1);
    row1.append(&sw1);

    let row2 = GtkBox::new(Orientation::Horizontal, 12);
    let lbl2 = Label::new(Some("Desktop Notifications on High-Severity Threats"));
    lbl2.set_hexpand(true);
    lbl2.set_halign(gtk4::Align::Start);
    let sw2 = gtk4::Switch::new();
    sw2.set_active(true);
    row2.append(&lbl2);
    row2.append(&sw2);

    let row3 = GtkBox::new(Orientation::Horizontal, 12);
    let lbl3 = Label::new(Some("Data Retention Period (Days): 30"));
    lbl3.set_hexpand(true);
    lbl3.set_halign(gtk4::Align::Start);
    row3.append(&lbl3);

    card.append(&row1);
    card.append(&row2);
    card.append(&row3);
    container.append(&card);

    let about_card = GtkBox::new(Orientation::Vertical, 6);
    about_card.add_css_class("card");
    let about_title = Label::new(Some("ABOUT NETSCOPE"));
    about_title.add_css_class("stat-label");
    about_title.set_halign(gtk4::Align::Start);
    let about_desc = Label::new(Some("NetScope v0.1.0\nProfessional, Cross-Distribution Linux Network Intelligence\nBuilt with Rust, GTK4 & Libadwaita. Privacy by default."));
    about_desc.set_halign(gtk4::Align::Start);
    about_card.append(&about_title);
    about_card.append(&about_desc);
    container.append(&about_card);

    container
}
