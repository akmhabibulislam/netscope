use crate::graph::BandwidthGraph;
use crate::state::AppState;
use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{
    Application, ApplicationWindow, Box as GtkBox, Button, Entry, HeaderBar, Label, Orientation,
    Paned, ScrolledWindow, Stack, StackSidebar, Window,
};
use libadwaita as adw;
use netscope_core::Protocol;
use netscope_dns::DnsInspector;
use netscope_network::diagnostics::DiagnosticsEngine;
use netscope_network::firewall::NetworkFirewall;
use netscope_network::investigation::Investigator;
use netscope_network::speedtest::SpeedTestEngine;
use netscope_network::wifi::WifiScanner;
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
    provider.load_from_string(css_data);

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
    let state = AppState::new();

    let window = ApplicationWindow::builder()
        .application(app)
        .title("NetScope 2.0 — Linux Network Intelligence")
        .default_width(1280)
        .default_height(820)
        .build();

    // Top HeaderBar with Linear styling
    let header_bar = HeaderBar::new();
    let title_box = GtkBox::new(Orientation::Horizontal, 8);
    let logo_lbl = Label::new(Some("NETSCOPE"));
    logo_lbl.add_css_class("heading-2");
    let ver_badge = Label::new(Some("v2.0 PRO"));
    ver_badge.add_css_class("badge");
    ver_badge.add_css_class("badge-info");
    title_box.append(&logo_lbl);
    title_box.append(&ver_badge);
    header_bar.set_title_widget(Some(&title_box));

    // Global Command Palette Button (Ctrl+K)
    let palette_btn = Button::with_label("⌘ Search or Run (Ctrl+K)");
    palette_btn.add_css_class("subtext");
    header_bar.pack_start(&palette_btn);

    window.set_titlebar(Some(&header_bar));

    let paned = Paned::new(Orientation::Horizontal);
    paned.set_wide_handle(true);

    let stack = Stack::new();
    stack.set_transition_type(gtk4::StackTransitionType::Crossfade);
    stack.set_transition_duration(120);

    let sidebar = StackSidebar::new();
    sidebar.set_stack(&stack);
    sidebar.set_width_request(220);

    // 1. Overview Dashboard
    let (dash_view, update_dash) = create_dashboard_page(&state, rt.clone());
    stack.add_titled(&dash_view, Some("dashboard"), "Overview");

    // 2. Active Connections + Inspector
    let (conn_view, update_conn) = create_connections_page(&state, rt.clone(), window.clone());
    stack.add_titled(&conn_view, Some("connections"), "Connections");

    // 3. Applications Network Usage
    let (proc_view, update_proc) = create_processes_page(&state, rt.clone());
    stack.add_titled(&proc_view, Some("processes"), "Applications");

    // 4. Live In/Out Packets Sniffer
    let (packets_view, update_packets) = create_packets_page(&state);
    stack.add_titled(&packets_view, Some("packets"), "Packet Inspector");

    // 4b. Network Conversations / Flows
    let (flows_view, update_flows) = create_flows_page(&state);
    stack.add_titled(&flows_view, Some("flows"), "Active Conversations");

    // 5. Timeline of Network Events
    let (timeline_view, update_timeline) = create_timeline_page(&state);
    stack.add_titled(&timeline_view, Some("timeline"), "Network Timeline");

    // 6. Network Investigation (IP/Domain)
    let investigate_view = create_investigation_page(rt.clone());
    stack.add_titled(&investigate_view, Some("investigate"), "Investigation");

    // 7. Internet Speed & Throughput Benchmark
    let speed_view = create_speedtest_page(rt.clone());
    stack.add_titled(&speed_view, Some("speedtest"), "Speed & Benchmark");

    // 8. Wi-Fi & RF Intelligence
    let (wifi_view, update_wifi) = create_wifi_page(&state, rt.clone());
    stack.add_titled(&wifi_view, Some("wifi"), "Wi-Fi & RF");

    // 9. DNS Intelligence & Querying
    let (dns_view, update_dns) = create_dns_page(rt.clone());
    stack.add_titled(&dns_view, Some("dns"), "DNS Intelligence");

    // 10. Diagnostics (Ping, TCP, Routes)
    let diag_view = create_diagnostics_page(rt.clone());
    stack.add_titled(&diag_view, Some("diagnostics"), "Diagnostics");

    // 11. Security Center & Threat Intel
    let (sec_view, update_sec) = create_security_page(&state, rt.clone());
    stack.add_titled(&sec_view, Some("security"), "Security Center");

    // 12. Settings & Data Quotas
    let settings_view = create_settings_page(&state);
    stack.add_titled(&settings_view, Some("settings"), "Settings & Quotas");

    paned.set_start_child(Some(&sidebar));
    paned.set_end_child(Some(&stack));
    paned.set_position(230);

    window.set_child(Some(&paned));

    // Connect Command Palette Dialog
    let stack_clone = stack.clone();
    let win_clone = window.clone();
    palette_btn.connect_clicked(move |_| {
        show_command_palette(&win_clone, &stack_clone);
    });

    // Keyboard shortcut controller for Ctrl+K
    let key_controller = gtk4::EventControllerKey::new();
    let stack_for_key = stack.clone();
    let win_for_key = window.clone();
    key_controller.connect_key_pressed(move |_, keyval, _, state| {
        if state.contains(gtk4::gdk::ModifierType::CONTROL_MASK) && keyval == gtk4::gdk::Key::k {
            show_command_palette(&win_for_key, &stack_for_key);
            glib::Propagation::Stop
        } else {
            glib::Propagation::Proceed
        }
    });
    window.add_controller(key_controller);

    window.present();

    // Initial triggers
    update_dash();
    update_conn();
    update_proc();
    update_packets();
    update_flows();
    update_timeline();
    update_wifi();
    update_dns();
    update_sec();

    // High performance background refresh (every 1.5 seconds)
    glib::timeout_add_local(std::time::Duration::from_millis(1500), move || {
        update_dash();
        update_packets();
        update_flows();
        update_sec();
        glib::ControlFlow::Continue
    });
}

fn create_card(title: &str, value_label: &Label) -> GtkBox {
    let card = GtkBox::new(Orientation::Vertical, 4);
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

fn create_dashboard_page(state: &AppState, rt: Arc<Runtime>) -> (GtkBox, Rc<dyn Fn()>) {
    let container = GtkBox::new(Orientation::Vertical, 16);
    container.add_css_class("view-container");

    let header_box = GtkBox::new(Orientation::Horizontal, 12);
    let title = Label::new(Some("Network Telemetry Overview"));
    title.add_css_class("heading-1");
    header_box.append(&title);
    container.append(&header_box);

    // Primary Metric Cards
    let grid_box = GtkBox::new(Orientation::Horizontal, 12);
    grid_box.set_homogeneous(true);

    let iface_val = Label::new(Some("wlan0"));
    let iface_card = create_card("Active Interface", &iface_val);

    let rx_val = Label::new(Some("0.0 KB/s"));
    rx_val.add_css_class("accent-green");
    let rx_card = create_card("Download Speed", &rx_val);

    let tx_val = Label::new(Some("0.0 KB/s"));
    tx_val.add_css_class("accent-blue");
    let tx_card = create_card("Upload Speed", &tx_val);

    let quota_val = Label::new(Some("0 MB / 5.0 GB"));
    let quota_card = create_card("Daily Data Allowance", &quota_val);

    grid_box.append(&iface_card);
    grid_box.append(&rx_card);
    grid_box.append(&tx_card);
    grid_box.append(&quota_card);
    container.append(&grid_box);

    // 60-Second Real-Time Waveform Graph
    let graph = BandwidthGraph::new();
    container.append(graph.widget());

    // Interface Info Card
    let iface_box = GtkBox::new(Orientation::Vertical, 6);
    iface_box.add_css_class("card");
    let iface_title = Label::new(Some("INTERFACE & LINK HEALTH"));
    iface_title.add_css_class("stat-label");
    iface_title.set_halign(gtk4::Align::Start);
    let iface_detail = Label::new(Some("Loading interface properties..."));
    iface_detail.set_halign(gtk4::Align::Start);
    iface_box.append(&iface_title);
    iface_box.append(&iface_detail);
    container.append(&iface_box);

    let state_clone = state.clone();
    let graph_clone = graph.clone();
    let rt_clone = rt.clone();

    let update_fn: Rc<dyn Fn()> = Rc::new(move || {
        let st = state_clone.clone();
        let gr = graph_clone.clone();
        let rt = rt_clone.clone();

        let if_val = iface_val.clone();
        let r_val = rx_val.clone();
        let t_val = tx_val.clone();
        let q_val = quota_val.clone();
        let if_det = iface_detail.clone();

        let (sender, receiver) = async_channel::bounded(1);
        std::thread::spawn(move || {
            let res = rt.block_on(async {
                let s = st.collector.collect_bandwidth_sample().await;
                let ifs = st.collector.poll_interfaces().await;
                (s, ifs, st)
            });
            let _ = sender.send_blocking(res);
        });

        glib::spawn_future_local(async move {
            if let Ok((sample, ifaces, st)) = receiver.recv().await {
                gr.push_sample(sample.rx_speed_bps, sample.tx_speed_bps);
                let _ = st.storage.insert_bandwidth_sample(&sample);

                let active_if = sample
                    .active_interface
                    .clone()
                    .unwrap_or_else(|| "lo".to_string());
                if_val.set_text(&active_if);

                r_val.set_text(&format!("{:.2} KB/s", sample.rx_speed_bps / 8000.0));
                t_val.set_text(&format!("{:.2} KB/s", sample.tx_speed_bps / 8000.0));

                let used_mb = (sample.rx_bytes_total + sample.tx_bytes_total) / (1024 * 1024);
                q_val.set_text(&format!("{} MB / 5.0 GB", used_mb));

                if let Some(active) = ifaces.iter().find(|i| i.name == active_if) {
                    let ip_str = active.ipv4_addresses.join(", ");
                    let mac_str = active.mac_address.as_deref().unwrap_or("N/A");
                    if_det.set_text(&format!(
                        "IPv4: {} | MAC: {} | MTU: {} | State: {} | Total Packets Rx/Tx: {}/{}",
                        if ip_str.is_empty() { "N/A" } else { &ip_str },
                        mac_str,
                        active.mtu,
                        active.oper_state,
                        active.stats.rx_packets,
                        active.stats.tx_packets
                    ));
                }
            }
        });
    });

    (container, update_fn)
}

fn create_connections_page(
    state: &AppState,
    rt: Arc<Runtime>,
    parent_window: ApplicationWindow,
) -> (GtkBox, Rc<dyn Fn()>) {
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.add_css_class("view-container");

    let top_bar = GtkBox::new(Orientation::Horizontal, 12);
    let title = Label::new(Some("Active Network Connections"));
    title.add_css_class("heading-1");
    top_bar.append(&title);

    let refresh_btn = Button::with_label("Refresh");
    top_bar.append(&refresh_btn);
    container.append(&top_bar);

    let scrolled = ScrolledWindow::new();
    scrolled.set_vexpand(true);

    let list_box = gtk4::ListBox::new();
    list_box.add_css_class("card");
    scrolled.set_child(Some(&list_box));
    container.append(&scrolled);

    let state_clone = state.clone();
    let rt_clone = rt.clone();
    let list_clone = list_box.clone();
    let parent_clone = parent_window.clone();

    let update_fn: Rc<dyn Fn()> = Rc::new(move || {
        let st = state_clone.clone();
        let rt = rt_clone.clone();
        let list = list_clone.clone();
        let parent = parent_clone.clone();

        let (sender, receiver) = async_channel::bounded(1);
        std::thread::spawn(move || {
            let conns = rt.block_on(async { st.collector.poll_connections().await });
            let _ = sender.send_blocking(conns);
        });

        glib::spawn_future_local(async move {
            if let Ok(conns) = receiver.recv().await {
                while let Some(child) = list.first_child() {
                    list.remove(&child);
                }

                for conn in conns.into_iter().take(80) {
                    let row = GtkBox::new(Orientation::Horizontal, 12);
                    row.set_margin_top(4);
                    row.set_margin_bottom(4);
                    row.set_margin_start(10);
                    row.set_margin_end(10);

                    let proto_lbl = Label::new(Some(&conn.protocol.to_string()));
                    proto_lbl.add_css_class("badge");
                    proto_lbl.add_css_class(if conn.protocol == Protocol::Tcp {
                        "badge-info"
                    } else {
                        "badge-warning"
                    });

                    let local_lbl =
                        Label::new(Some(&format!("{}:{}", conn.local_addr, conn.local_port)));
                    local_lbl.set_width_chars(21);
                    local_lbl.set_halign(gtk4::Align::Start);

                    let arrow = Label::new(Some("→"));
                    arrow.add_css_class("accent-blue");

                    let remote_lbl =
                        Label::new(Some(&format!("{}:{}", conn.remote_addr, conn.remote_port)));
                    remote_lbl.set_width_chars(21);
                    remote_lbl.set_halign(gtk4::Align::Start);

                    let state_lbl = Label::new(Some(&conn.state.to_string()));
                    state_lbl.set_width_chars(13);
                    state_lbl.add_css_class("badge");
                    state_lbl.add_css_class(
                        if conn.state == netscope_core::ConnectionState::Established {
                            "badge-success"
                        } else if conn.state == netscope_core::ConnectionState::Listen {
                            "badge-info"
                        } else {
                            "badge-warning"
                        },
                    );

                    let proc_str = conn
                        .process
                        .as_ref()
                        .map(|p| format!("{} (PID {})", p.name, p.pid))
                        .unwrap_or_else(|| "-".to_string());
                    let proc_lbl = Label::new(Some(&proc_str));
                    proc_lbl.set_halign(gtk4::Align::Start);
                    proc_lbl.set_hexpand(true);

                    let inspect_btn = Button::with_label("Inspect");
                    inspect_btn.add_css_class("subtext");
                    let conn_copy = conn.clone();
                    let p_win = parent.clone();
                    inspect_btn.connect_clicked(move |_| {
                        show_connection_inspector(&p_win, &conn_copy);
                    });

                    let kill_btn = Button::with_label("Drop");
                    kill_btn.add_css_class("destructive-action");
                    let local_s = format!("{}:{}", conn.local_addr, conn.local_port);
                    let remote_s = format!("{}:{}", conn.remote_addr, conn.remote_port);
                    let p_win = parent.clone();
                    kill_btn.connect_clicked(move |_| {
                        let alert = gtk4::AlertDialog::builder()
                            .modal(true)
                            .message(format!("Terminate TCP Connection?\n\n{} -> {}", local_s, remote_s))
                            .detail("This will immediately send a TCP reset (ss -K) to tear down the socket. Active transfers will be dropped.")
                            .buttons(["Cancel", "Terminate Connection"])
                            .cancel_button(0)
                            .default_button(1)
                            .build();

                        let loc = local_s.clone();
                        let rem = remote_s.clone();
                        let pw = p_win.clone();
                        let pw_for_err = p_win.clone();
                        alert.choose(Some(&pw), None::<&gtk4::gio::Cancellable>, move |choice| {
                            if choice == Ok(1) {
                                match NetworkFirewall::kill_connection(&loc, &rem) {
                                    Ok(msg) => {
                                        tracing::info!("{}", msg);
                                    }
                                    Err(e) => {
                                        let err_dialog = gtk4::AlertDialog::builder()
                                            .modal(true)
                                            .message("Failed to Terminate Connection")
                                            .detail(e)
                                            .build();
                                        err_dialog.show(Some(&pw_for_err));
                                    }
                                }
                            }
                        });
                    });

                    row.append(&proto_lbl);
                    row.append(&local_lbl);
                    row.append(&arrow);
                    row.append(&remote_lbl);
                    row.append(&state_lbl);
                    row.append(&proc_lbl);
                    row.append(&inspect_btn);
                    row.append(&kill_btn);

                    list.append(&row);
                }
            }
        });
    });

    let u_clone = update_fn.clone();
    refresh_btn.connect_clicked(move |_| {
        u_clone();
    });

    (container, update_fn)
}

fn show_connection_inspector(parent: &ApplicationWindow, conn: &netscope_core::NetworkConnection) {
    let dialog = Window::builder()
        .transient_for(parent)
        .title(format!(
            "Connection Inspector — {}:{}",
            conn.remote_addr, conn.remote_port
        ))
        .modal(true)
        .default_width(520)
        .default_height(400)
        .build();

    let content = GtkBox::new(Orientation::Vertical, 14);
    content.add_css_class("view-container");

    let title = Label::new(Some("Socket Metadata & Forensic Details"));
    title.add_css_class("heading-2");
    title.set_halign(gtk4::Align::Start);
    content.append(&title);

    let details_card = GtkBox::new(Orientation::Vertical, 8);
    details_card.add_css_class("card");

    let add_field = |parent_box: &GtkBox, key: &str, val: &str| {
        let row = GtkBox::new(Orientation::Horizontal, 12);
        let k = Label::new(Some(key));
        k.set_width_chars(18);
        k.set_halign(gtk4::Align::Start);
        k.add_css_class("stat-label");

        let v = Label::new(Some(val));
        v.set_halign(gtk4::Align::Start);
        v.set_hexpand(true);
        row.append(&k);
        row.append(&v);
        parent_box.append(&row);
    };

    add_field(&details_card, "Protocol", &conn.protocol.to_string());
    add_field(
        &details_card,
        "Local Endpoint",
        &format!("{}:{}", conn.local_addr, conn.local_port),
    );
    add_field(
        &details_card,
        "Remote Endpoint",
        &format!("{}:{}", conn.remote_addr, conn.remote_port),
    );
    add_field(&details_card, "Socket State", &conn.state.to_string());
    add_field(&details_card, "Socket Inode", &conn.inode.to_string());

    if let Some(ref p) = conn.process {
        add_field(&details_card, "Process Name", &p.name);
        add_field(&details_card, "PID", &p.pid.to_string());
        add_field(
            &details_card,
            "UID / User",
            &format!("{} ({})", p.uid, p.user.as_deref().unwrap_or("unknown")),
        );
        add_field(
            &details_card,
            "Executable Path",
            &p.exe_path
                .as_ref()
                .map(|path| path.to_string_lossy().to_string())
                .unwrap_or_else(|| "N/A".to_string()),
        );
    } else {
        add_field(
            &details_card,
            "Process Attribution",
            "Unattributed or kernel worker",
        );
    }

    content.append(&details_card);

    let close_btn = Button::with_label("Close Inspector");
    let d_clone = dialog.clone();
    close_btn.connect_clicked(move |_| {
        d_clone.close();
    });
    content.append(&close_btn);

    dialog.set_child(Some(&content));
    dialog.present();
}

fn create_processes_page(state: &AppState, rt: Arc<Runtime>) -> (GtkBox, Rc<dyn Fn()>) {
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.add_css_class("view-container");

    let title = Label::new(Some("Applications & Sockets Attribution"));
    title.add_css_class("heading-1");
    container.append(&title);

    let scrolled = ScrolledWindow::new();
    scrolled.set_vexpand(true);

    let list_box = gtk4::ListBox::new();
    list_box.add_css_class("card");
    scrolled.set_child(Some(&list_box));
    container.append(&scrolled);

    let state_clone = state.clone();
    let rt_clone = rt.clone();
    let list_clone = list_box.clone();

    let update_fn: Rc<dyn Fn()> = Rc::new(move || {
        let st = state_clone.clone();
        let rt = rt_clone.clone();
        let list = list_clone.clone();

        let (sender, receiver) = async_channel::bounded(1);
        std::thread::spawn(move || {
            let conns = rt.block_on(async { st.collector.poll_connections().await });
            let _ = sender.send_blocking(conns);
        });

        glib::spawn_future_local(async move {
            if let Ok(conns) = receiver.recv().await {
                let mut proc_map: std::collections::HashMap<
                    String,
                    (u32, usize, Vec<Protocol>, Option<std::path::PathBuf>),
                > = std::collections::HashMap::new();

                for conn in conns {
                    if let Some(p) = conn.process {
                        let entry =
                            proc_map
                                .entry(p.name)
                                .or_insert((p.pid, 0, Vec::new(), p.exe_path));
                        entry.1 += 1;
                        if !entry.2.contains(&conn.protocol) {
                            entry.2.push(conn.protocol);
                        }
                    }
                }

                while let Some(child) = list.first_child() {
                    list.remove(&child);
                }

                for (name, (pid, count, protos, path)) in proc_map {
                    let row = GtkBox::new(Orientation::Horizontal, 14);
                    row.set_margin_top(6);
                    row.set_margin_bottom(6);
                    row.set_margin_start(12);
                    row.set_margin_end(12);

                    let pid_badge = Label::new(Some(&format!("PID {}", pid)));
                    pid_badge.add_css_class("badge");
                    pid_badge.add_css_class("badge-info");

                    let name_lbl = Label::new(Some(&name));
                    name_lbl.add_css_class("heading-2");
                    name_lbl.set_width_chars(18);
                    name_lbl.set_halign(gtk4::Align::Start);

                    let sockets_lbl = Label::new(Some(&format!("{} open sockets", count)));
                    sockets_lbl.set_width_chars(16);
                    sockets_lbl.set_halign(gtk4::Align::Start);

                    let protos_str = protos
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let protos_lbl = Label::new(Some(&protos_str));
                    protos_lbl.set_width_chars(12);

                    let path_str = path
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "-".to_string());
                    let path_lbl = Label::new(Some(&path_str));
                    path_lbl.set_halign(gtk4::Align::Start);
                    path_lbl.set_hexpand(true);
                    path_lbl.add_css_class("dim-label");

                    row.append(&pid_badge);
                    row.append(&name_lbl);
                    row.append(&sockets_lbl);
                    row.append(&protos_lbl);
                    row.append(&path_lbl);

                    list.append(&row);
                }
            }
        });
    });

    (container, update_fn)
}

fn create_packets_page(state: &AppState) -> (GtkBox, Rc<dyn Fn()>) {
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.add_css_class("view-container");

    let top_bar = GtkBox::new(Orientation::Horizontal, 12);
    let title = Label::new(Some("Live Packet Stream (Inbound & Outbound Data)"));
    title.add_css_class("heading-1");
    top_bar.append(&title);

    let info_badge = Label::new(Some(if state.sniffer.has_raw_permission() {
        "AF_PACKET: Hardware Stream Active"
    } else {
        "AF_PACKET: Restricted (CAP_NET_RAW Required)"
    }));
    info_badge.add_css_class("badge");
    info_badge.add_css_class(if state.sniffer.has_raw_permission() {
        "badge-success"
    } else {
        "badge-warning"
    });
    top_bar.append(&info_badge);
    container.append(&top_bar);

    let perm_banner = GtkBox::new(Orientation::Horizontal, 10);
    perm_banner.add_css_class("card");
    let perm_lbl = Label::new(Some(if state.sniffer.has_raw_permission() {
        "Live AF_PACKET kernel socket active. Dissecting real-time Ethernet frames, 802.1Q VLANs, IPv4/IPv6 headers, and TCP/UDP transport endpoints."
    } else {
        "AF_PACKET raw socket permission denied. To enable kernel-level live packet capture without running as root, grant: sudo setcap cap_net_raw,cap_net_admin+eip <binary>. NetScope operates under an honest zero-simulation policy and will not display synthetic packet data."
    }));
    perm_lbl.set_wrap(true);
    perm_lbl.set_halign(gtk4::Align::Start);
    perm_banner.append(&perm_lbl);
    container.append(&perm_banner);

    let scrolled = ScrolledWindow::new();
    scrolled.set_vexpand(true);

    let list_box = gtk4::ListBox::new();
    list_box.add_css_class("card");
    scrolled.set_child(Some(&list_box));
    container.append(&scrolled);

    let sniffer_clone = state.sniffer.clone();
    let list_clone = list_box.clone();

    let update_fn: Rc<dyn Fn()> = Rc::new(move || {
        let packets = sniffer_clone.get_recent_packets(60);

        while let Some(child) = list_clone.first_child() {
            list_clone.remove(&child);
        }

        for pkt in packets {
            let row = GtkBox::new(Orientation::Horizontal, 12);
            row.set_margin_top(4);
            row.set_margin_bottom(4);
            row.set_margin_start(10);
            row.set_margin_end(10);

            let dir_badge = Label::new(Some(&pkt.direction.to_string()));
            dir_badge.add_css_class("badge");
            dir_badge.add_css_class(match pkt.direction {
                netscope_core::PacketDirection::Inbound => "badge-success",
                netscope_core::PacketDirection::Outbound => "badge-danger",
            });
            dir_badge.set_width_chars(10);

            let proto_badge = Label::new(Some(&pkt.protocol));
            proto_badge.add_css_class("badge");
            proto_badge.add_css_class("badge-info");
            proto_badge.set_width_chars(8);

            let src_lbl = Label::new(Some(&format!(
                "{}:{}",
                pkt.src_addr,
                pkt.src_port.unwrap_or(0)
            )));
            src_lbl.set_width_chars(21);
            src_lbl.set_halign(gtk4::Align::Start);

            let arrow = Label::new(Some(match pkt.direction {
                netscope_core::PacketDirection::Inbound => "← [IN]",
                netscope_core::PacketDirection::Outbound => "→ [OUT]",
            }));
            arrow.add_css_class("stat-label");

            let dst_lbl = Label::new(Some(&format!(
                "{}:{}",
                pkt.dst_addr,
                pkt.dst_port.unwrap_or(0)
            )));
            dst_lbl.set_width_chars(21);
            dst_lbl.set_halign(gtk4::Align::Start);

            let len_lbl = Label::new(Some(&format!("{} B", pkt.length_bytes)));
            len_lbl.set_width_chars(8);
            len_lbl.add_css_class("dim-label");

            let summary_lbl = Label::new(Some(&pkt.summary));
            summary_lbl.set_halign(gtk4::Align::Start);
            summary_lbl.set_hexpand(true);

            row.append(&dir_badge);
            row.append(&proto_badge);
            row.append(&src_lbl);
            row.append(&arrow);
            row.append(&dst_lbl);
            row.append(&len_lbl);
            row.append(&summary_lbl);

            list_clone.append(&row);
        }
    });

    (container, update_fn)
}

fn create_flows_page(state: &AppState) -> (GtkBox, Rc<dyn Fn()>) {
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.add_css_class("view-container");

    let top_bar = GtkBox::new(Orientation::Horizontal, 12);
    let title = Label::new(Some("Bidirectional Network Conversations & Session Flows"));
    title.add_css_class("heading-1");
    top_bar.append(&title);
    container.append(&top_bar);

    let desc_card = GtkBox::new(Orientation::Horizontal, 10);
    desc_card.add_css_class("card");
    let desc_lbl = Label::new(Some(
        "Aggregates live raw packets into canonical bidirectional sessions (A ⇄ B), tracking connection state, transfer byte metrics, and packet distributions."
    ));
    desc_lbl.set_wrap(true);
    desc_lbl.set_halign(gtk4::Align::Start);
    desc_card.append(&desc_lbl);
    container.append(&desc_card);

    let scrolled = ScrolledWindow::new();
    scrolled.set_vexpand(true);

    let list_box = gtk4::ListBox::new();
    list_box.add_css_class("card");
    scrolled.set_child(Some(&list_box));
    container.append(&scrolled);

    let sniffer_clone = state.sniffer.clone();
    let list_clone = list_box.clone();

    let update_fn: Rc<dyn Fn()> = Rc::new(move || {
        let flows = sniffer_clone.get_active_flows();

        while let Some(child) = list_clone.first_child() {
            list_clone.remove(&child);
        }

        if flows.is_empty() {
            let row = GtkBox::new(Orientation::Horizontal, 10);
            row.set_margin_top(12);
            row.set_margin_bottom(12);
            row.set_margin_start(16);
            let lbl = Label::new(Some("No active network flows recorded. Capture worker idle or awaiting packet activity."));
            lbl.add_css_class("dim-label");
            row.append(&lbl);
            list_clone.append(&row);
            return;
        }

        for flow in flows.into_iter().take(60) {
            let row = GtkBox::new(Orientation::Horizontal, 12);
            row.set_margin_top(4);
            row.set_margin_bottom(4);
            row.set_margin_start(10);
            row.set_margin_end(10);

            let proto_badge = Label::new(Some(&flow.key.protocol.to_string()));
            proto_badge.add_css_class("badge");
            proto_badge.add_css_class("badge-info");
            proto_badge.set_width_chars(6);

            let state_badge = Label::new(Some(&flow.state.to_string()));
            state_badge.add_css_class("badge");
            state_badge.add_css_class(match flow.state {
                netscope_core::FlowState::Established => "badge-success",
                netscope_core::FlowState::Closing | netscope_core::FlowState::Closed => {
                    "badge-warning"
                }
                _ => "badge-info",
            });
            state_badge.set_width_chars(11);

            let ep_a = format!("{}:{}", flow.key.endpoint_a.0, flow.key.endpoint_a.1);
            let a_lbl = Label::new(Some(&ep_a));
            a_lbl.set_width_chars(21);
            a_lbl.set_halign(gtk4::Align::Start);

            let arrow = Label::new(Some("⇄"));
            arrow.add_css_class("accent-blue");

            let ep_b = format!("{}:{}", flow.key.endpoint_b.0, flow.key.endpoint_b.1);
            let b_lbl = Label::new(Some(&ep_b));
            b_lbl.set_width_chars(21);
            b_lbl.set_halign(gtk4::Align::Start);

            let total_mb = flow.total_bytes() as f64 / 1024.0;
            let bytes_lbl = Label::new(Some(&format!("{:.1} KB", total_mb)));
            bytes_lbl.set_width_chars(10);
            bytes_lbl.set_halign(gtk4::Align::End);

            let pkts_lbl = Label::new(Some(&format!("{} pkts", flow.total_packets())));
            pkts_lbl.set_width_chars(10);
            pkts_lbl.set_halign(gtk4::Align::End);
            pkts_lbl.add_css_class("dim-label");

            let dur_lbl = Label::new(Some(&format!("{}s", flow.duration_seconds())));
            dur_lbl.set_width_chars(6);
            dur_lbl.set_halign(gtk4::Align::End);
            dur_lbl.add_css_class("dim-label");

            row.append(&proto_badge);
            row.append(&state_badge);
            row.append(&a_lbl);
            row.append(&arrow);
            row.append(&b_lbl);
            row.append(&bytes_lbl);
            row.append(&pkts_lbl);
            row.append(&dur_lbl);

            list_clone.append(&row);
        }
    });

    (container, update_fn)
}

fn create_timeline_page(state: &AppState) -> (GtkBox, Rc<dyn Fn()>) {
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.add_css_class("view-container");

    let title = Label::new(Some("Network Activity Timeline"));
    title.add_css_class("heading-1");
    container.append(&title);

    let scrolled = ScrolledWindow::new();
    scrolled.set_vexpand(true);

    let list_box = gtk4::ListBox::new();
    list_box.add_css_class("card");
    scrolled.set_child(Some(&list_box));
    container.append(&scrolled);

    let st_clone = state.clone();
    let list_clone = list_box.clone();

    let update_fn: Rc<dyn Fn()> = Rc::new(move || {
        let events = st_clone.storage.get_recent_events(50).unwrap_or_default();

        while let Some(child) = list_clone.first_child() {
            list_clone.remove(&child);
        }

        if events.is_empty() {
            let empty_lbl = Label::new(Some("Timeline recorder active. Network lifecycle events will appear here chronologically."));
            empty_lbl.add_css_class("subtext");
            list_clone.append(&empty_lbl);
            return;
        }

        for ev in events {
            let row = GtkBox::new(Orientation::Horizontal, 14);
            row.set_margin_top(6);
            row.set_margin_bottom(6);
            row.set_margin_start(12);

            let time_lbl = Label::new(Some(&ev.timestamp.format("%H:%M:%S").to_string()));
            time_lbl.add_css_class("dim-label");

            let type_badge = Label::new(Some(&ev.event_type.to_string()));
            type_badge.add_css_class("badge");
            type_badge.add_css_class("badge-info");

            let title_lbl = Label::new(Some(&ev.title));
            title_lbl.add_css_class("heading-2");
            title_lbl.set_halign(gtk4::Align::Start);

            let desc_lbl = Label::new(Some(&ev.details));
            desc_lbl.set_halign(gtk4::Align::Start);
            desc_lbl.set_hexpand(true);
            desc_lbl.add_css_class("subtext");

            row.append(&time_lbl);
            row.append(&type_badge);
            row.append(&title_lbl);
            row.append(&desc_lbl);
            list_clone.append(&row);
        }
    });

    (container, update_fn)
}

fn create_investigation_page(rt: Arc<Runtime>) -> GtkBox {
    let container = GtkBox::new(Orientation::Vertical, 16);
    container.add_css_class("view-container");

    let title = Label::new(Some("IP & Domain Forensic Investigation"));
    title.add_css_class("heading-1");
    container.append(&title);

    let search_box = GtkBox::new(Orientation::Horizontal, 8);
    let entry = Entry::new();
    entry.set_placeholder_text(Some(
        "Enter IP address or domain (e.g. 1.1.1.1, github.com)...",
    ));
    entry.set_hexpand(true);
    let run_btn = Button::with_label("Investigate");
    run_btn.add_css_class("suggested-action");
    search_box.append(&entry);
    search_box.append(&run_btn);
    container.append(&search_box);

    let card = GtkBox::new(Orientation::Vertical, 8);
    card.add_css_class("card");
    let res_title = Label::new(Some("INVESTIGATION REPORT"));
    res_title.add_css_class("stat-label");
    res_title.set_halign(gtk4::Align::Start);
    let res_text = Label::new(Some(
        "Enter an address above to evaluate routing provenance and reputation.",
    ));
    res_text.set_halign(gtk4::Align::Start);
    card.append(&res_title);
    card.append(&res_text);
    container.append(&card);

    let entry_clone = entry.clone();
    let res_lbl_clone = res_text.clone();
    run_btn.connect_clicked(move |_| {
        let q = entry_clone.text().to_string();
        if q.is_empty() { return; }

        res_lbl_clone.set_text("Analyzing target...");
        let rt = rt.clone();
        let (sender, receiver) = async_channel::bounded(1);

        std::thread::spawn(move || {
            let rep = rt.block_on(async { Investigator::investigate(&q).await });
            let _ = sender.send_blocking(rep);
        });

        let lbl = res_lbl_clone.clone();
        glib::spawn_future_local(async move {
            if let Ok(r) = receiver.recv().await {
                lbl.set_text(&format!(
                    "Query: {}\nClassification: {}\nReputation: {}\nResolved IPs: {}\nReverse DNS: {}\nNetwork / ASN: {}\nCountry / Transit: {}\nNotes: {}",
                    r.query,
                    if r.is_private { "Private Network (RFC 1918)" } else { "Public Internet Target" },
                    r.reputation_score,
                    r.resolved_ips.join(", "),
                    r.reverse_dns.unwrap_or_else(|| "None".to_string()),
                    r.asn.unwrap_or_else(|| "Local Subnet".to_string()),
                    r.country.unwrap_or_else(|| "Local".to_string()),
                    if r.notes.is_empty() { "No anomaly notes".to_string() } else { r.notes.join("; ") }
                ));
            }
        });
    });

    container
}

fn create_speedtest_page(rt: Arc<Runtime>) -> GtkBox {
    let container = GtkBox::new(Orientation::Vertical, 16);
    container.add_css_class("view-container");

    let title = Label::new(Some("Internet Speed & Throughput Benchmark"));
    title.add_css_class("heading-1");
    container.append(&title);

    let card = GtkBox::new(Orientation::Vertical, 12);
    card.add_css_class("card");

    let start_btn = Button::with_label("Run Full Benchmark Test");
    start_btn.add_css_class("suggested-action");
    card.append(&start_btn);

    let results_lbl = Label::new(Some(
        "Click above to benchmark latency, jitter, and download/upload throughput.",
    ));
    results_lbl.set_halign(gtk4::Align::Start);
    card.append(&results_lbl);
    container.append(&card);

    let res_clone = results_lbl.clone();
    let btn_clone = start_btn.clone();
    start_btn.connect_clicked(move |_| {
        res_clone.set_text("Benchmarking network throughput (latency, jitter, 5MB download, 1MB upload)...");
        btn_clone.set_sensitive(false);
        let rt = rt.clone();
        let (sender, receiver) = async_channel::bounded(1);

        std::thread::spawn(move || {
            let r = rt.block_on(async { SpeedTestEngine::run_benchmark().await });
            let _ = sender.send_blocking(r);
        });

        let lbl = res_clone.clone();
        let btn = btn_clone.clone();
        glib::spawn_future_local(async move {
            if let Ok(res) = receiver.recv().await {
                btn.set_sensitive(true);
                match res {
                    Ok(bench) => {
                        lbl.set_text(&format!(
                            "Benchmark Complete!\nServer: {}\nLatency: {:.2} ms | Jitter: {:.2} ms\nDownload: {:.2} Mbps\nUpload: {:.2} Mbps\nCompleted at: {} UTC",
                            bench.server, bench.latency_ms, bench.jitter_ms, bench.download_mbps, bench.upload_mbps, bench.timestamp.format("%H:%M:%S")
                        ));
                    }
                    Err(e) => {
                        lbl.set_text(&format!("Benchmark failed: {}", e));
                    }
                }
            }
        });
    });

    container
}

fn create_wifi_page(state: &AppState, rt: Arc<Runtime>) -> (GtkBox, Rc<dyn Fn()>) {
    let container = GtkBox::new(Orientation::Vertical, 16);
    container.add_css_class("view-container");

    let title = Label::new(Some("Wi-Fi & Wireless RF Intelligence"));
    title.add_css_class("heading-1");
    container.append(&title);

    let info_card = GtkBox::new(Orientation::Vertical, 10);
    info_card.add_css_class("card");

    let ssid_lbl = Label::new(Some("SSID: Scanning..."));
    ssid_lbl.add_css_class("heading-2");
    ssid_lbl.set_halign(gtk4::Align::Start);

    let bssid_lbl = Label::new(Some("BSSID / Access Point: -"));
    bssid_lbl.set_halign(gtk4::Align::Start);

    let signal_lbl = Label::new(Some("Signal RSSI: - dBm"));
    signal_lbl.set_halign(gtk4::Align::Start);
    signal_lbl.add_css_class("accent-green");

    let quality_lbl = Label::new(Some("Link Quality: -"));
    quality_lbl.set_halign(gtk4::Align::Start);

    let freq_lbl = Label::new(Some("Frequency: - GHz | Bitrate: - Mbps"));
    freq_lbl.set_halign(gtk4::Align::Start);

    info_card.append(&ssid_lbl);
    info_card.append(&bssid_lbl);
    info_card.append(&signal_lbl);
    info_card.append(&quality_lbl);
    info_card.append(&freq_lbl);
    container.append(&info_card);

    let st_clone = state.clone();
    let rt_clone = rt.clone();
    let update_fn: Rc<dyn Fn()> = Rc::new(move || {
        let st = st_clone.clone();
        let rt = rt_clone.clone();
        let s_lbl = ssid_lbl.clone();
        let b_lbl = bssid_lbl.clone();
        let sig_lbl = signal_lbl.clone();
        let q_lbl = quality_lbl.clone();
        let f_lbl = freq_lbl.clone();

        let (sender, receiver) = async_channel::bounded(1);
        std::thread::spawn(move || {
            let ifaces = rt.block_on(async { st.collector.poll_interfaces().await });
            let _ = sender.send_blocking(ifaces);
        });

        glib::spawn_future_local(async move {
            if let Ok(ifaces) = receiver.recv().await {
                let wifi_iface = ifaces.iter().find(|i| {
                    i.if_type == netscope_core::InterfaceType::WiFi || i.name.starts_with("wl")
                });

                if let Some(iface) = wifi_iface {
                    if let Some(details) = WifiScanner::get_wifi_details(&iface.name) {
                        s_lbl.set_text(&format!(
                            "SSID: {}",
                            details.ssid.unwrap_or_else(|| "Connected".to_string())
                        ));
                        b_lbl.set_text(&format!(
                            "BSSID / Access Point: {}",
                            details.bssid.unwrap_or_else(|| "N/A".to_string())
                        ));
                        sig_lbl.set_text(&format!(
                            "Signal RSSI: {} dBm",
                            details
                                .signal_dbm
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "-".to_string())
                        ));
                        q_lbl.set_text(&format!(
                            "Link Quality: {}",
                            details.link_quality.unwrap_or_else(|| "-".to_string())
                        ));
                        f_lbl.set_text(&format!(
                            "Frequency: {:.3} GHz | TX Bitrate: {:.1} Mbps",
                            details.frequency_ghz.unwrap_or(0.0),
                            details.tx_bitrate_mbps.unwrap_or(0.0)
                        ));
                    } else {
                        s_lbl.set_text(&format!(
                            "Wi-Fi Interface ({}) Idle / Unassociated",
                            iface.name
                        ));
                    }
                } else {
                    s_lbl.set_text("No active Wi-Fi interface detected on this machine");
                }
            }
        });
    });

    (container, update_fn)
}

fn create_dns_page(rt: Arc<Runtime>) -> (GtkBox, Rc<dyn Fn()>) {
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.add_css_class("view-container");

    let title = Label::new(Some("DNS Intelligence & Querying"));
    title.add_css_class("heading-1");
    container.append(&title);

    let resolvers_box = GtkBox::new(Orientation::Horizontal, 10);
    resolvers_box.add_css_class("card");
    let res_lbl = Label::new(Some("Configured Resolvers: 127.0.0.53"));
    res_lbl.set_halign(gtk4::Align::Start);
    resolvers_box.append(&res_lbl);
    container.append(&resolvers_box);

    let query_box = GtkBox::new(Orientation::Horizontal, 8);
    let entry = Entry::new();
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
        let (sender, receiver) =
            async_channel::bounded::<Result<netscope_core::DnsRecord, String>>(1);

        std::thread::spawn(move || {
            let res = rt.block_on(async {
                if let Ok(inspector) = DnsInspector::new() {
                    inspector
                        .resolve(&domain, "A")
                        .await
                        .map_err(|e| e.to_string())
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

    let title = Label::new(Some("Network Diagnostics Suite"));
    title.add_css_class("heading-1");
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
        let (sender, receiver) = async_channel::bounded(1);
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
                DiagnosticsEngine::test_tcp_port(
                    "google.com",
                    443,
                    std::time::Duration::from_secs(3),
                )
                .await
            });
            let _ = sender.send_blocking(res);
        });

        let l = lbl_tcp.clone();
        glib::spawn_future_local(async move {
            if let Ok(res) = receiver.recv().await {
                if res.is_reachable {
                    l.set_text(&format!(
                        "Connection Successful!\nTarget: google.com:443\nLatency: {:.2} ms",
                        res.latency_ms.unwrap_or(0.0)
                    ));
                } else {
                    l.set_text(&format!(
                        "Connection Failed!\nError: {}",
                        res.error.unwrap_or_default()
                    ));
                }
            }
        });
    });

    let lbl_routes = res_lbl.clone();
    routes_btn.connect_clicked(move |_| {
        let rts = DiagnosticsEngine::get_routing_table();
        let mut text = String::from("Kernel Routing Table:\n\n");
        text.push_str(&format!(
            "{:<18} {:<18} {:<18} {:<8} {:<8}\n",
            "Destination", "Gateway", "Genmask", "Flags", "Iface"
        ));
        text.push_str(&"-".repeat(70));
        text.push('\n');
        for r in rts {
            text.push_str(&format!(
                "{:<18} {:<18} {:<18} {:<8} {:<8}\n",
                r.destination, r.gateway, r.genmask, r.flags, r.interface
            ));
        }
        lbl_routes.set_text(&text);
    });

    container
}

fn create_security_page(state: &AppState, rt: Arc<Runtime>) -> (GtkBox, Rc<dyn Fn()>) {
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.add_css_class("view-container");

    let top_bar = GtkBox::new(Orientation::Horizontal, 12);
    let title = Label::new(Some("Security Center & Threat Intelligence"));
    title.add_css_class("heading-1");
    title.set_hexpand(true);
    title.set_halign(gtk4::Align::Start);
    top_bar.append(&title);

    let refresh_feeds_btn = Button::with_label("Update Threat Feeds");
    refresh_feeds_btn.add_css_class("subtext");
    top_bar.append(&refresh_feeds_btn);
    container.append(&top_bar);

    let status_banner = GtkBox::new(Orientation::Horizontal, 10);
    status_banner.add_css_class("card");
    let status_lbl = Label::new(Some(
        "Active Indicators: 0 | Live threat detection enabled across all network connections.",
    ));
    status_lbl.set_halign(gtk4::Align::Start);
    status_banner.append(&status_lbl);
    container.append(&status_banner);

    let scrolled = ScrolledWindow::new();
    scrolled.set_vexpand(true);

    let list_box = gtk4::ListBox::new();
    list_box.add_css_class("card");
    scrolled.set_child(Some(&list_box));
    container.append(&scrolled);

    let st_clone = state.clone();
    let rt_clone = rt.clone();
    let list_clone = list_box.clone();
    let status_lbl_clone = status_lbl.clone();

    let update_fn: Rc<dyn Fn()> = Rc::new(move || {
        let st = st_clone.clone();
        let rt = rt_clone.clone();
        let list = list_clone.clone();
        let stat_lbl = status_lbl_clone.clone();

        let (sender, receiver) = async_channel::bounded(1);
        std::thread::spawn(move || {
            let conns = rt.block_on(async { st.collector.poll_connections().await });
            let mut engine = st.rule_engine.write();
            let alerts = engine.evaluate_connections(&conns);
            for a in &alerts {
                let _ = st.storage.insert_alert(a);
            }
            let total_indicators = engine.threat_intel().len();
            let _ = sender.send_blocking((alerts, total_indicators));
        });

        glib::spawn_future_local(async move {
            if let Ok((alerts, total_indicators)) = receiver.recv().await {
                stat_lbl.set_text(&format!(
                    "Active Indicators: {} | Live threat detection enabled across all network connections.",
                    total_indicators
                ));

                while let Some(child) = list.first_child() {
                    list.remove(&child);
                }

                if alerts.is_empty() {
                    let row = GtkBox::new(Orientation::Horizontal, 10);
                    row.set_margin_top(12);
                    row.set_margin_bottom(12);
                    row.set_margin_start(16);
                    let lbl = Label::new(Some(
                        "No active threat anomalies detected. Host operating securely.",
                    ));
                    lbl.add_css_class("accent-green");
                    row.append(&lbl);
                    list.append(&row);
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
                        netscope_core::AlertSeverity::High
                        | netscope_core::AlertSeverity::Critical => "badge-danger",
                        netscope_core::AlertSeverity::Medium => "badge-warning",
                        _ => "badge-info",
                    });

                    let t_lbl = Label::new(Some(&alert.title));
                    t_lbl.add_css_class("heading-2");
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

                    list.append(&row);
                }
            }
        });
    });

    let st_for_feed = state.clone();
    let rt_for_feed = rt.clone();
    let stat_for_feed = status_lbl.clone();
    let btn_for_feed = refresh_feeds_btn.clone();
    let u_feed = update_fn.clone();

    refresh_feeds_btn.connect_clicked(move |_| {
        btn_for_feed.set_sensitive(false);
        stat_for_feed.set_text(
            "Downloading & updating live threat intelligence feeds (abuse.ch & Tor Project)...",
        );
        let st = st_for_feed.clone();
        let rt = rt_for_feed.clone();
        let btn = btn_for_feed.clone();
        let stat = stat_for_feed.clone();
        let u = u_feed.clone();

        let (sender, receiver) = async_channel::bounded(1);
        std::thread::spawn(move || {
            let res = rt.block_on(async {
                let mut pipeline = netscope_security::ThreatPipeline::new();
                let mut total_added = 0;
                for provider in ["feodo", "urlhaus", "tor_exits"] {
                    if let Ok(indicators) = pipeline.fetch_feed_updates(provider).await {
                        let added = st.rule_engine.write().ingest_indicators(indicators);
                        total_added += added;
                    }
                }
                total_added
            });
            let _ = sender.send_blocking(res);
        });

        glib::spawn_future_local(async move {
            if let Ok(added) = receiver.recv().await {
                stat.set_text(&format!(
                    "Threat feed update completed! Added/updated {} indicators.",
                    added
                ));
                btn.set_sensitive(true);
                u();
            }
        });
    });

    (container, update_fn)
}

fn create_settings_page(state: &AppState) -> GtkBox {
    let container = GtkBox::new(Orientation::Vertical, 16);
    container.add_css_class("view-container");

    let title = Label::new(Some("Settings & Data Quotas"));
    title.add_css_class("heading-1");
    container.append(&title);

    let card = GtkBox::new(Orientation::Vertical, 12);
    card.add_css_class("card");

    let row_quota = GtkBox::new(Orientation::Horizontal, 12);
    let lbl_quota = Label::new(Some("Active Daily Allowance Limit (5.0 GB)"));
    lbl_quota.set_hexpand(true);
    lbl_quota.set_halign(gtk4::Align::Start);
    let sw_quota = gtk4::Switch::new();
    sw_quota.set_active(true);
    row_quota.append(&lbl_quota);
    row_quota.append(&sw_quota);

    let row1 = GtkBox::new(Orientation::Horizontal, 12);
    let lbl1 = Label::new(Some("External Public IP & Geolocation Lookups (Opt-In)"));
    lbl1.set_hexpand(true);
    lbl1.set_halign(gtk4::Align::Start);
    let sw1 = gtk4::Switch::new();
    sw1.set_active(false);
    row1.append(&lbl1);
    row1.append(&sw1);

    let row2 = GtkBox::new(Orientation::Horizontal, 12);
    let lbl2 = Label::new(Some("Desktop Notifications on Security Alerts"));
    lbl2.set_hexpand(true);
    lbl2.set_halign(gtk4::Align::Start);
    let sw2 = gtk4::Switch::new();
    sw2.set_active(true);
    row2.append(&lbl2);
    row2.append(&sw2);

    let export_btn = Button::with_label("Export Full Forensic HTML Report");
    export_btn.add_css_class("suggested-action");
    let st_for_export = state.clone();
    export_btn.connect_clicked(move |_| {
        if let Ok(html) = st_for_export.storage.export_html_report() {
            let _ = std::fs::write("/tmp/netscope-report.html", html);
        }
    });

    card.append(&row_quota);
    card.append(&row1);
    card.append(&row2);
    card.append(&export_btn);
    container.append(&card);

    let about_card = GtkBox::new(Orientation::Vertical, 6);
    about_card.add_css_class("card");
    let about_title = Label::new(Some("ABOUT NETSCOPE 2.0"));
    about_title.add_css_class("stat-label");
    about_title.set_halign(gtk4::Align::Start);
    let about_desc = Label::new(Some("NetScope 2.0 — Production-Quality Linux Network Intelligence\nBuilt with Rust, GTK4 & Libadwaita. Privacy by default."));
    about_desc.set_halign(gtk4::Align::Start);
    about_card.append(&about_title);
    about_card.append(&about_desc);
    container.append(&about_card);

    container
}

fn show_command_palette(parent: &ApplicationWindow, stack: &Stack) {
    let dialog = Window::builder()
        .transient_for(parent)
        .title("NetScope Command Palette (Ctrl+K)")
        .modal(true)
        .default_width(550)
        .default_height(350)
        .build();

    let content = GtkBox::new(Orientation::Vertical, 10);
    content.add_css_class("view-container");

    let entry = Entry::new();
    entry.set_placeholder_text(Some(
        "Type a command or jump to page (e.g. connections, speedtest, packets)...",
    ));
    content.append(&entry);

    let list = gtk4::ListBox::new();
    list.add_css_class("card");

    let pages = [
        ("dashboard", "Go to: Overview Dashboard"),
        ("connections", "Go to: Active Connections"),
        ("processes", "Go to: Applications Network Activity"),
        ("packets", "Go to: Live Packet Stream"),
        ("timeline", "Go to: Network Timeline"),
        ("investigate", "Go to: IP & Domain Investigation"),
        ("speedtest", "Go to: Speed & Benchmark Test"),
        ("wifi", "Go to: Wi-Fi & RF Intelligence"),
        ("dns", "Go to: DNS Intelligence"),
        ("diagnostics", "Go to: Diagnostics Suite"),
        ("security", "Go to: Security Center"),
        ("settings", "Go to: Settings & Quotas"),
    ];

    for (id, label_text) in pages {
        let row = GtkBox::new(Orientation::Horizontal, 10);
        let lbl = Label::new(Some(label_text));
        lbl.set_halign(gtk4::Align::Start);
        lbl.set_hexpand(true);
        row.append(&lbl);

        let row_btn = Button::with_label("Jump");
        row_btn.add_css_class("subtext");
        let s_clone = stack.clone();
        let d_clone = dialog.clone();
        row_btn.connect_clicked(move |_| {
            s_clone.set_visible_child_name(id);
            d_clone.close();
        });
        row.append(&row_btn);
        list.append(&row);
    }

    let scrolled = ScrolledWindow::new();
    scrolled.set_vexpand(true);
    scrolled.set_child(Some(&list));
    content.append(&scrolled);

    dialog.set_child(Some(&content));
    dialog.present();
}
