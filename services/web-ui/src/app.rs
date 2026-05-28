use gloo_net::http::Request;
use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;

#[derive(Debug, Clone, Deserialize)]
pub struct NodeMetricsUI {
    pub connections_accepted: u64,
    pub circuits_active: u64,
    pub circuits_created: u64,
    pub circuits_destroyed: u64,
    pub bytes_forwarded: u64,
    pub bytes_received: u64,
    pub streams_opened: u64,
    pub uptime_secs: u64,
    #[serde(default)]
    pub event_snapshot: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub node_type: String,
    pub address: String,
    pub bandwidth: u64,
    #[allow(dead_code)]
    pub metrics: Option<NodeMetricsUI>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Stats {
    pub total_nodes: usize,
    pub entry_count: usize,
    pub middle_count: usize,
    pub exit_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsSummary {
    pub registrations: u64,
    pub removals: u64,
    pub heartbeats: u64,
    pub path_requests: u64,
    pub stale_cleaned: u64,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EventEntry {
    pub elapsed_secs: f64,
    pub event_type: String,
    pub label: String,
    pub detail: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DashboardData {
    pub nodes: Vec<NodeInfo>,
    pub stats: Stats,
    pub metrics: MetricsSummary,
    pub ready: bool,
    pub events: Vec<EventEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum TabKind { All, Entry, Middle, Exit }

#[derive(Debug, Clone, Copy, PartialEq)]
enum SortCol { Id, Type, Addr, Bw }

async fn fetch_dashboard() -> Option<DashboardData> {
    let resp = Request::get("/api/dashboard").send().await.ok()?;
    resp.json::<DashboardData>().await.ok()
}

fn format_bandwidth(bps: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bps >= GB { format!("{:.1} GB/s", bps as f64 / GB as f64) }
    else if bps >= MB { format!("{:.1} MB/s", bps as f64 / MB as f64) }
    else if bps >= KB { format!("{:.1} KB/s", bps as f64 / KB as f64) }
    else { format!("{bps} B/s") }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB { format!("{:.1} GB", bytes as f64 / GB as f64) }
    else if bytes >= MB { format!("{:.1} MB", bytes as f64 / MB as f64) }
    else if bytes >= KB { format!("{:.1} KB", bytes as f64 / KB as f64) }
    else { format!("{bytes} B") }
}

fn format_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn format_elapsed(secs: f64) -> String {
    let total = secs as u64;
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    format!("+{h}:{m:02}:{s:02}")
}

fn bw_bar(bps: u64, max_bps: u64) -> String {
    if max_bps == 0 { return String::new(); }
    let ratio = (bps as f64 / max_bps as f64).clamp(0.0, 1.0);
    let filled = (ratio * 10.0) as usize;
    let empty = 10usize.saturating_sub(filled);
    format!("{}{}", "\u{2588}".repeat(filled), "\u{2591}".repeat(empty))
}

fn filter_nodes(nodes: &[NodeInfo], tab: TabKind) -> Vec<NodeInfo> {
    nodes.iter()
        .filter(|n| match tab {
            TabKind::All => true,
            TabKind::Entry => n.node_type == "Entry",
            TabKind::Middle => n.node_type == "Middle",
            TabKind::Exit => n.node_type == "Exit",
        })
        .cloned()
        .collect()
}

fn sort_nodes(nodes: &mut [NodeInfo], col: SortCol, asc: bool) {
    match col {
        SortCol::Id => nodes.sort_by(|a, b| if asc { a.node_id.cmp(&b.node_id) } else { b.node_id.cmp(&a.node_id) }),
        SortCol::Type => nodes.sort_by(|a, b| if asc { a.node_type.cmp(&b.node_type) } else { b.node_type.cmp(&a.node_type) }),
        SortCol::Addr => nodes.sort_by(|a, b| if asc { a.address.cmp(&b.address) } else { b.address.cmp(&a.address) }),
        SortCol::Bw => nodes.sort_by(|a, b| if asc { a.bandwidth.cmp(&b.bandwidth) } else { b.bandwidth.cmp(&a.bandwidth) }),
    }
}

#[component]
fn NodeRow(node: NodeInfo, selected_id: ReadSignal<Option<String>>, on_select: Callback<String>, max_bw: u64) -> impl IntoView {
    let nid = node.node_id.clone();
    let short_id: String = nid.chars().take(12).collect();
    let bw = format_bandwidth(node.bandwidth);
    let bar = bw_bar(node.bandwidth, max_bw);
    let type_class = format!("type-badge type-{}", match node.node_type.as_str() {
        "Entry" => "entry", "Middle" => "middle", "Exit" => "exit", _ => ""
    });
    let nid_for_row = nid.clone();

    let selected = move || selected_id.get().as_ref() == Some(&nid);

    view! {
        <tr class="node-row" class:row-selected=selected on:click=move |_| on_select.run(nid_for_row.clone())>
            <td class="mono" title=node.node_id.clone()>{short_id}"..."</td>
            <td><span class=type_class>{node.node_type.clone()}</span></td>
            <td class="mono">{node.address.clone()}</td>
            <td class="right mono">
                <span class="bw-bar">{bar}</span>
                " " {bw}
            </td>
        </tr>
    }
}

#[component]
fn EventRow(entry: EventEntry) -> impl IntoView {
    let time_str = format_elapsed(entry.elapsed_secs);
    let label_class = format!("log-label ev-{}", entry.event_type);

    view! {
        <div class="log-row">
            <span class="log-time">{time_str}</span>
            <span class=label_class>{entry.label}</span>
            <span class="log-detail">{entry.detail}</span>
        </div>
    }
}

fn relay_event_color(ev: &str) -> &'static str {
    if ev.contains("\u{2190} ACCEPT")      { "rel-accept" }
    else if ev.contains("\u{2699} CREATE") { "rel-create" }
    else if ev.contains("\u{2192} EXTEND") { "rel-extend" }
    else if ev.contains("\u{2717} DESTROY"){ "rel-destroy" }
    else if ev.contains("\u{2717} ERROR")  { "rel-error" }
    else if ev.contains("\u{2192} STREAM") { "rel-stream" }
    else if ev.contains("\u{2014} END")    { "rel-end" }
    else if ev.contains("\u{2014} CLOSED") { "rel-end" }
    else if ev.contains("\u{2194} DATA")   { "rel-data" }
    else if ev.contains("\u{2192} RELAY\u{2192}") { "rel-fwd" }
    else if ev.contains("\u{2190} RELAY\u{2190}") { "rel-bwd" }
    else { "rel-default" }
}

/// Split a relay event into (timestamp, label, detail).
/// Events are formatted as: "[+0:00:05] ICON LABEL    detail text here"
fn split_relay_event(ev: &str) -> (String, String, String) {
    // Split timestamp (before first "] ")
    let (ts, rest) = if let Some(pos) = ev.find("] ") {
        let ts = &ev[..=pos];   // "[+0:00:05]"
        let rest = ev[pos + 2..].trim_start(); // "ICON LABEL    detail..."
        (ts, rest)
    } else {
        return (String::new(), ev.to_string(), String::new());
    };

    // Split label from detail at the gap
    if let Some(pos) = rest.find("    ") {
        let label = rest[..pos].to_string();
        let detail = rest[pos..].trim_start().to_string();
        (ts.to_string(), label, detail)
    } else {
        (ts.to_string(), rest.to_string(), String::new())
    }
}

#[component]
pub fn App() -> impl IntoView {
    let data: RwSignal<Option<DashboardData>> = RwSignal::new(None);
    let active_tab: RwSignal<TabKind> = RwSignal::new(TabKind::All);
    let sort_col: RwSignal<SortCol> = RwSignal::new(SortCol::Id);
    let sort_asc: RwSignal<bool> = RwSignal::new(true);
    let selected_id: RwSignal<Option<String>> = RwSignal::new(None);
    let all_events: RwSignal<Vec<EventEntry>> = RwSignal::new(Vec::new());
    let latest_elapsed: RwSignal<f64> = RwSignal::new(0.0);
    let countdown: RwSignal<u8> = RwSignal::new(3);

    spawn_local(async move {
        loop {
            if let Some(d) = fetch_dashboard().await {
                let mut events = all_events.get();

                // Collect events newer than the last-seen timestamp.
                // Process oldest-first so events sharing the same timestamp
                // all pass (e.g. 3 PATH events from pool initialization).
                let threshold = latest_elapsed.get();
                let mut fresh: Vec<EventEntry> = d
                    .events
                    .iter()
                    .filter(|e| e.elapsed_secs > threshold)
                    .cloned()
                    .collect();
                fresh.sort_by(|a, b| a.elapsed_secs.partial_cmp(&b.elapsed_secs).unwrap());

                let mut new_threshold = threshold;
                for evt in fresh {
                    new_threshold = evt.elapsed_secs;
                    events.push(evt);
                }
                latest_elapsed.set(new_threshold);

                events.truncate(20);
                all_events.set(events);
                data.set(Some(d));
            }
            for i in (1..=10).rev() {
                countdown.set(i);
                gloo_timers::future::sleep(std::time::Duration::from_millis(1000)).await;
            }
        }
    });

    let on_sort = move |col: SortCol| {
        if sort_col.get() == col {
            sort_asc.update(|v| *v = !*v);
        } else {
            sort_col.set(col);
            sort_asc.set(true);
        }
    };

    view! {
        <div class="container">
            <header class="header">
                <h1>"$ discovery --dashboard"<span class="cursor">"_"</span></h1>
                {move || data.get().map(|d| {
                    let uptime = format_uptime(d.metrics.uptime_secs);
                    view! {
                        <div class="header-stats">
                            <span class="stat">"Up: " <strong>{uptime}</strong></span>
                            <span class="stat">"Nodes: " <strong>{d.stats.total_nodes}</strong> " (E:" <strong>{d.stats.entry_count}</strong> " M:" <strong>{d.stats.middle_count}</strong> " X:" <strong>{d.stats.exit_count}</strong> ")"</span>
                            <span class="stat">"Paths: " <strong>{d.metrics.path_requests}</strong></span>
                        </div>
                    }
                })}
            </header>

            <div class="tab-bar">
                <button class="tab-btn" class:tab-active=move || active_tab.get() == TabKind::All
                    on:click=move |_| { active_tab.set(TabKind::All); selected_id.set(None); }>"All Nodes"</button>
                <button class="tab-btn" class:tab-active=move || active_tab.get() == TabKind::Entry
                    on:click=move |_| { active_tab.set(TabKind::Entry); selected_id.set(None); }>"Entry"</button>
                <button class="tab-btn" class:tab-active=move || active_tab.get() == TabKind::Middle
                    on:click=move |_| { active_tab.set(TabKind::Middle); selected_id.set(None); }>"Middle"</button>
                <button class="tab-btn" class:tab-active=move || active_tab.get() == TabKind::Exit
                    on:click=move |_| { active_tab.set(TabKind::Exit); selected_id.set(None); }>"Exit"</button>
            </div>

            <div class="node-panel">
                <table class="node-table">
                    <thead>
                        <tr>
                            <th style="cursor:pointer" on:click=move |_| on_sort(SortCol::Id)>
                                "ID" {move || if sort_col.get() == SortCol::Id { if sort_asc.get() { " ▲" } else { " ▼" } } else { "" }}
                            </th>
                            <th style="cursor:pointer" on:click=move |_| on_sort(SortCol::Type)>
                                "Type" {move || if sort_col.get() == SortCol::Type { if sort_asc.get() { " ▲" } else { " ▼" } } else { "" }}
                            </th>
                            <th style="cursor:pointer" on:click=move |_| on_sort(SortCol::Addr)>
                                "Addr" {move || if sort_col.get() == SortCol::Addr { if sort_asc.get() { " ▲" } else { " ▼" } } else { "" }}
                            </th>
                            <th class="right" style="cursor:pointer" on:click=move |_| on_sort(SortCol::Bw)>
                                "BW" {move || if sort_col.get() == SortCol::Bw { if sort_asc.get() { " ▲" } else { " ▼" } } else { "" }}
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        {move || {
                            let d = data.get();
                            match &d {
                                Some(d) => {
                                    let mut nodes = filter_nodes(&d.nodes, active_tab.get());
                                    let max_bw = nodes.iter().map(|n| n.bandwidth).max().unwrap_or(1);
                                    sort_nodes(&mut nodes, sort_col.get(), sort_asc.get());
                                    if nodes.is_empty() {
                                        view! { <tr><td colspan="4" class="empty-cell">"No nodes matching filter"</td></tr> }.into_any()
                                    } else {
                                        nodes.into_iter().map(move |n| {
                                            let sel = selected_id;
                                            view! { <NodeRow node=n selected_id=sel.read_only() on_select=Callback::new(move |id: String| { if selected_id.get() == Some(id.clone()) { selected_id.set(None) } else { selected_id.set(Some(id)) }}) max_bw=max_bw/> }
                                        }).collect_view().into_any()
                                    }
                                }
                                None => view! { <tr><td colspan="4" class="empty-cell">"Connecting to discovery service..."</td></tr> }.into_any()
                            }
                        }}
                    </tbody>
                </table>
            </div>

            {move || {
                if let (Some(ref id), Some(ref d)) = (selected_id.get(), data.get()) {
                    if let Some(n) = d.nodes.iter().find(|n| n.node_id == *id) {
                        let bw = format_bandwidth(n.bandwidth);
                        let m = n.metrics.as_ref();
                        let uptime = m.map(|m| format_uptime(m.uptime_secs)).unwrap_or_default();
                        let conns = m.map(|m| m.connections_accepted.to_string()).unwrap_or_default();
                        let streams = m.map(|m| m.streams_opened.to_string()).unwrap_or_default();
                        let created = m.map(|m| m.circuits_created.to_string()).unwrap_or_default();
                        let destroyed = m.map(|m| m.circuits_destroyed.to_string()).unwrap_or_default();
                        let fwd = m.map(|m| format_bytes(m.bytes_forwarded)).unwrap_or_default();
                        let recv = m.map(|m| format_bytes(m.bytes_received)).unwrap_or_default();
                        let relay_events = m.map(|m| m.event_snapshot.clone()).unwrap_or_default();
                        let short_id: String = n.node_id.chars().take(12).collect();
                        let ntype = n.node_type.clone();
                        let addr = n.address.clone();
                        return view! {
                            <div class="bottom-panel">
                                <div class="bottom-header">
                                    <span class="tab-label">"Node: " {short_id}"..."</span>
                                    <span class="tab-label-inactive" style="margin-left:8px">{ntype}</span>
                                    <span class="stat" style="margin-left:8px">{addr}</span>
                                    <span class="stat" style="margin-left:8px">"BW: " {bw}</span>
                                    <span class="stat" style="margin-left:8px">"Up: " {uptime}</span>
                                    <span class="stat" style="margin-left:8px">"Conn: " {conns}</span>
                                    <span class="stat" style="margin-left:8px">"Str: " {streams}</span>
                                    <span class="stat" style="margin-left:8px">"Circ: " {created}"/" {destroyed}</span>
                                    <span class="stat" style="margin-left:8px">"Fwd: " {fwd}</span>
                                    <span class="stat" style="margin-left:8px">"Rec: " {recv}</span>
                                </div>
                                <div class="log-panel" style="max-height:200px;border:1px solid var(--border);margin-top:4px">
                                    {if relay_events.is_empty() {
                                        view! { <div class="log-empty-msg">"Waiting for relay events..."</div> }.into_any()
                                    } else {
                                        relay_events.into_iter().rev().take(200).map(|ev| {
                                            let color = relay_event_color(&ev);
                                            let (ts, label, detail) = split_relay_event(&ev);
                                            view! {
                                                <div class="log-row">
                                                    <span class="rel-time">{ts}" "</span>
                                                    <span class=color.to_string()>{label}"    "</span>
                                                    <span class="rel-detail">{detail}</span>
                                                </div>
                                            }
                                        }).collect_view().into_any()
                                    }}
                                </div>
                            </div>
                        }.into_any();
                    }
                }
                view! {}.into_any()
            }}

            <div class="log-panel-side">
                <div class="tab-label-inactive">
                    "Activity Log"
                    {move || view! { <span class="log-count">" (" {all_events.get().len()} " events)"</span> }}
                </div>
                <div class="log-panel">
                    {move || {
                        let evts = all_events.get();
                        if evts.is_empty() {
                            view! { <div class="log-empty-msg">"No activity yet"</div> }.into_any()
                        } else {
                            evts.into_iter().rev().map(|e| view! { <EventRow entry=e/> }).collect_view().into_any()
                        }
                    }}
                </div>
            </div>

            <div class="status-bar">
                {move || {
                    let c = countdown.get();
                    let filled = "\u{2588}".repeat(c as usize);
                    let empty = "\u{2591}".repeat(10usize.saturating_sub(c as usize));
                    view! { <span class="countdown-bar">{filled}{empty}</span> }
                }}
            </div>
        </div>
    }
}
