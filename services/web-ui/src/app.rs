use gloo_net::http::Request;
use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;

#[derive(Debug, Clone, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub node_type: String,
    pub address: String,
    pub bandwidth: u64,
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

async fn fetch_dashboard() -> Option<DashboardData> {
    let resp = Request::get("/api/dashboard").send().await.ok()?;
    resp.json::<DashboardData>().await.ok()
}

fn format_bandwidth(bps: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bps >= GB {
        format!("{:.1} GB/s", bps as f64 / GB as f64)
    } else if bps >= MB {
        format!("{:.1} MB/s", bps as f64 / MB as f64)
    } else if bps >= KB {
        format!("{:.1} KB/s", bps as f64 / KB as f64)
    } else {
        format!("{bps} B/s")
    }
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

#[component]
fn NodeRow(node: NodeInfo) -> impl IntoView {
    let type_class = match node.node_type.as_str() {
        "Entry" => "type-badge type-entry",
        "Middle" => "type-badge type-middle",
        "Exit" => "type-badge type-exit",
        _ => "type-badge",
    };
    let short_id: String = node.node_id.chars().take(12).collect();
    let bw = format_bandwidth(node.bandwidth);
    let node_type = node.node_type.clone();
    let address = node.address.clone();
    let full_id = node.node_id.clone();

    view! {
        <tr>
            <td class="mono" title=full_id>{short_id}"..."</td>
            <td><span class=type_class>{node_type}</span></td>
            <td class="mono">{address}</td>
            <td class="right mono">{bw}</td>
        </tr>
    }
}

#[component]
fn EventRow(entry: EventEntry) -> impl IntoView {
    let time_str = format_elapsed(entry.elapsed_secs);
    let label_class = format!("log-label ev-{}", entry.event_type);
    let label = entry.label.clone();
    let detail = entry.detail.clone();

    view! {
        <div class="log-row">
            <span class="log-time">{time_str}</span>
            <span class=label_class>{label}</span>
            <span class="log-detail">{detail}</span>
        </div>
    }
}

#[component]
pub fn App() -> impl IntoView {
    let data: RwSignal<Option<DashboardData>> = RwSignal::new(None);

    spawn_local(async move {
        loop {
            if let Some(d) = fetch_dashboard().await {
                data.set(Some(d));
            }
            gloo_timers::future::sleep(std::time::Duration::from_millis(3000)).await;
        }
    });

    view! {
        <div class="container">
            <header class="header">
                <h1>"Tor Discovery Service"</h1>
                {move || data.get().map(|d| {
                    let ready_class = if d.ready { "badge badge-ready" } else { "badge badge-not-ready" };
                    let ready_text = if d.ready { "● READY" } else { "✗ NOT READY" };
                    let uptime = format_uptime(d.metrics.uptime_secs);
                    let e = d.stats.entry_count;
                    let m = d.stats.middle_count;
                    let x = d.stats.exit_count;
                    let regs   = d.metrics.registrations;
                    let rms    = d.metrics.removals;
                    let hbs    = d.metrics.heartbeats;
                    let paths  = d.metrics.path_requests;
                    let cleaned = d.metrics.stale_cleaned;
                    view! {
                        <div class="header-stats">
                            <span class=ready_class>{ready_text}</span>
                            <span class="stat">"Up: " <strong>{uptime}</strong></span>
                            <span class="stat-sep">"E:" <strong>{e}</strong> " M:" <strong>{m}</strong> " X:" <strong>{x}</strong></span>
                            <span class="stat">"Regs: " <strong>{regs}</strong></span>
                            <span class="stat">"Removed: " <strong>{rms}</strong></span>
                            <span class="stat">"HBs: " <strong>{hbs}</strong></span>
                            <span class="stat">"Paths: " <strong>{paths}</strong></span>
                            <span class="stat">"Cleaned: " <strong>{cleaned}</strong></span>
                        </div>
                    }
                })}
            </header>

            // ── Node Registry ───────────────────────────────────────────────
            <div class="section-label">"Node Registry"</div>
            <table class="node-table">
                <thead>
                    <tr>
                        <th>"ID"</th>
                        <th>"Type"</th>
                        <th>"Address"</th>
                        <th class="right">"Bandwidth"</th>
                    </tr>
                </thead>
                <tbody>
                    {move || match data.get() {
                        None => view! {
                            <tr class="empty-row"><td colspan="4">"Connecting to discovery service..."</td></tr>
                        }.into_any(),
                        Some(d) if d.nodes.is_empty() => view! {
                            <tr class="empty-row"><td colspan="4">"No relay nodes registered"</td></tr>
                        }.into_any(),
                        Some(d) => d.nodes
                            .into_iter()
                            .map(|n| view! { <NodeRow node=n/> })
                            .collect_view()
                            .into_any(),
                    }}
                </tbody>
            </table>

            // ── Activity Log ────────────────────────────────────────────────
            <div class="section-label" style="margin-top:20px">
                "Activity Log"
                {move || data.get().map(|d| {
                    let count = d.events.len();
                    view! { <span class="log-count">" (" {count} " events)"</span> }
                })}
            </div>
            <div class="log-panel">
                {move || match data.get() {
                    None => view! {
                        <div class="log-empty">"Waiting for events..."</div>
                    }.into_any(),
                    Some(d) if d.events.is_empty() => view! {
                        <div class="log-empty">"No activity yet"</div>
                    }.into_any(),
                    Some(d) => d.events
                        .into_iter()
                        .map(|e| view! { <EventRow entry=e/> })
                        .collect_view()
                        .into_any(),
                }}
            </div>

            <div class="footer">
                "Refreshes every 3s · "
                {move || data.get().map(|d| format!("{} node(s) registered", d.stats.total_nodes))}
            </div>
        </div>
    }
}
