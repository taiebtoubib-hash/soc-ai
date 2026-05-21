import { useState, useEffect, useCallback } from "react";

const MOCK_INCIDENTS = [
  {
    id: "INC-7f2a1b", timestamp: new Date(Date.now() - 12000).toISOString(),
    src_ip: "185.220.101.47", rule: "BRUTE_FORCE", attack_type: "r2l",
    ml_label: "malicious", final_score: 0.94,
    actions: ["block_ip", "notify", "log"], resolved: true,
    llm_analysis: "High-confidence brute-force attack from a Tor exit node (RU). 47 failed SSH auth attempts in 5 min. Immediate block recommended.",
    country: "RU", features: { src_port: 54821, dst_port: 22, protocol: "tcp", failed_auth: 47, unique_ports: 1 },
  },
  {
    id: "INC-3c9d4e", timestamp: new Date(Date.now() - 45000).toISOString(),
    src_ip: "103.76.228.12", rule: "PORT_SCAN", attack_type: "probe",
    ml_label: "malicious", final_score: 0.87,
    actions: ["block_ip", "log"], resolved: true,
    llm_analysis: "Systematic TCP SYN scan across 32 ports from CN infrastructure. Classic reconnaissance pattern prior to targeted exploitation.",
    country: "CN", features: { src_port: 49120, dst_port: 443, protocol: "tcp", failed_auth: 0, unique_ports: 32 },
  },
  {
    id: "INC-8a5f2c", timestamp: new Date(Date.now() - 120000).toISOString(),
    src_ip: "91.108.4.18", rule: "C2_COMMUNICATION", attack_type: "u2r",
    ml_label: "malicious", final_score: 0.91,
    actions: ["isolate_host", "notify", "block_ip", "log"], resolved: false,
    llm_analysis: "Active C2 beacon to known Cobalt Strike infrastructure. Affected host should be immediately isolated. Lateral movement risk is high.",
    country: "NL", features: { src_port: 443, dst_port: 4444, protocol: "tcp", failed_auth: 0, unique_ports: 3 },
  },
  {
    id: "INC-1e6b9f", timestamp: new Date(Date.now() - 300000).toISOString(),
    src_ip: "192.168.1.102", rule: "DATA_EXFILTRATION", attack_type: "r2l",
    ml_label: "suspicious", final_score: 0.63,
    actions: ["notify", "log"], resolved: true,
    llm_analysis: "Unusual outbound DNS traffic volume from internal host. Possible DNS tunneling. Recommend PCAP capture and endpoint investigation.",
    country: "internal", features: { src_port: 53124, dst_port: 53, protocol: "udp", failed_auth: 0, unique_ports: 1 },
  },
  {
    id: "INC-5d3c7a", timestamp: new Date(Date.now() - 600000).toISOString(),
    src_ip: "45.152.66.55", rule: "PORT_SCAN", attack_type: "probe",
    ml_label: "suspicious", final_score: 0.58,
    actions: ["log"], resolved: true,
    llm_analysis: "Low-intensity scan, possibly automated vulnerability scanner. Monitor for escalation. No immediate action required.",
    country: "DE", features: { src_port: 62441, dst_port: 80, protocol: "tcp", failed_auth: 0, unique_ports: 8 },
  },
];

const THREAT_STATS = { total_24h: 247, malicious: 31, suspicious: 89, blocked_ips: 28, auto_resolved: 94, avg_response_ms: 340 };

const timeAgo = (iso) => {
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
};
const scoreColor = (s) => s >= 0.85 ? "#ff3b5c" : s >= 0.6 ? "#ff9f0a" : "#30d158";
const labelBg = (l) => ({
  malicious: { bg: "rgba(255,59,92,0.15)", text: "#ff3b5c", border: "rgba(255,59,92,0.3)" },
  suspicious: { bg: "rgba(255,159,10,0.15)", text: "#ff9f0a", border: "rgba(255,159,10,0.3)" },
  benign: { bg: "rgba(48,209,88,0.15)", text: "#30d158", border: "rgba(48,209,88,0.3)" },
}[l] || { bg: "rgba(255,255,255,0.05)", text: "#aaa", border: "rgba(255,255,255,0.1)" });
const actionIcon = (a) => ({ block_ip: "🚫", isolate_host: "🔒", notify: "📣", log: "📋" }[a] || "⚙️");
const verdictMeta = (v) => ({
  confirmed_tp: { label: "✓ CONFIRMED", color: "#30d158", bg: "rgba(48,209,88,0.1)" },
  false_positive: { label: "✗ MARKED FP", color: "#ff9f0a", bg: "rgba(255,159,10,0.1)" },
  escalated: { label: "⬆ ESCALATED", color: "#00c8ff", bg: "rgba(0,200,255,0.1)" },
}[v]);

function Sparkline({ data, color }) {
  const w = 80, h = 28, mx = Math.max(...data), mn = Math.min(...data);
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - ((v - mn) / (mx - mn || 1)) * h}`).join(" ");
  return <svg width={w} height={h} style={{ display: "block" }}><polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" /></svg>;
}

function ScoreRing({ score }) {
  const r = 16, c = 2 * Math.PI * r, color = scoreColor(score);
  return (
    <svg width="42" height="42" viewBox="0 0 42 42">
      <circle cx="21" cy="21" r={r} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="3" />
      <circle cx="21" cy="21" r={r} fill="none" stroke={color} strokeWidth="3"
        strokeDasharray={`${score * c} ${c}`} strokeLinecap="round" transform="rotate(-90 21 21)" />
      <text x="21" y="21" textAnchor="middle" dominantBaseline="central"
        style={{ fill: color, fontSize: "9px", fontFamily: "monospace", fontWeight: 700 }}>
        {(score * 100).toFixed(0)}
      </text>
    </svg>
  );
}

function IncidentRow({ inc, selected, fbVerdict, onClick }) {
  const lc = labelBg(inc.ml_label);
  const vm = fbVerdict ? verdictMeta(fbVerdict) : null;
  return (
    <div onClick={onClick} style={{
      display: "grid", gridTemplateColumns: "42px 1fr 80px 52px 108px",
      alignItems: "center", gap: "10px", padding: "10px 14px",
      cursor: "pointer", borderBottom: "1px solid rgba(255,255,255,0.04)",
      background: selected ? "rgba(0,200,255,0.05)" : "transparent",
      borderLeft: selected ? "2px solid #00c8ff" : "2px solid transparent",
      transition: "background 0.15s",
    }}>
      <ScoreRing score={inc.final_score} />
      <div>
        <div style={{ display: "flex", gap: 7, alignItems: "center", marginBottom: 3 }}>
          <span style={{ fontFamily: "monospace", fontSize: 12, color: "#ddd", fontWeight: 600 }}>{inc.src_ip}</span>
          <span style={{ fontFamily: "monospace", fontSize: 9, color: "#444" }}>{inc.country}</span>
        </div>
        <span style={{ fontSize: 10, color: "#555", fontFamily: "monospace" }}>{inc.rule}</span>
      </div>
      <span style={{
        fontSize: 9, fontWeight: 700, fontFamily: "monospace", letterSpacing: "0.04em",
        padding: "3px 6px", borderRadius: 3, background: lc.bg, color: lc.text, border: `1px solid ${lc.border}`,
        textAlign: "center",
      }}>{inc.ml_label.toUpperCase()}</span>
      <div style={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
        {inc.actions.slice(0, 3).map(a => <span key={a} title={a} style={{ fontSize: 12 }}>{actionIcon(a)}</span>)}
      </div>
      {vm
        ? <span style={{ fontSize: 9, fontWeight: 700, fontFamily: "monospace", padding: "3px 6px", borderRadius: 3, background: vm.bg, color: vm.color, textAlign: "center", letterSpacing: "0.04em" }}>{vm.label}</span>
        : <span style={{ fontSize: 10, color: "#333", fontFamily: "monospace", textAlign: "right" }}>{timeAgo(inc.timestamp)}</span>
      }
    </div>
  );
}

function FeedbackPanel({ inc, existingFeedback, onSubmit }) {
  const [verdict, setVerdict] = useState(null);
  const [note, setNote] = useState("");
  const [correctLabel, setCorrectLabel] = useState("");
  const [done, setDone] = useState(false);

  useEffect(() => { setVerdict(null); setNote(""); setCorrectLabel(""); setDone(false); }, [inc?.id]);

  if (!inc) return null;

  if (existingFeedback || done) {
    const fb = existingFeedback;
    const vm = verdictMeta(fb?.verdict || verdict);
    return (
      <div style={{ background: "rgba(48,209,88,0.03)", border: "1px solid rgba(48,209,88,0.12)", borderRadius: 8, padding: "14px", marginTop: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#30d158" }} />
          <span style={{ fontFamily: "monospace", fontSize: 10, color: "#30d158", letterSpacing: "0.08em" }}>FEEDBACK RECORDED</span>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 8 }}>
          {vm && <span style={{ fontSize: 11, fontWeight: 700, fontFamily: "monospace", padding: "3px 10px", borderRadius: 4, background: vm.bg, color: vm.color }}>{vm.label}</span>}
          {fb?.correctLabel && <span style={{ fontSize: 11, color: "#666", fontFamily: "monospace" }}>→ <span style={{ color: "#ff9f0a" }}>{fb.correctLabel}</span></span>}
        </div>
        {fb?.note && <div style={{ padding: "7px 10px", background: "rgba(255,255,255,0.02)", borderRadius: 4, fontSize: 11, color: "#555", fontStyle: "italic", borderLeft: "2px solid rgba(255,255,255,0.06)", marginBottom: 8 }}>"{fb.note}"</div>}
        <div style={{ fontSize: 9, color: "#2d2d2d", fontFamily: "monospace" }}>→ queued for soc.feedback topic · will retrain fp_model.pkl + threat_model.pkl</div>
      </div>
    );
  }

  const opts = [
    { key: "confirmed_tp", icon: "✓", label: "Confirm threat", desc: "System was correct", color: "#30d158", border: "rgba(48,209,88,0.35)", bg: "rgba(48,209,88,0.1)" },
    { key: "false_positive", icon: "✗", label: "Mark as FP", desc: "Not a real threat", color: "#ff9f0a", border: "rgba(255,159,10,0.35)", bg: "rgba(255,159,10,0.1)" },
    { key: "escalated", icon: "⬆", label: "Escalate", desc: "Needs tier-2 review", color: "#00c8ff", border: "rgba(0,200,255,0.35)", bg: "rgba(0,200,255,0.1)" },
  ];

  return (
    <div style={{ background: "rgba(255,255,255,0.015)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 8, padding: "14px", marginTop: 12 }}>
      <div style={{ fontFamily: "monospace", fontSize: 9, color: "#444", letterSpacing: "0.1em", marginBottom: 12, textTransform: "uppercase" }}>Analyst feedback</div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 7, marginBottom: 12 }}>
        {opts.map(o => (
          <button key={o.key} onClick={() => setVerdict(o.key)} style={{
            padding: "10px 6px", borderRadius: 6, cursor: "pointer",
            border: verdict === o.key ? `1.5px solid ${o.border}` : "1px solid rgba(255,255,255,0.07)",
            background: verdict === o.key ? o.bg : "rgba(255,255,255,0.01)",
            transition: "all 0.15s", display: "flex", flexDirection: "column", alignItems: "center", gap: 4,
          }}>
            <span style={{ fontSize: 20, color: verdict === o.key ? o.color : "#3a3a3a" }}>{o.icon}</span>
            <span style={{ fontFamily: "monospace", fontSize: 9, fontWeight: 700, letterSpacing: "0.04em", color: verdict === o.key ? o.color : "#444" }}>{o.label.toUpperCase()}</span>
            <span style={{ fontSize: 9, color: verdict === o.key ? o.color : "#2a2a2a", textAlign: "center", lineHeight: 1.4, opacity: 0.85 }}>{o.desc}</span>
          </button>
        ))}
      </div>
      {verdict === "false_positive" && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ fontFamily: "monospace", fontSize: 9, color: "#444", marginBottom: 6, letterSpacing: "0.06em" }}>CORRECT LABEL</div>
          <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
            {["benign", "scanner", "internal_tool", "pentest", "noise"].map(l => (
              <button key={l} onClick={() => setCorrectLabel(l === correctLabel ? "" : l)} style={{
                padding: "3px 9px", borderRadius: 3, fontSize: 9, fontFamily: "monospace", cursor: "pointer",
                border: correctLabel === l ? "1px solid rgba(255,159,10,0.4)" : "1px solid rgba(255,255,255,0.07)",
                background: correctLabel === l ? "rgba(255,159,10,0.1)" : "transparent",
                color: correctLabel === l ? "#ff9f0a" : "#444",
              }}>{l}</button>
            ))}
          </div>
        </div>
      )}
      <textarea value={note} onChange={e => setNote(e.target.value)}
        placeholder="Optional note — context, evidence, reason for override..."
        rows={2} style={{
          width: "100%", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 5, padding: "7px 10px", color: "#999", fontFamily: "monospace", fontSize: 11,
          resize: "none", outline: "none", marginBottom: 10, lineHeight: 1.5,
        }} />
      <button onClick={() => {
        if (!verdict) return;
        onSubmit(inc.id, {
          verdict, note: note.trim(), correctLabel: verdict === "false_positive" ? correctLabel : "",
          incidentId: inc.id, srcIp: inc.src_ip, originalLabel: inc.ml_label,
          originalScore: inc.final_score, rule: inc.rule, features: inc.features,
          analystTimestamp: new Date().toISOString()
        });
        setDone(true);
      }} disabled={!verdict} style={{
        width: "100%", padding: "9px", borderRadius: 6, fontFamily: "monospace", fontSize: 11,
        fontWeight: 700, letterSpacing: "0.06em", cursor: verdict ? "pointer" : "not-allowed",
        border: verdict ? "1px solid rgba(0,200,255,0.35)" : "1px solid rgba(255,255,255,0.05)",
        background: verdict ? "rgba(0,200,255,0.08)" : "transparent",
        color: verdict ? "#00c8ff" : "#2a2a2a", transition: "all 0.15s",
      }}>
        {verdict ? "SUBMIT → soc.feedback" : "SELECT A VERDICT TO CONTINUE"}
      </button>
      <div style={{ marginTop: 6, fontSize: 9, color: "#252525", fontFamily: "monospace" }}>
        Features vector + verdict saved as new training row for next model retrain
      </div>
    </div>
  );
}

function DetailPanel({ inc, feedback, onFeedback }) {
  if (!inc) return <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "#2a2a2a", fontSize: 13 }}>Select an incident</div>;
  const lc = labelBg(inc.ml_label);
  return (
    <div style={{ padding: "16px", overflowY: "auto", height: "100%" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
        <div>
          <div style={{ fontFamily: "monospace", fontSize: 11, color: "#444", marginBottom: 3 }}>{inc.id}</div>
          <div style={{ fontFamily: "monospace", fontSize: 17, color: "#eee", fontWeight: 700 }}>{inc.src_ip}</div>
        </div>
        <span style={{ padding: "4px 12px", borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: "monospace", background: lc.bg, color: lc.text, border: `1px solid ${lc.border}` }}>{inc.ml_label.toUpperCase()}</span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 7, marginBottom: 12 }}>
        {[["Rule", inc.rule], ["Attack", inc.attack_type.toUpperCase()], ["Score", `${(inc.final_score * 100).toFixed(1)}%`], ["Country", inc.country], ["Status", inc.resolved ? "✅ Resolved" : "⏳ Pending"], ["Time", timeAgo(inc.timestamp)]].map(([k, v]) => (
          <div key={k} style={{ background: "rgba(255,255,255,0.02)", borderRadius: 5, padding: "7px 9px", border: "1px solid rgba(255,255,255,0.04)" }}>
            <div style={{ fontSize: 9, color: "#3a3a3a", fontFamily: "monospace", marginBottom: 2, textTransform: "uppercase", letterSpacing: "0.08em" }}>{k}</div>
            <div style={{ fontSize: 12, color: "#bbb", fontFamily: "monospace" }}>{v}</div>
          </div>
        ))}
      </div>
      <div style={{ background: "rgba(0,200,100,0.03)", border: "1px solid rgba(0,200,100,0.1)", borderRadius: 7, padding: "11px", marginBottom: 11 }}>
        <div style={{ fontSize: 9, color: "#30d158", fontFamily: "monospace", marginBottom: 6, letterSpacing: "0.1em" }}>🤖 AI ANALYSIS — OLLAMA</div>
        <div style={{ fontSize: 11, color: "#888", lineHeight: 1.7 }}>{inc.llm_analysis}</div>
      </div>
      <div style={{ marginBottom: 4 }}>
        <div style={{ fontSize: 9, color: "#333", fontFamily: "monospace", marginBottom: 6, letterSpacing: "0.08em", textTransform: "uppercase" }}>Actions executed</div>
        <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
          {inc.actions.map(a => (
            <div key={a} style={{ display: "flex", alignItems: "center", gap: 5, background: "rgba(255,255,255,0.02)", borderRadius: 4, padding: "4px 9px", border: "1px solid rgba(255,255,255,0.04)", fontSize: 10, color: "#777", fontFamily: "monospace" }}>
              <span>{actionIcon(a)}</span><span>{a}</span><span style={{ color: "#30d158", fontSize: 9 }}>✓</span>
            </div>
          ))}
        </div>
      </div>
      <FeedbackPanel inc={inc} existingFeedback={feedback[inc.id]} onSubmit={onFeedback} />
    </div>
  );
}

function StatCard({ label, value, sub, spark, sparkColor }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 10, padding: "12px 14px", display: "flex", flexDirection: "column", gap: 5 }}>
      <div style={{ fontSize: 9, color: "#3a3a3a", fontFamily: "monospace", letterSpacing: "0.1em", textTransform: "uppercase" }}>{label}</div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
        <div>
          <div style={{ fontSize: 22, fontWeight: 700, fontFamily: "monospace", color: "#e8e8e8", lineHeight: 1 }}>{value}</div>
          {sub && <div style={{ fontSize: 10, color: "#3a3a3a", marginTop: 3 }}>{sub}</div>}
        </div>
        {spark && <Sparkline data={spark} color={sparkColor || "#00c8ff"} />}
      </div>
    </div>
  );
}

function FeedbackLog({ log }) {
  if (!log.length) return <div style={{ padding: 28, textAlign: "center", color: "#2a2a2a", fontFamily: "monospace", fontSize: 11 }}>No feedback submitted yet in this session</div>;
  return (
    <div>
      {log.slice().reverse().map((fb, i) => {
        const vm = verdictMeta(fb.verdict);
        return (
          <div key={i} style={{ padding: "10px 16px", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
              <span style={{ fontSize: 9, fontWeight: 700, fontFamily: "monospace", padding: "2px 7px", borderRadius: 3, background: vm.bg, color: vm.color }}>{vm.label}</span>
              <span style={{ fontFamily: "monospace", fontSize: 11, color: "#777" }}>{fb.srcIp}</span>
              <span style={{ fontFamily: "monospace", fontSize: 9, color: "#3a3a3a" }}>{fb.rule}</span>
              <span style={{ marginLeft: "auto", fontFamily: "monospace", fontSize: 9, color: "#2d2d2d" }}>{new Date(fb.analystTimestamp).toLocaleTimeString()}</span>
            </div>
            <div style={{ display: "flex", gap: 14, fontSize: 9, color: "#444", fontFamily: "monospace" }}>
              <span>original: <span style={{ color: "#666" }}>{fb.originalLabel}</span></span>
              {fb.correctLabel && <span>→ <span style={{ color: "#ff9f0a" }}>{fb.correctLabel}</span></span>}
              <span>score: <span style={{ color: "#666" }}>{(fb.originalScore * 100).toFixed(0)}%</span></span>
              {fb.note && <span style={{ fontStyle: "italic", color: "#333" }}>"{fb.note.slice(0, 40)}{fb.note.length > 40 ? "…" : ""}"</span>}
            </div>
          </div>
        );
      })}
      <div style={{ padding: "10px 16px" }}>
        <div style={{ fontSize: 9, color: "#2a2a2a", fontFamily: "monospace" }}>
          In production: each record POSTs to /api/feedback → soc.feedback Kafka topic → nightly retrain
        </div>
      </div>
    </div>
  );
}

function LiveTicker({ incidents }) {
  const [idx, setIdx] = useState(0);
  useEffect(() => { const t = setInterval(() => setIdx(i => (i + 1) % incidents.length), 3000); return () => clearInterval(t); }, [incidents.length]);
  const inc = incidents[idx]; const lc = labelBg(inc.ml_label);
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, background: "rgba(255,255,255,0.02)", borderRadius: 6, padding: "5px 14px", border: "1px solid rgba(255,255,255,0.05)", fontSize: 11, fontFamily: "monospace" }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#ff3b5c", flexShrink: 0, animation: "pulse 1.5s ease-in-out infinite" }} />
      <span style={{ color: "#444" }}>LIVE</span>
      <span style={{ color: lc.text, fontWeight: 700 }}>{inc.ml_label.toUpperCase()}</span>
      <span style={{ color: "#777" }}>{inc.src_ip}</span>
      <span style={{ color: "#333" }}>→</span>
      <span style={{ color: "#555" }}>{inc.rule}</span>
      <span style={{ color: "#333" }}>→</span>
      <span style={{ color: inc.resolved ? "#30d158" : "#ff9f0a" }}>{inc.resolved ? "AUTO-RESOLVED" : "PENDING"}</span>
    </div>
  );
}

export default function SOCDashboard() {
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState("all");
  const [incidents, setIncidents] = useState([]);
  const [feedback, setFeedback] = useState({});
  const [feedbackLog, setFeedbackLog] = useState([]);
  const [showLog, setShowLog] = useState(false);
  const [clock, setClock] = useState(new Date().toLocaleTimeString());
  // apiStatus: "loading" | "empty" | "live" | "error"
  // - "loading": initial fetch in progress
  // - "empty":   API returned [] — pipeline has no data yet (show spinner, NOT mock data)
  // - "live":    real incident data loaded
  // - "error":   API unreachable (network error / non-200) — fall back to MOCK_INCIDENTS
  const [apiStatus, setApiStatus] = useState("loading");

  useEffect(() => { const t = setInterval(() => setClock(new Date().toLocaleTimeString()), 1000); return () => clearInterval(t); }, []);

  // Fetch initial incidents
  useEffect(() => {
    fetch("/api/incidents")
      .then(res => {
        if (!res.ok) throw new Error("HTTP error " + res.status);
        return res.json();
      })
      .then(data => {
        if (data && data.length > 0) {
          setIncidents(data);
          setSelected(prev => prev || data[0]);
          setApiStatus("live");
        } else {
          // Pipeline is running but has no data yet — do NOT use mock data
          setIncidents([]);
          setApiStatus("empty");
        }
      })
      .catch(err => {
        // API is unreachable — fall back to MOCK_INCIDENTS so the UI is not blank
        console.error("Failed to fetch incidents (using mock data):", err);
        setIncidents(MOCK_INCIDENTS);
        setSelected(prev => prev || MOCK_INCIDENTS[0]);
        setApiStatus("error");
      });
  }, []);

  // SSE: connect to /stream and add new incidents from soc.frontend topic
  useEffect(() => {
    const es = new EventSource("/stream");
    es.onmessage = (e) => {
      try {
        const inc = JSON.parse(e.data);
        setIncidents(prev => {
          if (prev.find(i => i.id === inc.id)) return prev;
          const nextList = [inc, ...prev];
          setSelected(curr => curr || inc);
          return nextList;
        });
        // First real SSE event means pipeline is live
        setApiStatus("live");
      } catch { }
    };
    es.onerror = () => { };
    return () => es.close();
  }, []);

  const handleFeedback = useCallback((incId, record) => {
    setFeedback(prev => ({ ...prev, [incId]: record }));
    setFeedbackLog(prev => [...prev, record]);
    fetch("/api/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(record),
    }).catch(() => { });
  }, []);

  const reviewedCount = Object.keys(feedback).length;
  const filtered = filter === "all" ? incidents
    : filter === "reviewed" ? incidents.filter(i => feedback[i.id])
      : filter === "pending" ? incidents.filter(i => !feedback[i.id])
        : incidents.filter(i => i.ml_label === filter);

  return (
    <div style={{ minHeight: "100vh", background: "#080a0f", fontFamily: "system-ui, sans-serif", color: "#e0e0e0" }}>
      <style>{`
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
        @keyframes slideIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
        @keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
        *{box-sizing:border-box;margin:0;padding:0;}
        textarea{background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.07);border-radius:5px;padding:7px 10px;color:#999;font-family:monospace;font-size:11px;resize:none;outline:none;width:100%;}
        textarea::placeholder{color:#252525;}
        ::-webkit-scrollbar{width:3px;}::-webkit-scrollbar-track{background:transparent;}
        ::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.08);border-radius:2px;}
      `}</style>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "11px 24px", borderBottom: "1px solid rgba(255,255,255,0.06)", background: "rgba(0,0,0,0.5)", position: "sticky", top: 0, zIndex: 10 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#30d158", animation: "pulse 2s infinite" }} />
            <span style={{ fontFamily: "monospace", fontSize: 13, fontWeight: 700, letterSpacing: "0.15em", color: "#e8e8e8" }}>SOC·AI</span>
          </div>
          <span style={{ color: "#1a1a1a", fontSize: 14 }}>|</span>
          <span style={{ fontFamily: "monospace", fontSize: 11, color: "#333" }}>SECURITY OPERATIONS CENTER</span>
          {apiStatus === "error" && <span style={{ fontFamily: "monospace", fontSize: 9, color: "#ff9f0a", background: "rgba(255,159,10,0.1)", border: "1px solid rgba(255,159,10,0.3)", borderRadius: 3, padding: "2px 7px", letterSpacing: "0.06em" }}>DEMO</span>}
        </div>
        {incidents.length > 0 ? <LiveTicker incidents={incidents} /> : <span style={{ fontFamily: "monospace", fontSize: 11, color: "#333" }}>NO LIVE DATA</span>}
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <button onClick={() => setShowLog(v => !v)} style={{ position: "relative", padding: "5px 12px", borderRadius: 6, cursor: "pointer", border: showLog ? "1px solid rgba(0,200,255,0.35)" : "1px solid rgba(255,255,255,0.08)", background: showLog ? "rgba(0,200,255,0.08)" : "transparent", color: showLog ? "#00c8ff" : "#555", fontFamily: "monospace", fontSize: 9, letterSpacing: "0.07em" }}>
            FEEDBACK LOG
            {reviewedCount > 0 && <span style={{ position: "absolute", top: -5, right: -5, width: 16, height: 16, borderRadius: "50%", background: "#00c8ff", color: "#000", fontSize: 8, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center" }}>{reviewedCount}</span>}
          </button>
          <span style={{ fontFamily: "monospace", fontSize: 11, color: "#2a2a2a" }}>{clock}</span>
        </div>
      </div>
      <div style={{ padding: "18px 24px", maxWidth: 1400, margin: "0 auto" }}>
        {showLog && (
          <div style={{ marginBottom: 14, background: "rgba(255,255,255,0.015)", border: "1px solid rgba(0,200,255,0.15)", borderRadius: 10, overflow: "hidden", animation: "slideIn 0.18s ease" }}>
            <div style={{ padding: "9px 16px", borderBottom: "1px solid rgba(255,255,255,0.05)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <span style={{ fontFamily: "monospace", fontSize: 10, color: "#00c8ff", letterSpacing: "0.1em" }}>FEEDBACK LOG — {reviewedCount} submitted · {incidents.length - reviewedCount} pending</span>
              <button onClick={() => setShowLog(false)} style={{ background: "transparent", border: "none", color: "#333", cursor: "pointer", fontFamily: "monospace", fontSize: 11 }}>✕</button>
            </div>
            <FeedbackLog log={feedbackLog} />
          </div>
        )}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(6,1fr)", gap: 9, marginBottom: 14 }}>
          <StatCard label="Alerts 24h" value={THREAT_STATS.total_24h} spark={[12, 18, 24, 15, 31, 22, 28, 35, 19, 42, 38, 247]} sparkColor="#00c8ff" />
          <StatCard label="Malicious" value={THREAT_STATS.malicious} sub="confirmed" spark={[2, 3, 1, 4, 2, 5, 3, 4, 6, 3, 5, 31]} sparkColor="#ff3b5c" />
          <StatCard label="Suspicious" value={THREAT_STATS.suspicious} sub="under review" spark={[8, 12, 7, 15, 11, 9, 14, 10, 13, 16, 12, 89]} sparkColor="#ff9f0a" />
          <StatCard label="IPs Blocked" value={THREAT_STATS.blocked_ips} sub="auto-blocked" spark={[1, 2, 1, 3, 2, 4, 3, 3, 4, 2, 3, 28]} sparkColor="#ff3b5c" />
          <StatCard label="Auto-Resolved" value={`${THREAT_STATS.auto_resolved}%`} sub="no human needed" spark={[88, 90, 91, 93, 92, 95, 93, 94, 95, 94, 96, 94]} sparkColor="#30d158" />
          <StatCard label="Reviewed" value={`${reviewedCount}/${incidents.length}`} sub="analyst feedback" spark={[0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, reviewedCount]} sparkColor="#00c8ff" />
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 400px", gap: 10, height: "calc(100vh - 260px)", minHeight: 460 }}>
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 10, overflow: "hidden", display: "flex", flexDirection: "column" }}>
            <div style={{ padding: "9px 14px", borderBottom: "1px solid rgba(255,255,255,0.06)", display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0 }}>
              <span style={{ fontFamily: "monospace", fontSize: 10, color: "#555", letterSpacing: "0.1em" }}>INCIDENTS</span>
              <div style={{ display: "flex", gap: 4 }}>
                {[{ k: "all", l: "ALL" }, { k: "malicious", l: "MALICIOUS" }, { k: "suspicious", l: "SUSPICIOUS" }, { k: "pending", l: `PENDING (${incidents.length - reviewedCount})` }, { k: "reviewed", l: `REVIEWED (${reviewedCount})` }].map(f => (
                  <button key={f.k} onClick={() => setFilter(f.k)} style={{ padding: "2px 8px", borderRadius: 3, fontSize: 8, fontFamily: "monospace", cursor: "pointer", border: "1px solid", background: filter === f.k ? "rgba(0,200,255,0.1)" : "transparent", borderColor: filter === f.k ? "rgba(0,200,255,0.3)" : "rgba(255,255,255,0.06)", color: filter === f.k ? "#00c8ff" : "#3a3a3a", letterSpacing: "0.04em" }}>{f.l}</button>
                ))}
              </div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "42px 1fr 80px 52px 108px", gap: "10px", padding: "5px 14px", background: "rgba(0,0,0,0.2)", flexShrink: 0 }}>
              {["SCORE", "SOURCE", "VERDICT", "ACTS", "STATUS"].map(h => <span key={h} style={{ fontSize: 8, color: "#2d2d2d", fontFamily: "monospace", letterSpacing: "0.08em" }}>{h}</span>)}
            </div>
            <div style={{ overflowY: "auto", flex: 1 }}>
              {(apiStatus === "loading" || apiStatus === "empty") && incidents.length === 0 ? (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 12, padding: 40 }}>
                  <div style={{ width: 28, height: 28, border: "2px solid rgba(0,200,255,0.15)", borderTop: "2px solid #00c8ff", borderRadius: "50%", animation: "spin 1s linear infinite" }} />
                  <span style={{ fontFamily: "monospace", fontSize: 11, color: "#444", letterSpacing: "0.06em" }}>
                    {apiStatus === "loading" ? "CONNECTING TO PIPELINE…" : "⏳ WAITING FOR PIPELINE DATA…"}
                  </span>
                  <span style={{ fontFamily: "monospace", fontSize: 9, color: "#2a2a2a", textAlign: "center", maxWidth: 260, lineHeight: 1.6 }}>
                    {apiStatus === "empty" ? "The API is reachable but no incidents have arrived yet. Run simulate_alerts.py to send test data." : "Fetching incidents from API…"}
                  </span>
                </div>
              ) : (
                <>
                  {filtered.map(inc => (
                    <IncidentRow key={inc.id} inc={inc} selected={selected?.id === inc.id}
                      fbVerdict={feedback[inc.id]?.verdict} onClick={() => setSelected(inc)} />
                  ))}
                  {filtered.length === 0 && <div style={{ padding: 36, textAlign: "center", color: "#222", fontSize: 11, fontFamily: "monospace" }}>No incidents match this filter</div>}
                </>
              )}
            </div>
          </div>
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 10, overflow: "hidden", display: "flex", flexDirection: "column" }}>
            <div style={{ padding: "9px 14px", borderBottom: "1px solid rgba(255,255,255,0.06)", display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0 }}>
              <span style={{ fontFamily: "monospace", fontSize: 10, color: "#555", letterSpacing: "0.1em" }}>INCIDENT DETAIL</span>
              {selected && (feedback[selected.id] ? <span style={{ fontFamily: "monospace", fontSize: 8, color: "#30d158", letterSpacing: "0.06em" }}>● REVIEWED</span> : <span style={{ fontFamily: "monospace", fontSize: 8, color: "#ff9f0a", letterSpacing: "0.06em", animation: "pulse 2s infinite" }}>● AWAITING REVIEW</span>)}
            </div>
            <div style={{ flex: 1, overflowY: "auto" }}>
              <DetailPanel inc={selected} feedback={feedback} onFeedback={handleFeedback} />
            </div>
          </div>
        </div>
        <div style={{ marginTop: 10, padding: "9px 14px", background: "rgba(255,255,255,0.01)", border: "1px solid rgba(255,255,255,0.04)", borderRadius: 7, display: "flex", gap: 20, flexWrap: "wrap", alignItems: "center" }}>
          <span style={{ fontFamily: "monospace", fontSize: 8, color: "#2a2a2a", letterSpacing: "0.1em" }}>FEEDBACK VERDICTS:</span>
          {[["✓ CONFIRM", "True positive — reinforces model"], ["✗ MARK FP", "Trains FP filter with correct label"], ["⬆ ESCALATE", "True positive, tier-2 required"]].map(([v, d]) => (
            <div key={v} style={{ display: "flex", gap: 5, alignItems: "center" }}>
              <span style={{ fontFamily: "monospace", fontSize: 8, color: "#555" }}>{v}</span>
              <span style={{ fontSize: 8, color: "#222" }}>→ {d}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
