import { useState, useRef, useEffect } from "react";

const MODES = [
  { id: "log", label: "Log Analysis", icon: "🔍", color: "#00FF9C", desc: "Paste logs for threat detection & IOC extraction" },
  { id: "cve", label: "CVE Research", icon: "🛡️", color: "#FF6B6B", desc: "Look up vulnerabilities, CVSS scores & mitigations" },
  { id: "report", label: "Report Writer", icon: "📝", color: "#4ECDC4", desc: "Draft pentest findings, SOC reports & narratives" },
  { id: "ctf", label: "CTF Assistant", icon: "🚩", color: "#FFE66D", desc: "Get hints, decode payloads & solve challenges" },
  { id: "vt", label: "VirusTotal", icon: "🦠", color: "#FF9F43", desc: "Scan IPs, domains, URLs & file hashes for threats" },
];

const SYSTEM_PROMPTS = {
  log: `You are an expert SOC Analyst and threat hunter. When given log data, you:
- Identify suspicious patterns, anomalies, and IOCs (IPs, hashes, domains)
- Map findings to MITRE ATT&CK tactics and techniques
- Assign severity levels (Critical/High/Medium/Low)
- Suggest immediate response actions
- Be concise, structured, and evidence-based. Use markdown formatting.`,
  cve: `You are a vulnerability research expert. When given a CVE ID, software name, or vulnerability description, you:
- Provide CVE details, CVSS score breakdown, and affected versions
- Explain the attack vector and exploitability in plain terms
- Give prioritized remediation steps
- Mention known exploit availability (public PoC, Metasploit, etc.)
- Use markdown formatting with clear sections.`,
  report: `You are a professional penetration testing report writer and SOC analyst. You help:
- Structure findings into executive summaries and technical narratives
- Write clear, evidence-based vulnerability descriptions
- Draft remediation recommendations in business-friendly language
- Format reports for client delivery
- Use markdown formatting. Maintain professional but direct tone.`,
  ctf: `You are an expert CTF mentor. You help players:
- Understand challenge categories (web, crypto, forensics, pwn, OSINT, etc.)
- Provide structured hints without giving away full solutions unless asked
- Explain underlying concepts and techniques
- Suggest tools and commands to try
- Decode/analyze provided payloads or artifacts
Use markdown. Be educational and encouraging.`,
  vt: `You are a threat intelligence analyst. You will be given VirusTotal scan results in JSON format. Your job is to:
- Summarize the threat verdict clearly (malicious / suspicious / clean)
- Highlight the most important detections and vendor flags
- Identify threat categories, malware families if present
- Extract key IOC context (geo, ASN, reputation tags)
- Give a clear recommended action (block / monitor / safe)
- Use markdown formatting with severity rating.`,
};

const VT_TYPES = [
  { id: "ip", label: "IP Address", placeholder: "e.g. 185.220.101.1", endpoint: (v) => `https://www.virustotal.com/api/v3/ip_addresses/${v}` },
  { id: "domain", label: "Domain", placeholder: "e.g. malware-site.ru", endpoint: (v) => `https://www.virustotal.com/api/v3/domains/${v}` },
  { id: "url", label: "URL", placeholder: "e.g. http://phishing.com/login", endpoint: null },
  { id: "hash", label: "File Hash", placeholder: "MD5 / SHA1 / SHA256", endpoint: (v) => `https://www.virustotal.com/api/v3/files/${v}` },
];

export default function App() {
  const [mode, setMode] = useState("log");
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [showKeyInput, setShowKeyInput] = useState(false);
  const [vtType, setVtType] = useState("ip");
  const [vtInput, setVtInput] = useState("");
  const [vtLoading, setVtLoading] = useState(false);
  const [vtResult, setVtResult] = useState(null);
  const [vtError, setVtError] = useState("");
  const bottomRef = useRef(null);

  const currentMode = MODES.find((m) => m.id === mode);

  useEffect(() => {
    setMessages([]);
    setInput("");
    setVtResult(null);
    setVtError("");
  }, [mode]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading, vtResult]);

  const sendMessage = async () => {
    if (!input.trim() || loading) return;
    const userMsg = { role: "user", content: input.trim() };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    setLoading(true);
    try {
      const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-6",
          max_tokens: 1000,
          system: SYSTEM_PROMPTS[mode],
          messages: newMessages,
        }),
      });
      const data = await response.json();
      const reply = data.content?.find((b) => b.type === "text")?.text || "No response.";
      setMessages([...newMessages, { role: "assistant", content: reply }]);
    } catch {
      setMessages([...newMessages, { role: "assistant", content: "⚠️ Error connecting to AI. Please try again." }]);
    } finally {
      setLoading(false);
    }
  };

  const scanVirusTotal = async () => {
    if (!apiKey.trim()) { setVtError("⚠️ Please enter your VirusTotal API key first."); return; }
    if (!vtInput.trim()) { setVtError("⚠️ Please enter a value to scan."); return; }
    setVtLoading(true);
    setVtResult(null);
    setVtError("");

    try {
      let vtData;
      const typeObj = VT_TYPES.find((t) => t.id === vtType);

      if (vtType === "url") {
        const formData = new URLSearchParams();
        formData.append("url", vtInput.trim());
        const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
          method: "POST",
          headers: { "x-apikey": apiKey, "Content-Type": "application/x-www-form-urlencoded" },
          body: formData,
        });
        const submitData = await submitRes.json();
        const analysisId = submitData?.data?.id;
        if (!analysisId) throw new Error("Failed to submit URL");
        await new Promise((r) => setTimeout(r, 3000));
        const analysisRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          headers: { "x-apikey": apiKey },
        });
        vtData = await analysisRes.json();
      } else {
        const url = typeObj.endpoint(vtInput.trim());
        const res = await fetch(url, { headers: { "x-apikey": apiKey } });
        if (res.status === 404) throw new Error("Not found in VirusTotal database.");
        if (res.status === 401) throw new Error("Invalid API key.");
        vtData = await res.json();
      }

      setVtResult(vtData);
      await analyzeWithAI(vtData);
    } catch (err) {
      setVtError(`⚠️ ${err.message || "Scan failed. Check your API key and input."}`);
    } finally {
      setVtLoading(false);
    }
  };

  const analyzeWithAI = async (vtData) => {
    const stats = vtData?.data?.attributes?.last_analysis_stats || vtData?.data?.attributes?.stats || {};
    const detections = vtData?.data?.attributes?.last_analysis_results || {};
    const topDetections = Object.entries(detections)
      .filter(([, v]) => v.category === "malicious" || v.category === "suspicious")
      .slice(0, 10)
      .map(([vendor, v]) => `${vendor}: ${v.result || v.category}`)
      .join("\n");

    const summary = `VirusTotal Scan Results:
Type: ${vtType.toUpperCase()}
Value: ${vtInput}
Stats: ${JSON.stringify(stats)}
Top detections:\n${topDetections || "None"}
Tags: ${(vtData?.data?.attributes?.tags || []).join(", ") || "N/A"}
Country: ${vtData?.data?.attributes?.country || "N/A"}
ASN: ${vtData?.data?.attributes?.asn || "N/A"}
Reputation: ${vtData?.data?.attributes?.reputation ?? "N/A"}`.trim();

    const userMsg = { role: "user", content: summary };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setLoading(true);
    try {
      const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-6",
          max_tokens: 1000,
          system: SYSTEM_PROMPTS.vt,
          messages: newMessages,
        }),
      });
      const data = await response.json();
      const reply = data.content?.find((b) => b.type === "text")?.text || "Could not analyze results.";
      setMessages([...newMessages, { role: "assistant", content: reply }]);
    } catch {
      setMessages([...newMessages, { role: "assistant", content: "⚠️ AI analysis failed." }]);
    } finally {
      setLoading(false);
    }
  };

  const getVtStats = () => vtResult?.data?.attributes?.last_analysis_stats || vtResult?.data?.attributes?.stats || null;

  const formatMessage = (text) => {
    return text
      .replace(/^### (.+)$/gm, '<h3 style="color:#00FF9C;font-size:0.95rem;margin:12px 0 4px;font-family:monospace">$1</h3>')
      .replace(/^## (.+)$/gm, '<h2 style="color:#4ECDC4;font-size:1rem;margin:14px 0 6px;font-family:monospace">$1</h2>')
      .replace(/\*\*(.+?)\*\*/g, '<strong style="color:#FFE66D">$1</strong>')
      .replace(/`([^`]+)`/g, '<code style="background:#1a1a2e;color:#00FF9C;padding:1px 5px;border-radius:3px;font-size:0.85em">$1</code>')
      .replace(/^- (.+)$/gm, '<div style="display:flex;gap:8px;margin:3px 0"><span style="color:#FF6B6B">▸</span><span>$1</span></div>')
      .replace(/\n/g, '<br/>');
  };

  const stats = getVtStats();

  return (
    <div style={{ background: "#0a0a0f", minHeight: "100vh", fontFamily: "'Courier New', monospace", color: "#e0e0e0", display: "flex", flexDirection: "column" }}>
      {/* Header */}
      <div style={{ padding: "14px 20px 10px", borderBottom: "1px solid #1e1e2e", background: "#0d0d1a" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: "1.2rem" }}>⚡</span>
            <span style={{ color: "#00FF9C", fontWeight: "bold", fontSize: "1.05rem", letterSpacing: 1 }}>
              CYBER<span style={{ color: "#FF6B6B" }}>AGENT</span>
            </span>
            <span style={{ color: "#333", fontSize: "0.7rem" }}>v2.0</span>
          </div>
          <button
            onClick={() => setShowKeyInput(!showKeyInput)}
            style={{
              padding: "4px 10px", borderRadius: 4,
              border: `1px solid ${apiKey ? "#00FF9C44" : "#FF6B6B44"}`,
              background: "transparent", color: apiKey ? "#00FF9C" : "#FF6B6B",
              cursor: "pointer", fontSize: "0.7rem", fontFamily: "monospace",
            }}
          >
            {apiKey ? "🔑 VT Key Set" : "🔑 Set VT Key"}
          </button>
        </div>

        {showKeyInput && (
          <div style={{ marginBottom: 10, display: "flex", gap: 8 }}>
            <input
              type="password"
              placeholder="Paste your VirusTotal API key..."
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              style={{
                flex: 1, background: "#111120", border: "1px solid #FF9F4344",
                borderRadius: 4, color: "#ddd", fontFamily: "monospace",
                fontSize: "0.78rem", padding: "6px 10px", outline: "none",
              }}
            />
            <button
              onClick={() => setShowKeyInput(false)}
              style={{
                padding: "6px 12px", background: "#FF9F43", color: "#000",
                border: "none", borderRadius: 4, cursor: "pointer",
                fontFamily: "monospace", fontSize: "0.78rem", fontWeight: "bold",
              }}
            >
              SAVE
            </button>
          </div>
        )}

        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {MODES.map((m) => (
            <button
              key={m.id}
              onClick={() => setMode(m.id)}
              style={{
                padding: "4px 10px", borderRadius: 4,
                border: `1px solid ${mode === m.id ? m.color : "#2a2a3e"}`,
                background: mode === m.id ? `${m.color}18` : "transparent",
                color: mode === m.id ? m.color : "#555",
                cursor: "pointer", fontSize: "0.74rem", fontFamily: "monospace",
              }}
            >
              {m.icon} {m.label}
            </button>
          ))}
        </div>
      </div>

      <div style={{ padding: "6px 20px", background: "#0d0d1a", borderBottom: "1px solid #1e1e2e", fontSize: "0.72rem", color: "#444" }}>
        <span style={{ color: currentMode.color }}>▸ </span>{currentMode.desc}
      </div>

      {mode === "vt" && (
        <div style={{ padding: "14px 20px", background: "#0d0d17", borderBottom: "1px solid #1e1e2e" }}>
          <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
            {VT_TYPES.map((t) => (
              <button
                key={t.id}
                onClick={() => { setVtType(t.id); setVtInput(""); setVtResult(null); setVtError(""); }}
                style={{
                  padding: "4px 10px", borderRadius: 4,
                  border: `1px solid ${vtType === t.id ? "#FF9F43" : "#2a2a3e"}`,
                  background: vtType === t.id ? "#FF9F4318" : "transparent",
                  color: vtType === t.id ? "#FF9F43" : "#555",
                  cursor: "pointer", fontSize: "0.72rem", fontFamily: "monospace",
                }}
              >
                {t.label}
              </button>
            ))}
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <input
              value={vtInput}
              onChange={(e) => setVtInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && scanVirusTotal()}
              placeholder={VT_TYPES.find((t) => t.id === vtType)?.placeholder}
              style={{
                flex: 1, background: "#111120", border: "1px solid #2a2a3e",
                borderRadius: 4, color: "#ddd", fontFamily: "monospace",
                fontSize: "0.8rem", padding: "8px 12px", outline: "none",
              }}
            />
            <button
              onClick={scanVirusTotal}
              disabled={vtLoading}
              style={{
                padding: "8px 16px", background: vtLoading ? "#1a1a2e" : "#FF9F43",
                color: vtLoading ? "#444" : "#000", border: "none", borderRadius: 4,
                cursor: vtLoading ? "not-allowed" : "pointer",
                fontFamily: "monospace", fontWeight: "bold", fontSize: "0.8rem",
              }}
            >
              {vtLoading ? "SCANNING..." : "SCAN ▶"}
            </button>
          </div>
          {vtError && <div style={{ marginTop: 8, color: "#FF6B6B", fontSize: "0.75rem" }}>{vtError}</div>}
          {stats && (
            <div style={{ marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
              {[
                { label: "Malicious", key: "malicious", color: "#FF6B6B" },
                { label: "Suspicious", key: "suspicious", color: "#FF9F43" },
                { label: "Clean", key: "undetected", color: "#00FF9C" },
                { label: "Harmless", key: "harmless", color: "#4ECDC4" },
              ].map((s) => (
                <div key={s.key} style={{
                  padding: "4px 10px", borderRadius: 4,
                  border: `1px solid ${s.color}44`, background: `${s.color}11`,
                  fontSize: "0.72rem", color: s.color,
                }}>
                  {s.label}: <strong>{stats[s.key] ?? 0}</strong>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div style={{
        flex: 1, overflowY: "auto", padding: "14px 20px",
        display: "flex", flexDirection: "column", gap: 10,
        minHeight: 200, maxHeight: mode === "vt" ? "40vh" : "60vh",
      }}>
        {messages.length === 0 && (
          <div style={{ textAlign: "center", color: "#333", marginTop: 40, fontSize: "0.82rem" }}>
            <div style={{ fontSize: "2rem", marginBottom: 8 }}>{currentMode.icon}</div>
            <div style={{ color: "#3a3a5a" }}>
              {mode === "log" && "Paste auth logs, syslog or SIEM alerts below"}
              {mode === "cve" && 'Try: "CVE-2021-44228" or "Log4Shell details"'}
              {mode === "report" && 'Try: "Write a finding for RCE via file upload"'}
              {mode === "ctf" && 'Describe your CTF challenge to get started'}
              {mode === "vt" && !apiKey && "🔑 Set your VirusTotal API key above to start scanning"}
              {mode === "vt" && apiKey && "Enter an IP, domain, URL or hash above and click SCAN"}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} style={{ display: "flex", justifyContent: msg.role === "user" ? "flex-end" : "flex-start" }}>
            <div style={{
              maxWidth: "87%", padding: "9px 13px", borderRadius: 6,
              fontSize: "0.8rem", lineHeight: 1.6,
              ...(msg.role === "user"
                ? { background: "#1a1a2e", border: `1px solid ${currentMode.color}33`, color: "#ccc", borderBottomRightRadius: 2 }
                : { background: "#111120", border: "1px solid #2a2a3e", color: "#bbb", borderBottomLeftRadius: 2 }),
            }}>
              {msg.role === "assistant"
                ? <div dangerouslySetInnerHTML={{ __html: formatMessage(msg.content) }} />
                : <span style={{ whiteSpace: "pre-wrap" }}>{msg.content}</span>}
            </div>
          </div>
        ))}

        {loading && (
          <div style={{ display: "flex", gap: 4, padding: "6px 0" }}>
            {[0, 1, 2].map((i) => (
              <div key={i} style={{
                width: 5, height: 5, borderRadius: "50%", background: currentMode.color,
                animation: `pulse 1.2s ease-in-out ${i * 0.2}s infinite`,
              }} />
            ))}
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {mode !== "vt" && (
        <div style={{ padding: "10px 20px 14px", borderTop: "1px solid #1e1e2e", background: "#0d0d1a" }}>
          <div style={{ display: "flex", gap: 8 }}>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
              placeholder={
                mode === "log" ? "Paste logs or describe suspicious activity..."
                : mode === "cve" ? "Enter CVE ID or describe a vulnerability..."
                : mode === "report" ? "Describe your finding or paste raw notes..."
                : "Describe your CTF challenge..."
              }
              rows={3}
              style={{
                flex: 1, background: "#111120", border: "1px solid #2a2a3e",
                borderRadius: 6, color: "#ddd", fontFamily: "monospace",
                fontSize: "0.8rem", padding: "8px 11px", resize: "none", outline: "none", lineHeight: 1.5,
              }}
            />
            <button
              onClick={sendMessage}
              disabled={loading || !input.trim()}
              style={{
                padding: "0 14px",
                background: loading || !input.trim() ? "#1a1a2e" : currentMode.color,
                color: loading || !input.trim() ? "#444" : "#000",
                border: "none", borderRadius: 6,
                cursor: loading || !input.trim() ? "not-allowed" : "pointer",
                fontFamily: "monospace", fontWeight: "bold", fontSize: "0.82rem", minWidth: 56,
              }}
            >
              {loading ? "..." : "RUN ▶"}
            </button>
          </div>
          <div style={{ fontSize: "0.65rem",
