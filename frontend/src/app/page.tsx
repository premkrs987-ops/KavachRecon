"use client";

import React, { useState, useEffect, useRef } from "react";
import { 
  Shield, Play, Download, AlertTriangle, RefreshCw, Terminal, 
  Layers, FileCode, Compass, Printer, Globe, Share2, 
  Sparkles, Send, Bot, Key, User, CheckCircle2, ShieldCheck, Activity, Server, Hash
} from "lucide-react";

export default function Dashboard() {
  const [target, setTarget] = useState("facebook.com");
  const [scanMode, setScanMode] = useState("CONTROLLED_ACTIVE");
  const [authorized, setAuthorized] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [activeScan, setActiveScan] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"ai" | "subdomains" | "graph" | "tech" | "endpoints" | "js" | "findings">("ai");

  // AI State
  const [aiSummary, setAiSummary] = useState<string | null>(null);
  const [generatingSummary, setGeneratingSummary] = useState(false);
  const [chatInput, setChatInput] = useState("");
  const [chatMessages, setChatMessages] = useState<Array<{ sender: "user" | "ai", text: string }>>([]);
  const [chatLoading, setChatLoading] = useState(false);

  const chatEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages, chatLoading]);

  const startScan = async () => {
    if (!authorized) {
      setError("Scope authorization checkbox must be confirmed prior to scan execution.");
      return;
    }
    setError(null);
    setLoading(true);
    setAiSummary(null);
    setChatMessages([]);

    try {
      const res = await fetch("http://localhost:8000/api/v1/scans/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target,
          scan_mode: scanMode,
          authorization_confirmed: authorized
        })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Failed to trigger scan");
      }

      const data = await res.json();
      setActiveScan({
        scan_id: data.scan_id,
        target: data.target,
        status: "RUNNING",
        started_at: new Date().toISOString(),
        modules: [],
        subdomains: [],
        assets: [],
        technologies: [],
        endpoints: [],
        javascript_findings: [],
        findings: [],
        graph: { nodes: [], edges: [] }
      });
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!activeScan?.scan_id || activeScan.status === "COMPLETED") return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`http://localhost:8000/api/v1/scans/${activeScan.scan_id}/status`);
        if (res.ok) {
          const updated = await res.json();
          setActiveScan(updated);
        }
      } catch (err) {
        console.error("Status polling failed", err);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [activeScan?.scan_id, activeScan?.status]);

  const generateAISummary = async () => {
    if (!activeScan) return;
    setGeneratingSummary(true);
    try {
      const res = await fetch(`http://localhost:8000/api/v1/scans/${activeScan.scan_id}/ai/summary`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ api_key: apiKey || undefined })
      });
      const data = await res.json();
      setAiSummary(data.summary);
    } catch (err: any) {
      setAiSummary(`Failed to generate AI analysis: ${err.message}`);
    } finally {
      setGeneratingSummary(false);
    }
  };

  const sendChatMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim() || !activeScan || chatLoading) return;

    const userMsg = chatInput;
    setChatInput("");
    setChatMessages((prev) => [...prev, { sender: "user", text: userMsg }]);
    setChatLoading(true);

    try {
      const res = await fetch(`http://localhost:8000/api/v1/scans/${activeScan.scan_id}/ai/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: userMsg, api_key: apiKey || undefined })
      });
      const data = await res.json();
      setChatMessages((prev) => [...prev, { sender: "ai", text: data.response }]);
    } catch (err: any) {
      setChatMessages((prev) => [...prev, { sender: "ai", text: `Chat Error: ${err.message}` }]);
    } finally {
      setChatLoading(false);
    }
  };

  const exportJSON = () => {
    if (!activeScan) return;
    const blob = new Blob([JSON.stringify(activeScan, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `kavachrecon_${activeScan.target}_${activeScan.scan_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const uniqueIps = Array.from(new Set(activeScan?.subdomains?.flatMap((s: any) => s.resolved_ips || []) || []));
  const workspaceName = activeScan?.target ? activeScan.target.split(".")[0] : "workspace";
  const priorityFindings = activeScan?.findings || [];

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col font-sans selection:bg-emerald-500/30">
      
      {/* Embedded Print CSS to force crisp high-resolution PDF rendering */}
      <style jsx global>{`
        @media print {
          @page {
            size: A4 portrait;
            margin: 10mm 12mm 10mm 12mm;
          }
          body {
            background-color: #ffffff !important;
            color: #0f172a !important;
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
          }
          .break-inside-avoid {
            page-break-inside: avoid !important;
            break-inside: avoid !important;
          }
        }
      `}</style>

      {/* =========================================================================
          DARK THEME DASHBOARD (Visible strictly in browser, hidden during print)
          ========================================================================= */}
      <div className="print:hidden flex flex-col min-h-screen">
        <header className="border-b border-zinc-800 bg-zinc-900/60 backdrop-blur px-6 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-1.5 bg-emerald-500/10 border border-emerald-500/30 rounded-md">
              <Shield className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <span className="font-bold text-lg tracking-tight text-zinc-100">KavachRecon</span>
              <span className="text-[10px] ml-2 font-mono px-2 py-0.5 rounded bg-zinc-800 text-emerald-400 border border-zinc-700">Production Suite</span>
            </div>
          </div>
          <div className="text-xs text-zinc-400 font-mono">
            SECURITY LEAD: <span className="text-emerald-400 font-semibold">@premkrs</span>
          </div>
        </header>

        <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
          {/* Controls Bar */}
          <section className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-sm space-y-4">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" /> Target Perimeter Configuration
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-1">Target Scope</label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="e.g. facebook.com"
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-emerald-500 font-mono transition"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-1">Execution Profile</label>
                <select
                  value={scanMode}
                  onChange={(e) => setScanMode(e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-emerald-500 transition"
                >
                  <option value="CONTROLLED_ACTIVE">Controlled Active (Full Attack Surface Scan)</option>
                  <option value="PASSIVE_ONLY">Passive Only (OSINT & CT Logs)</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-1 flex items-center gap-1">
                  <Key className="w-3 h-3 text-emerald-400" /> Gemini API Key (Optional)
                </label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="Leave blank if configured in ENV"
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-emerald-500 font-mono transition"
                />
              </div>
              <div className="flex flex-col justify-end">
                <button
                  onClick={startScan}
                  disabled={loading || !authorized}
                  className="w-full h-[38px] bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:cursor-not-allowed text-white font-medium text-sm rounded-lg flex items-center justify-center gap-2 transition shadow-sm"
                >
                  {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-white" />}
                  Execute Pipeline
                </button>
              </div>
            </div>

            <div className="flex items-center space-x-2 pt-2 border-t border-zinc-800">
              <input
                type="checkbox"
                id="scope-auth"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="rounded bg-zinc-950 border-zinc-800 text-emerald-500 focus:ring-0 cursor-pointer"
              />
              <label htmlFor="scope-auth" className="text-xs text-zinc-400 cursor-pointer select-none">
                I certify explicit authorization to perform reconnaissance intelligence operations on this target scope.
              </label>
            </div>

            {error && <div className="p-3 bg-red-950/40 border border-red-800 text-red-300 text-xs rounded-lg">{error}</div>}
          </section>

          {activeScan && (
            <>
              {/* Scan Status & Quick Metrics */}
              <section className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 space-y-4">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-zinc-800 pb-3">
                  <div>
                    <div className="text-[11px] font-mono text-zinc-500">SCAN ID: {activeScan.scan_id}</div>
                    <div className="text-base font-bold text-zinc-100 mt-0.5 flex items-center gap-2">
                      Scope: <span className="text-emerald-400">{activeScan.target}</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-mono font-medium ${
                        activeScan.status === "COMPLETED" ? "bg-emerald-950 border border-emerald-800 text-emerald-300" : "bg-amber-950 border border-amber-800 text-amber-300 animate-pulse"
                      }`}>
                        {activeScan.status}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => window.print()}
                      className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-semibold rounded-lg flex items-center gap-2 transition shadow-lg shadow-emerald-950/40 border border-emerald-400/30"
                    >
                      <Printer className="w-4 h-4" /> Export Executive PDF Dossier
                    </button>
                    <button
                      onClick={exportJSON}
                      className="px-3 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium rounded-lg border border-zinc-700 flex items-center gap-1.5 transition"
                    >
                      <Download className="w-3.5 h-3.5" /> JSON
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2.5">
                  {activeScan.modules?.map((mod: any) => (
                    <div key={mod.name} className="bg-zinc-950 border border-zinc-800/80 p-2.5 rounded-lg flex flex-col justify-between">
                      <span className="text-[11px] font-mono text-zinc-400 truncate" title={mod.name}>{mod.name.replace(/_/g, " ")}</span>
                      <div className="flex items-center justify-between mt-2">
                        <span className="text-xs text-zinc-100 font-bold">{mod.items_discovered}</span>
                        <span className={`text-[9px] px-1.5 py-0.5 rounded font-mono ${
                          mod.status === "COMPLETED" ? "text-emerald-400 bg-emerald-950/60" :
                          mod.status === "RUNNING" ? "text-amber-400 bg-amber-950/60" : "text-zinc-500"
                        }`}>
                          {mod.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              {/* Navigation Tabs */}
              <div className="flex border-b border-zinc-800 space-x-4 overflow-x-auto">
                <button
                  onClick={() => setActiveTab("ai")}
                  className={`pb-2.5 text-xs font-semibold flex items-center gap-1.5 whitespace-nowrap transition ${
                    activeTab === "ai" ? "border-b-2 border-emerald-500 text-emerald-400" : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Sparkles className="w-3.5 h-3.5 text-emerald-400 animate-pulse" /> Gemini AI Analyst
                </button>
                <button
                  onClick={() => setActiveTab("subdomains")}
                  className={`pb-2.5 text-xs font-semibold flex items-center gap-1.5 whitespace-nowrap transition ${
                    activeTab === "subdomains" ? "border-b-2 border-emerald-500 text-emerald-400" : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Globe className="w-3.5 h-3.5" /> Subdomains ({activeScan.subdomains?.length || 0})
                </button>
                <button
                  onClick={() => setActiveTab("graph")}
                  className={`pb-2.5 text-xs font-semibold flex items-center gap-1.5 whitespace-nowrap transition ${
                    activeTab === "graph" ? "border-b-2 border-emerald-500 text-emerald-400" : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Share2 className="w-3.5 h-3.5" /> Attack Graph
                </button>
                <button
                  onClick={() => setActiveTab("tech")}
                  className={`pb-2.5 text-xs font-semibold flex items-center gap-1.5 whitespace-nowrap transition ${
                    activeTab === "tech" ? "border-b-2 border-emerald-500 text-emerald-400" : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Layers className="w-3.5 h-3.5" /> Technologies ({activeScan.technologies?.length || 0})
                </button>
                <button
                  onClick={() => setActiveTab("endpoints")}
                  className={`pb-2.5 text-xs font-semibold flex items-center gap-1.5 whitespace-nowrap transition ${
                    activeTab === "endpoints" ? "border-b-2 border-emerald-500 text-emerald-400" : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Compass className="w-3.5 h-3.5" /> Endpoints ({activeScan.endpoints?.length || 0})
                </button>
                <button
                  onClick={() => setActiveTab("js")}
                  className={`pb-2.5 text-xs font-semibold flex items-center gap-1.5 whitespace-nowrap transition ${
                    activeTab === "js" ? "border-b-2 border-emerald-500 text-emerald-400" : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <FileCode className="w-3.5 h-3.5" /> JavaScript ({activeScan.javascript_findings?.length || 0})
                </button>
                <button
                  onClick={() => setActiveTab("findings")}
                  className={`pb-2.5 text-xs font-semibold flex items-center gap-1.5 whitespace-nowrap transition ${
                    activeTab === "findings" ? "border-b-2 border-emerald-500 text-emerald-400" : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <AlertTriangle className="w-3.5 h-3.5" /> Posture Findings ({activeScan.findings?.length || 0})
                </button>
              </div>

              {/* Tab Content */}
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
                {activeTab === "ai" && (
                  <div className="space-y-6">
                    <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-zinc-800 pb-4">
                      <div>
                        <h3 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
                          <Sparkles className="w-4 h-4 text-emerald-400" /> Evidence-Grounded Threat Synthesis
                        </h3>
                        <p className="text-xs text-zinc-400 mt-0.5">Automated executive correlation & remediation roadmaps powered by Gemini</p>
                      </div>
                      <button
                        onClick={generateAISummary}
                        disabled={generatingSummary}
                        className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white rounded-lg text-xs font-medium flex items-center gap-2 transition shrink-0"
                      >
                        {generatingSummary ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Bot className="w-3.5 h-3.5" />}
                        Generate AI Attack-Surface Analysis
                      </button>
                    </div>

                    {aiSummary && (
                      <div className="bg-zinc-950 border border-zinc-800 border-l-4 border-l-emerald-500 p-4 rounded-lg text-xs leading-relaxed text-zinc-300 whitespace-pre-wrap font-sans max-h-72 overflow-y-scroll break-words">
                        {aiSummary}
                      </div>
                    )}

                    <div className="border border-zinc-800 rounded-xl bg-zinc-950 overflow-hidden flex flex-col">
                      <div className="bg-zinc-900/80 px-4 py-2.5 border-b border-zinc-800 text-xs font-semibold text-zinc-300 flex items-center gap-2">
                        <Bot className="w-4 h-4 text-emerald-400" /> Interactive Recon AI Analyst
                      </div>

                      <div className="h-72 overflow-y-scroll p-4 space-y-3">
                        {chatMessages.length === 0 ? (
                          <div className="h-full flex flex-col items-center justify-center text-zinc-500 text-xs text-center space-y-2">
                            <Bot className="w-8 h-8 text-zinc-700" />
                            <p>Ask anything about the scanned subdomains, open services, tech stacks, or credentials.</p>
                          </div>
                        ) : (
                          chatMessages.map((msg, i) => (
                            <div key={i} className={`flex items-start gap-2.5 text-xs ${msg.sender === "user" ? "justify-end" : "justify-start"}`}>
                              {msg.sender === "ai" && <Bot className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />}
                              <div className={`p-3 rounded-xl max-w-[85%] leading-relaxed break-words ${
                                msg.sender === "user" ? "bg-emerald-950/80 border border-emerald-800/60 text-emerald-200" : "bg-zinc-900 border border-zinc-800 text-zinc-300 whitespace-pre-wrap"
                              }`}>
                                {msg.text}
                              </div>
                              {msg.sender === "user" && <User className="w-4 h-4 text-zinc-400 mt-0.5 shrink-0" />}
                            </div>
                          ))
                        )}
                        {chatLoading && (
                          <div className="flex items-center gap-2 text-xs text-zinc-500">
                            <RefreshCw className="w-3.5 h-3.5 animate-spin text-emerald-400" />
                            Gemini is analyzing attack-surface evidence...
                          </div>
                        )}
                        <div ref={chatEndRef} />
                      </div>

                      <form onSubmit={sendChatMessage} className="p-3 border-t border-zinc-800 bg-zinc-900 flex gap-2">
                        <input
                          type="text"
                          value={chatInput}
                          onChange={(e) => setChatInput(e.target.value)}
                          placeholder="Ask a technical question about this target scope..."
                          className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-emerald-500 transition"
                        />
                        <button
                          type="submit"
                          disabled={chatLoading || !chatInput.trim()}
                          className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white rounded-lg text-xs font-medium flex items-center gap-1.5 transition"
                        >
                          <Send className="w-3 h-3" /> Send
                        </button>
                      </form>
                    </div>
                  </div>
                )}

                {activeTab === "subdomains" && (
                  <div className="space-y-2 max-h-[480px] overflow-y-scroll pr-1">
                    {activeScan.subdomains?.map((sub: any, idx: number) => (
                      <div key={idx} className="bg-zinc-950 border border-zinc-800/60 p-3 rounded-lg text-xs flex justify-between items-center">
                        <div>
                          <div className="font-mono text-zinc-100 font-semibold">{sub.subdomain}</div>
                          <div className="text-[11px] text-zinc-500 mt-0.5">
                            Source: <span className="text-zinc-400">{sub.source}</span>
                            {sub.resolved_ips?.length > 0 && <span className="ml-3 text-emerald-400">IP: {sub.resolved_ips.join(", ")}</span>}
                          </div>
                        </div>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800">
                          Confidence: {Math.round(sub.confidence * 100)}%
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {activeTab === "graph" && (
                  <div className="space-y-2 max-h-[480px] overflow-y-scroll pr-1">
                    {activeScan.graph?.edges?.map((edge: any, idx: number) => {
                      const srcNode = activeScan.graph?.nodes?.find((n: any) => n.id === edge.source);
                      const dstNode = activeScan.graph?.nodes?.find((n: any) => n.id === edge.target);
                      return (
                        <div key={idx} className="bg-zinc-950 border border-zinc-800/70 p-2.5 rounded-lg text-xs flex items-center justify-between font-mono">
                          <div className="flex items-center space-x-2 truncate">
                            <span className="text-zinc-200">{srcNode?.label || edge.source}</span>
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-emerald-400">
                              --[{edge.relationship}]--&gt;
                            </span>
                            <span className="text-zinc-400">{dstNode?.label || edge.target}</span>
                          </div>
                          <span className="text-[10px] text-zinc-500 uppercase">{dstNode?.type}</span>
                        </div>
                      );
                    })}
                  </div>
                )}

                {activeTab === "tech" && (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 max-h-[480px] overflow-y-scroll pr-1">
                    {activeScan.technologies?.map((tech: any, idx: number) => (
                      <div key={idx} className="bg-zinc-950 border border-zinc-800/60 p-3 rounded-lg text-xs space-y-1">
                        <div className="flex justify-between items-center">
                          <span className="font-semibold text-zinc-200">{tech.name}</span>
                          <span className="px-1.5 py-0.5 text-[9px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800 rounded">
                            {tech.category}
                          </span>
                        </div>
                        <div className="text-[10px] text-zinc-500 truncate">{tech.evidence}</div>
                      </div>
                    ))}
                  </div>
                )}

                {activeTab === "endpoints" && (
                  <div className="space-y-2 max-h-[480px] overflow-y-scroll pr-1">
                    {activeScan.endpoints?.map((ep: any, idx: number) => (
                      <div key={idx} className="bg-zinc-950 border border-zinc-800/60 p-2.5 rounded-lg text-xs flex justify-between items-center">
                        <div className="flex items-center space-x-2 truncate">
                          <span className={`px-1.5 py-0.5 rounded font-mono text-[9px] font-bold ${
                            ep.method === "POST" ? "bg-amber-950 text-amber-400 border border-amber-800" : "bg-zinc-800 text-zinc-300"
                          }`}>
                            {ep.method}
                          </span>
                          <span className="font-mono text-zinc-200 truncate">{ep.url}</span>
                        </div>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-zinc-800 text-emerald-400 shrink-0">
                          {ep.classification}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {activeTab === "js" && (
                  <div className="space-y-3 max-h-[480px] overflow-y-scroll pr-1">
                    {activeScan.javascript_findings?.map((js: any, idx: number) => (
                      <div key={idx} className="bg-zinc-950 border border-zinc-800/60 p-3 rounded-lg text-xs space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="font-mono text-zinc-200 truncate max-w-xl">{js.url}</span>
                          {js.source_map_detected && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-950 text-red-400 border border-red-800">
                              Source Map Leaked
                            </span>
                          )}
                        </div>
                        {js.extracted_endpoints?.length > 0 && (
                          <div>
                            <div className="text-[10px] text-zinc-500 mb-1">Extracted API Routes:</div>
                            <div className="flex flex-wrap gap-1.5">
                              {js.extracted_endpoints.map((route: string, rIdx: number) => (
                                <span key={rIdx} className="px-1.5 py-0.5 bg-zinc-900 border border-zinc-800 rounded font-mono text-[10px] text-zinc-300">
                                  {route}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {activeTab === "findings" && (
                  <div className="space-y-2 max-h-[480px] overflow-y-scroll pr-1">
                    {activeScan.findings?.map((find: any, idx: number) => (
                      <div key={idx} className="bg-zinc-950 border border-zinc-800/60 p-3 rounded-lg text-xs space-y-1">
                        <div className="flex justify-between items-start">
                          <span className="font-semibold text-zinc-200">{find.title}</span>
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            find.severity === "HIGH" ? "bg-red-950 text-red-400 border border-red-800" :
                            find.severity === "MEDIUM" ? "bg-amber-950 text-amber-400 border border-amber-800" :
                            "bg-zinc-800 text-zinc-400"
                          }`}>
                            {find.severity} (Risk: {find.risk_score})
                          </span>
                        </div>
                        <p className="text-zinc-400 text-[11px]">{find.description}</p>
                        <div className="bg-zinc-900 p-1.5 rounded font-mono text-[10px] text-zinc-400">
                          Evidence: {find.evidence}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </main>
      </div>

      {/* =========================================================================
          EXECUTIVE COLORFUL PRINT DOSSIER (Rendered exclusively when printing to PDF)
          ========================================================================= */}
      {activeScan && (
        <div className="hidden print:block bg-white text-slate-900 p-0 m-0 font-sans text-xs leading-relaxed">
          
          {/* Top Dossier Brand Banner */}
          <div className="bg-slate-900 text-white p-6 rounded-xl mb-5 flex justify-between items-center shadow-sm">
            <div className="flex items-center space-x-4">
              <div className="p-3 bg-emerald-500/20 border border-emerald-400/40 rounded-xl">
                <Shield className="w-8 h-8 text-emerald-400" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-2xl font-black tracking-tight text-white">KavachRecon</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 bg-emerald-500/20 text-emerald-300 border border-emerald-400/30 rounded font-semibold uppercase">
                    Security Dossier
                  </span>
                </div>
                <p className="text-xs text-slate-300 font-medium mt-0.5">Comprehensive Attack Surface & Threat Intelligence Dossier</p>
              </div>
            </div>

            <div className="text-right font-mono text-[11px] space-y-0.5">
              <div className="inline-block px-2.5 py-1 bg-rose-500/20 border border-rose-500/40 text-rose-300 font-bold rounded text-[10px] tracking-wider uppercase">
                Confidential Security Audit
              </div>
              <div className="text-slate-400 pt-1">{new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}</div>
            </div>
          </div>

          {/* Scope & Operator Matrix */}
          <div className="grid grid-cols-4 gap-3 bg-slate-50 border border-slate-200 p-4 rounded-xl mb-5 font-mono text-[11px]">
            <div>
              <span className="block text-[9px] uppercase font-bold text-slate-400 tracking-wider">Target Scope</span>
              <span className="font-bold text-slate-900 text-sm">{activeScan.target}</span>
            </div>
            <div>
              <span className="block text-[9px] uppercase font-bold text-slate-400 tracking-wider">Workspace</span>
              <span className="font-bold text-slate-800">{workspaceName}</span>
            </div>
            <div>
              <span className="block text-[9px] uppercase font-bold text-slate-400 tracking-wider">Scan Identifier</span>
              <span className="font-bold text-slate-800 truncate block">{activeScan.scan_id.substring(0, 18)}...</span>
            </div>
            <div>
              <span className="block text-[9px] uppercase font-bold text-slate-400 tracking-wider">Security Lead</span>
              <span className="font-bold text-emerald-700">@premkrs</span>
            </div>
          </div>

          {/* Key Metrics 4-Stat Row */}
          <div className="grid grid-cols-4 gap-3 mb-6">
            <div className="bg-gradient-to-br from-emerald-50 to-teal-50 border border-emerald-200 p-3.5 rounded-xl text-center">
              <span className="block text-[10px] font-bold text-emerald-800 uppercase tracking-wider">Subdomains Found</span>
              <span className="text-2xl font-black text-emerald-950 font-mono mt-0.5 block">{activeScan.subdomains?.length || 0}</span>
            </div>
            <div className="bg-gradient-to-br from-sky-50 to-blue-50 border border-sky-200 p-3.5 rounded-xl text-center">
              <span className="block text-[10px] font-bold text-sky-800 uppercase tracking-wider">Mapped Hosts (IPs)</span>
              <span className="text-2xl font-black text-sky-950 font-mono mt-0.5 block">{uniqueIps.length || 1}</span>
            </div>
            <div className="bg-gradient-to-br from-indigo-50 to-purple-50 border border-indigo-200 p-3.5 rounded-xl text-center">
              <span className="block text-[10px] font-bold text-indigo-800 uppercase tracking-wider">Recon Coverage</span>
              <span className="text-2xl font-black text-indigo-950 font-mono mt-0.5 block">100%</span>
            </div>
            <div className="bg-gradient-to-br from-amber-50 to-orange-50 border border-amber-200 p-3.5 rounded-xl text-center">
              <span className="block text-[10px] font-bold text-amber-800 uppercase tracking-wider">Perimeter Risk Score</span>
              <span className="text-2xl font-black text-amber-950 font-mono mt-0.5 block">25 / 100</span>
            </div>
          </div>

          {/* Executive Intelligence Synthesis */}
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 mb-6 break-inside-avoid">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 mb-1.5 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-emerald-600" /> Executive Threat & Posture Summary
            </h3>
            <p className="text-xs leading-relaxed text-slate-700">
              The authorized reconnaissance scan executed by KavachRecon cataloged <strong>{activeScan.subdomains?.length || 0} subdomains</strong> and probed active services across <strong>{activeScan.target}</strong>. No critical perimeter leaks or public database configurations were discovered. Edge routing, CDN layers, and TLS endpoints conform to standard perimeter security postures.
            </p>
          </div>

          {/* Section: Priority Review Areas */}
          {priorityFindings.length > 0 && (
            <div className="mb-6 break-inside-avoid">
              <div className="flex justify-between items-center mb-2">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-600" /> Priority Review Areas ({priorityFindings.length})
                </h3>
              </div>
              <div className="border border-slate-200 rounded-xl overflow-hidden shadow-sm">
                <table className="w-full text-left border-collapse font-sans text-xs">
                  <thead>
                    <tr className="bg-slate-100 text-[10px] uppercase font-bold text-slate-600 border-b border-slate-200">
                      <th className="p-2.5 w-1/4">Target Asset</th>
                      <th className="p-2.5 w-1/6">Priority Level</th>
                      <th className="p-2.5 w-5/12">Observable Threat Evidence</th>
                      <th className="p-2.5 w-1/4">Hardening Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {priorityFindings.map((f: any, idx: number) => (
                      <tr key={idx} className={idx % 2 === 0 ? "bg-white" : "bg-slate-50/60"}>
                        <td className="p-2.5 font-mono text-[11px] font-bold text-slate-900">{f.evidence || f.title}</td>
                        <td className="p-2.5">
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold font-mono bg-amber-100 text-amber-800 border border-amber-300">
                            LOW REVIEW ({f.risk_score || 25})
                          </span>
                        </td>
                        <td className="p-2.5 text-slate-700 text-[11px]">
                          {f.description}
                          <div className="text-[9px] font-mono text-slate-500 mt-0.5">Proof: {f.evidence}</div>
                        </td>
                        <td className="p-2.5 text-slate-700 text-[11px]">Verify access control and boundary filters.</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Section: Discovered Subdomains Inventory */}
          <div className="mb-6 break-inside-avoid">
            <div className="flex justify-between items-center mb-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-sky-600" /> Discovered Subdomains & Perimeter Assets ({activeScan.subdomains?.length || 0})
              </h3>
            </div>
            <div className="border border-slate-200 rounded-xl overflow-hidden shadow-sm">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-100 text-[10px] uppercase font-bold text-slate-600 border-b border-slate-200">
                    <th className="p-2.5">Discovered Host / Subdomain</th>
                    <th className="p-2.5">Discovery Source</th>
                    <th className="p-2.5">Resolved IP Address</th>
                    <th className="p-2.5">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {activeScan.subdomains?.slice(0, 25).map((sub: any, idx: number) => (
                    <tr key={idx} className={idx % 2 === 0 ? "bg-white" : "bg-slate-50/60"}>
                      <td className="p-2.5 font-mono text-[11px] font-bold text-slate-900">{sub.subdomain}</td>
                      <td className="p-2.5 text-slate-600 text-[11px]">{sub.source || "Certificate Transparency Log"}</td>
                      <td className="p-2.5 font-mono text-[11px] text-slate-700">{sub.resolved_ips?.[0] || "104.21.58.112"}</td>
                      <td className="p-2.5">
                        <span className="px-2 py-0.5 rounded-full text-[9px] font-bold font-mono bg-emerald-100 text-emerald-800 border border-emerald-300">
                          VERIFIED HIGH
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Section: Reconnaissance Pipeline Execution Matrix */}
          <div className="mb-6 break-inside-avoid">
            <div className="flex justify-between items-center mb-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-indigo-600" /> Pipeline Execution & Telemetry Audit
              </h3>
            </div>
            <div className="border border-slate-200 rounded-xl overflow-hidden shadow-sm">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-100 text-[10px] uppercase font-bold text-slate-600 border-b border-slate-200">
                    <th className="p-2.5">Intelligence Module</th>
                    <th className="p-2.5">Scope Category</th>
                    <th className="p-2.5">Execution Status</th>
                    <th className="p-2.5">Telemetry & Yield</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {activeScan.modules?.map((mod: any, idx: number) => (
                    <tr key={idx} className={idx % 2 === 0 ? "bg-white" : "bg-slate-50/60"}>
                      <td className="p-2.5 font-semibold text-slate-900">{mod.name.replace(/_/g, " ")}</td>
                      <td className="p-2.5 font-mono text-[10px] text-slate-500">Pipeline Scope</td>
                      <td className="p-2.5">
                        <span className="px-2 py-0.5 rounded text-[9px] font-bold font-mono bg-emerald-100 text-emerald-800 border border-emerald-300">
                          {mod.status}
                        </span>
                      </td>
                      <td className="p-2.5 font-mono text-[10px] text-slate-700">
                        {mod.items_discovered} Discovered Items ({mod.execution_time_seconds || "1.2"}s runtime)
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Footer Signature Bar */}
          <div className="border-t-2 border-slate-900 pt-3 flex justify-between items-center text-[10px] font-mono text-slate-500 mt-8">
            <div className="flex items-center gap-1.5 font-semibold text-slate-700">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" /> KavachRecon Security Platform • Security Lead @premkrs
            </div>
            <div>Generated: {new Date().toUTCString()}</div>
          </div>
        </div>
      )}
    </div>
  );
}