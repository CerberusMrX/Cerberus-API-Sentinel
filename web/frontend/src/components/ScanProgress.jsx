import React, { useEffect, useState, useRef } from 'react';
import { Terminal, Activity, Globe, Shield, AlertTriangle, CheckCircle, Search } from 'lucide-react';

const ScanProgress = ({ targetUrl, scanId: propScanId, onComplete }) => {
    const [logs, setLogs] = useState([]);
    const [progress, setProgress] = useState(0);
    const [currentAction, setCurrentAction] = useState('Initializing...');
    const [discoveredUrls, setDiscoveredUrls] = useState([]);
    const [vulnCount, setVulnCount] = useState(0);
    const logsEndRef = useRef(null);

    const [activePayloads, setActivePayloads] = useState([]);
    const payloadsEndRef = useRef(null);

    // Reconnaissance data
    const [phase, setPhase] = useState('initializing'); // reconnaissance | scanning | reporting
    const [reconData, setReconData] = useState({
        openPorts: [],
        subdomains: [],
        directories: [],
        technologies: null
    });


    // Auto-scroll logs
    useEffect(() => {
        logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [logs]);

    // Auto-scroll payloads
    useEffect(() => {
        payloadsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [activePayloads]);

    useEffect(() => {
        // Require scanId prop - no fallbacks
        if (!propScanId) {
            console.error("ScanProgress: scanId prop is required");
            setLogs(prev => [...prev, '[Error] No scan ID provided. Cannot connect to WebSocket.']);
            setCurrentAction('Error: No Scan ID');
            return;
        }

        const scanId = propScanId;

        // Determine WebSocket URL dynamically
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = 'localhost:8000'; // Default to localhost:8000 for dev
        // In production, this should be window.location.host or from env

        const wsUrl = `${protocol}//${host}/ws/scans/${scanId}/`;

        console.log(`[ScanProgress] Connecting to WebSocket: ${wsUrl} (Scan ID: ${scanId})`);

        let socket;
        try {
            socket = new WebSocket(wsUrl);
        } catch (e) {
            console.error("WebSocket connection failed:", e);
            setLogs(prev => [...prev, `[Error] Failed to create WebSocket: ${e.message}`]);
            setCurrentAction('Connection Failed');
            return;
        }

        socket.onopen = () => {
            console.log(`[ScanProgress] WebSocket Connected (Scan ID: ${scanId})`);
            setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ✓ Connected to real-time scan stream.`]);
        };

        socket.onerror = (error) => {
            console.error("[ScanProgress] WebSocket Error:", error);
            setLogs(prev => [...prev, `[Error] WebSocket connection error. Server may not support WebSockets.`]);
            setCurrentAction('Connection Error');
        };

        socket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                console.log('[ScanProgress] Received:', data);

                if (data.action) setCurrentAction(data.action);
                if (data.log) setLogs(prev => [...prev, data.log]);
                if (data.progress) setProgress(data.progress);

                // Update phase
                if (data.phase) setPhase(data.phase);

                if (data.vuln_count !== undefined) setVulnCount(data.vuln_count);

                // Reconnaissance events
                if (data.port_found) {
                    setReconData(prev => ({
                        ...prev,
                        openPorts: [...prev.openPorts, data.port_found]
                    }));
                }

                if (data.subdomain_found) {
                    setReconData(prev => ({
                        ...prev,
                        subdomains: [...prev.subdomains, data.subdomain_found]
                    }));
                }

                if (data.directory_found) {
                    setReconData(prev => ({
                        ...prev,
                        directories: [...prev.directories, data.directory_found]
                    }));
                }

                if (data.technologies) {
                    setReconData(prev => ({
                        ...prev,
                        technologies: data.technologies
                    }));
                }

                if (data.url_found) {
                    setDiscoveredUrls(prev => {
                        if (!prev.includes(data.url_found)) {
                            return [...prev, data.url_found];
                        }
                        return prev;
                    });
                }

                if (data.discovered_urls) {
                    setDiscoveredUrls(prev => {
                        const newUrls = data.discovered_urls.filter(url => !prev.includes(url));
                        return [...prev, ...newUrls];
                    });
                }

                if (data.payload) {
                    setActivePayloads(prev => [...prev, `[${data.scanner}] Testing: ${data.payload}`].slice(-50)); // Keep last 50
                }

                if (data.action === 'Completed') {
                    console.log('[ScanProgress] Scan completed');
                    if (onComplete) onComplete();
                }
            } catch (e) {
                console.error('[ScanProgress] Error parsing WebSocket message:', e);
            }
        };

        socket.onclose = (event) => {
            console.log(`[ScanProgress] WebSocket disconnected (Code: ${event.code}, Reason: ${event.reason || 'No reason'})`);
            setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] WebSocket disconnected.`]);
        };

        return () => {
            socket.close();
        };
    }, [targetUrl, propScanId, onComplete]);

    return (
        <div className="bg-gray-900 rounded-lg shadow-xl border border-gray-700 overflow-hidden font-mono text-sm h-full flex flex-col">
            {/* Header */}
            <div className="bg-gray-800 px-4 py-2 flex justify-between items-center border-b border-gray-700 shrink-0">
                <div className="flex items-center gap-2 text-gray-300">
                    <Terminal className="w-4 h-4" />
                    <span className="font-semibold">Cerberus Scanner - Live Execution</span>
                </div>
                <div className="flex items-center gap-4 text-xs">
                    <div className="flex items-center gap-1 text-blue-400">
                        <Globe className="w-3 h-3" />
                        <span>{targetUrl}</span>
                    </div>
                    <div className="flex items-center gap-1 text-green-400">
                        <Activity className="w-3 h-3 animate-pulse" />
                        <span>{currentAction}</span>
                    </div>
                    {/* DEBUG INFO */}
                    <div className="text-xs text-gray-500">
                        Scan ID: {propScanId || 'N/A'} | WS: {window.location.protocol === 'https:' ? 'wss' : 'ws'}://localhost:8000
                    </div>
                </div>
            </div>

            <div className="flex flex-1 min-h-0">
                {/* Left Column: Logs & Payloads */}
                <div className="flex-1 flex flex-col border-r border-gray-700">
                    {/* Terminal Output */}
                    <div className="flex-1 p-4 overflow-y-auto bg-black text-green-500 space-y-1 font-mono border-b border-gray-700">
                        <div className="text-gray-500 text-xs mb-2 uppercase tracking-wider">System Logs</div>
                        {logs.map((log, i) => (
                            <div key={i} className="break-all hover:bg-gray-900 px-1 rounded">
                                <span className="text-gray-500 mr-2">$</span>
                                {log}
                            </div>
                        ))}
                        <div ref={logsEndRef} />
                    </div>

                    {/* Active Payloads */}
                    <div className="h-48 p-4 overflow-y-auto bg-gray-900 text-blue-400 space-y-1 font-mono">
                        <div className="text-gray-500 text-xs mb-2 uppercase tracking-wider flex items-center gap-2">
                            <Shield className="w-3 h-3" /> Active Payloads
                        </div>
                        {activePayloads.length === 0 ? (
                            <div className="text-gray-600 italic">Waiting for scanner...</div>
                        ) : (
                            activePayloads.map((payload, i) => (
                                <div key={i} className="break-all text-xs border-l-2 border-blue-500 pl-2">
                                    {payload}
                                </div>
                            ))
                        )}
                        <div ref={payloadsEndRef} />
                    </div>
                </div>

                {/* Right Column: Stats & Sitemap */}
                <div className="w-80 bg-gray-800 flex flex-col gap-6 p-4 overflow-y-auto">
                    {/* Progress Circle */}
                    <div className="text-center shrink-0">
                        <div className="relative w-24 h-24 mx-auto mb-2 flex items-center justify-center">
                            <svg className="w-full h-full transform -rotate-90">
                                <circle cx="48" cy="48" r="40" stroke="currentColor" strokeWidth="8" fill="transparent" className="text-gray-700" />
                                <circle cx="48" cy="48" r="40" stroke="currentColor" strokeWidth="8" fill="transparent" strokeDasharray={251.2} strokeDashoffset={251.2 - (251.2 * progress) / 100} className="text-blue-500 transition-all duration-300 ease-out" />
                            </svg>
                            <span className="absolute text-xl font-bold text-white">{progress}%</span>
                        </div>
                    </div>

                    {/* Stats Grid */}
                    <div className="grid grid-cols-2 gap-3 shrink-0">
                        <div className="bg-gray-900 p-3 rounded border border-gray-700 text-center">
                            <div className="text-xl font-bold text-white">{discoveredUrls.length}</div>
                            <div className="text-[10px] text-gray-500 uppercase">URLs</div>
                        </div>
                        <div className="bg-gray-900 p-3 rounded border border-gray-700 text-center">
                            <div className={`text-xl font-bold ${vulnCount > 0 ? 'text-red-500' : 'text-white'}`}>{vulnCount}</div>
                            <div className="text-[10px] text-gray-500 uppercase">Vulns</div>
                        </div>
                    </div>

                    {/* Live Sitemap */}
                    <div className="flex-1 overflow-hidden flex flex-col min-h-[200px]">
                        <h4 className="text-gray-400 text-xs uppercase tracking-wider mb-2 flex items-center gap-2 font-semibold">
                            <Globe className="w-3 h-3" /> Live Sitemap
                        </h4>
                        <div className="flex-1 overflow-y-auto space-y-1 pr-1 custom-scrollbar bg-gray-900 rounded p-2 border border-gray-700">
                            {discoveredUrls.map((url, i) => (
                                <div key={i} className="text-[10px] text-gray-300 truncate py-1 px-2 bg-gray-800 rounded border border-gray-700 hover:bg-gray-700 transition-colors" title={url}>
                                    {url}
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ScanProgress;
