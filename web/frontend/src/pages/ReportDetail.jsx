import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, AlertTriangle, Shield, CheckCircle, Download } from 'lucide-react';
import { scansAPI } from '../services/api';

const ReportDetail = () => {
    const { id } = useParams();
    const [scan, setScan] = useState(null);
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            try {
                // Get scan data
                const scanResponse = await scansAPI.get(id);
                setScan(scanResponse.data);

                // Get vulnerabilities separately
                const vulnResponse = await scansAPI.getVulnerabilities(id);
                setVulnerabilities(vulnResponse.data || []);
            } catch (error) {
                console.error('Failed to fetch scan/vulnerabilities:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [id]);

    const handleExportPDF = () => {
        window.print();
    };

    if (loading) return <div className="p-8">Loading report...</div>;
    if (!scan) return <div className="p-8">Report not found.</div>;

    return (
        <div className="p-8 max-w-6xl mx-auto">
            <Link to="/reports" className="flex items-center text-gray-500 hover:text-gray-700 mb-6">
                <ArrowLeft className="w-4 h-4 mr-2" /> Back to Reports
            </Link>

            <div className="bg-white p-6 rounded-lg shadow-md border border-gray-200 mb-8">
                <div className="flex justify-between items-start">
                    <div>
                        <h1 className="text-3xl font-bold text-gray-900 mb-2">Scan Report</h1>
                        <p className="text-gray-500">ID: {scan.id}</p>
                    </div>
                    <div className="flex items-center gap-3">
                        <button
                            onClick={handleExportPDF}
                            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                        >
                            <Download className="w-4 h-4" />
                            Export PDF
                        </button>
                        <div className={`px-4 py-2 rounded-full font-bold text-sm
            ${scan.status === 'COMPLETED' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}`}>
                            {scan.status}
                        </div>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2 space-y-6">
                    <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-red-500" /> Vulnerabilities Found ({vulnerabilities.length})
                    </h2>

                    {vulnerabilities.length === 0 ? (
                        <div className="bg-green-50 p-6 rounded-lg border border-green-200 text-green-700 flex items-center gap-3">
                            <CheckCircle className="w-6 h-6" />
                            No vulnerabilities detected. Good job!
                        </div>
                    ) : (
                        vulnerabilities.map((vuln, index) => (
                            <div key={index} className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 border-l-4 border-l-red-500">
                                <div className="flex justify-between items-start mb-2">
                                    <h3 className="text-lg font-bold text-gray-900">{vuln.name}</h3>
                                    <span className="bg-red-100 text-red-800 text-xs font-bold px-2 py-1 rounded uppercase">{vuln.severity}</span>
                                </div>
                                <p className="text-gray-600 mb-4">{vuln.description}</p>

                                <div className="bg-gray-50 p-4 rounded text-sm font-mono overflow-x-auto">
                                    <div className="text-xs text-gray-500 uppercase mb-1">Evidence</div>
                                    {vuln.evidence}
                                </div>
                            </div>
                        ))
                    )}
                </div>

                <div className="space-y-6">
                    <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                        <h3 className="font-bold text-gray-800 mb-4 flex items-center gap-2">
                            <Shield className="w-4 h-4" /> Scan Details
                        </h3>
                        <dl className="space-y-3 text-sm">
                            <div>
                                <dt className="text-gray-500">Started</dt>
                                <dd className="font-medium">{new Date(scan.started_at || Date.now()).toLocaleString()}</dd>
                            </div>
                            <div>
                                <dt className="text-gray-500">Completed</dt>
                                <dd className="font-medium">{scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'N/A'}</dd>
                            </div>
                        </dl>
                    </div>
                </div>
            </div>

            {/* Reconnaissance Data Section */}
            {scan.status === 'COMPLETED' && scan.results?.reconnaissance && (
                <div className="mt-8">
                    <h2 className="text-xl font-bold text-gray-800 mb-4">Reconnaissance Data</h2>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        {/* Subdirectories */}
                        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                            <h4 className="font-semibold text-blue-900 mb-2 text-sm">
                                📁 Subdirectories ({scan.results.reconnaissance.subdirectories.length})
                            </h4>
                            <div className="max-h-40 overflow-y-auto space-y-1">
                                {scan.results.reconnaissance.subdirectories.map((dir, idx) => (
                                    <div key={idx} className="text-xs font-mono bg-white px-2 py-1 rounded text-gray-700">{dir}</div>
                                ))}
                            </div>
                        </div>

                        {/* Subdomains */}
                        <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
                            <h4 className="font-semibold text-purple-900 mb-2 text-sm">
                                🌐 Subdomains ({scan.results.reconnaissance.subdomains.length})
                            </h4>
                            <div className="max-h-40 overflow-y-auto space-y-1">
                                {scan.results.reconnaissance.subdomains.map((sub, idx) => (
                                    <div key={idx} className="text-xs font-mono bg-white px-2 py-1 rounded text-gray-700">{sub}</div>
                                ))}
                            </div>
                        </div>

                        {/* Open Ports */}
                        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                            <h4 className="font-semibold text-green-900 mb-2 text-sm">
                                🔓 Open Ports ({scan.results.reconnaissance.open_ports.length})
                            </h4>
                            <div className="max-h-40 overflow-y-auto space-y-1">
                                {scan.results.reconnaissance.open_ports.map((port, idx) => (
                                    <div key={idx} className="text-xs bg-white px-2 py-1 rounded flex justify-between">
                                        <span className="font-mono text-gray-700">Port {port.port}</span>
                                        <span className="text-gray-600">{port.service}</span>
                                        <span className={`font-semibold ${port.state === 'open' ? 'text-green-600' : port.state === 'filtered' ? 'text-yellow-600' : 'text-gray-500'}`}>
                                            {port.state}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Tech Stack */}
                        <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                            <h4 className="font-semibold text-orange-900 mb-2 text-sm">
                                ⚙️ Tech Stack
                            </h4>
                            <div className="max-h-40 overflow-y-auto space-y-1 text-xs">
                                <div className="bg-white px-2 py-1 rounded">
                                    <span className="font-semibold text-gray-700">Server:</span> {scan.results.reconnaissance.tech_stack.server}
                                </div>
                                <div className="bg-white px-2 py-1 rounded">
                                    <span className="font-semibold text-gray-700">Backend:</span> {scan.results.reconnaissance.tech_stack.backend}
                                </div>
                                <div className="bg-white px-2 py-1 rounded">
                                    <span className="font-semibold text-gray-700">Frontend:</span> {scan.results.reconnaissance.tech_stack.frontend}
                                </div>
                                <div className="bg-white px-2 py-1 rounded">
                                    <span className="font-semibold text-gray-700">Database:</span> {scan.results.reconnaissance.tech_stack.database}
                                </div>
                                <div className="bg-white px-2 py-1 rounded">
                                    <span className="font-semibold text-gray-700">Languages:</span> {scan.results.reconnaissance.tech_stack.languages.join(', ')}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ReportDetail;
