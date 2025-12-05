import React, { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, Activity, Clock, CheckCircle, XCircle, AlertCircle, Play, Trash2 } from 'lucide-react';
import { projectsAPI, scansAPI } from '../services/api';
import StatusBadge from '../components/StatusBadge';
import ConfirmationModal from '../components/ConfirmationModal';
import ScanProgress from '../components/ScanProgress';

const ProjectDetail = () => {
    const { id } = useParams();
    const [project, setProject] = useState(null);
    const [scans, setScans] = useState([]);
    const [selectedScan, setSelectedScan] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [loadingVulns, setLoadingVulns] = useState(false);
    const [startingScan, setStartingScan] = useState(false);
    const [deleteModal, setDeleteModal] = useState({ isOpen: false, scanId: null });

    useEffect(() => {
        fetchProjectData();
    }, [id]);

    const fetchProjectData = async () => {
        try {
            const [projectRes, scansRes] = await Promise.all([
                projectsAPI.get(id),
                projectsAPI.getScans(id)
            ]);
            setProject(projectRes.data);
            setScans(scansRes.data.results || scansRes.data);
            setLoading(false);
        } catch (err) {
            console.error('Error fetching project details:', err);
            setError('Failed to load project details');
            setLoading(false);
        }
    };

    const handleScanSelect = async (scan) => {
        setSelectedScan(scan);
        if (scan.status === 'COMPLETED') {
            setLoadingVulns(true);
            try {
                const response = await scansAPI.getVulnerabilities(scan.id);
                setSelectedScan(prev => ({
                    ...prev,
                    vulnerabilities: response.data
                }));
            } catch (err) {
                console.error('Error fetching vulnerabilities:', err);
            } finally {
                setLoadingVulns(false);
            }
        }
    };

    const handleStartScan = async () => {
        setStartingScan(true);
        // ScanProgress component will handle the visualization
        // The actual API call happens inside the component's onComplete or we trigger it here?
        // Wait, the API call is synchronous. We need to start the API call BUT show the UI.
        // If we await the API call, the UI won't update if it's blocking the main thread? 
        // No, JS is single threaded but the await yields.
        // However, we want the visualization to run for 20s.
        // So we should start the visualization AND the API call.

        try {
            await projectsAPI.startScan(id);
            await fetchProjectData();
            // We don't alert here anymore, the visualization will finish naturally
        } catch (err) {
            console.error('Error starting scan:', err);
            alert('Failed to start scan. Please try again.');
            setStartingScan(false);
        }
    };

    const onScanComplete = () => {
        setStartingScan(false);
        alert('Scan completed successfully!');
    };

    const confirmDeleteScan = (scanId, e) => {
        e.stopPropagation();
        setDeleteModal({ isOpen: true, scanId });
    };

    const handleDeleteScan = async () => {
        if (!deleteModal.scanId) return;

        try {
            await scansAPI.delete(deleteModal.scanId);
            if (selectedScan?.id === deleteModal.scanId) {
                setSelectedScan(null);
            }
            await fetchProjectData();
        } catch (error) {
            console.error('Error deleting scan:', error);
            alert('Failed to delete scan');
        }
    };

    if (loading) return <div className="p-8">Loading...</div>;
    if (error) return <div className="p-8 text-red-600">{error}</div>;
    if (!project) return <div className="p-8">Project not found</div>;

    return (
        <div className="p-8 h-[calc(100vh-64px)] overflow-hidden flex flex-col">
            <div className="mb-6 flex items-center gap-4">
                <Link to="/projects" className="p-2 hover:bg-gray-100 rounded-full transition-colors">
                    <ArrowLeft className="w-6 h-6 text-gray-600" />
                </Link>
                <div>
                    <h1 className="text-2xl font-bold text-gray-900">{project.name}</h1>
                    <p className="text-gray-500 text-sm">{project.target_url}</p>
                </div>
            </div>

            {startingScan ? (
                <div className="flex-1 flex flex-col min-h-0">
                    <ScanProgress
                        targetUrl={project.target_url}
                        onComplete={onScanComplete}
                    />
                </div>
            ) : (
                <div className="flex gap-6 flex-1 overflow-hidden">
                    {/* Scans List */}
                    <div className="w-1/3 bg-white rounded-lg shadow-md border border-gray-200 flex flex-col">
                        <div className="p-4 border-b border-gray-200 bg-gray-50 flex justify-between items-center">
                            <h2 className="font-bold text-gray-700">Scan History</h2>
                            <button
                                onClick={handleStartScan}
                                className="flex items-center gap-2 px-3 py-1.5 rounded text-sm transition-colors shadow-sm bg-green-600 text-white hover:bg-green-700"
                            >
                                <Play className="w-4 h-4" />
                                New Scan
                            </button>
                        </div>

                        <div className="flex-1 overflow-y-auto p-4 space-y-3">
                            {scans.length === 0 ? (
                                <div className="text-center text-gray-500 py-8">
                                    No scans yet
                                </div>
                            ) : (
                                scans.map((scan) => (
                                    <div
                                        key={scan.id}
                                        onClick={() => handleScanSelect(scan)}
                                        className={`p-4 rounded-lg border cursor-pointer transition-all ${selectedScan?.id === scan.id
                                            ? 'border-blue-500 bg-blue-50 shadow-sm'
                                            : 'border-gray-200 hover:border-blue-300 hover:bg-gray-50'
                                            }`}
                                    >
                                        <div className="flex justify-between items-start mb-3">
                                            <div className="flex-1">
                                                <p className="text-sm text-gray-500 mb-1">
                                                    Scan ID: <span className="font-mono text-xs">{scan.id.substring(0, 8)}...</span>
                                                </p>
                                                <StatusBadge status={scan.status} />
                                            </div>
                                            <button
                                                onClick={(e) => confirmDeleteScan(scan.id, e)}
                                                className="text-red-500 hover:text-red-700 transition-colors p-1 rounded hover:bg-red-50"
                                                title="Delete scan"
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        </div>
                                        <div className="flex items-center text-xs text-gray-500">
                                            <Clock className="w-3 h-3 mr-1" />
                                            {new Date(scan.started_at).toLocaleString()}
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>

                    {/* Scan Details */}
                    <div className="flex-1 bg-white rounded-lg shadow-md border border-gray-200 flex flex-col overflow-hidden">
                        {selectedScan ? (
                            <>
                                <div className="p-6 border-b border-gray-200 bg-gray-50">
                                    <div className="flex justify-between items-start">
                                        <div>
                                            <h2 className="text-xl font-bold text-gray-900 mb-2">Scan Details</h2>
                                            <div className="flex gap-4 text-sm text-gray-600">
                                                <span className="font-mono">ID: {selectedScan.id}</span>
                                                <span>Started: {new Date(selectedScan.started_at).toLocaleString()}</span>
                                            </div>
                                        </div>
                                        <StatusBadge status={selectedScan.status} />
                                    </div>
                                </div>

                                <div className="flex-1 overflow-y-auto p-6">
                                    {selectedScan.status === 'COMPLETED' && (
                                        <div>
                                            <h3 className="font-semibold text-gray-800 mb-3">Vulnerabilities Found</h3>
                                            {loadingVulns ? (
                                                <div className="text-center py-8">
                                                    <Activity className="w-8 h-8 text-blue-600 animate-spin mx-auto mb-2" />
                                                    <p className="text-gray-500">Loading vulnerabilities...</p>
                                                </div>
                                            ) : (!selectedScan.vulnerabilities || selectedScan.vulnerabilities.length === 0) ? (
                                                <div className="text-center py-8 bg-green-50 rounded-lg border border-green-200">
                                                    <CheckCircle className="w-12 h-12 text-green-600 mx-auto mb-2" />
                                                    <p className="text-green-700 font-semibold">No vulnerabilities found!</p>
                                                    <p className="text-green-600 text-sm mt-1">This scan completed successfully with no issues detected.</p>
                                                </div>
                                            ) : (
                                                <div className="space-y-3">
                                                    {selectedScan.vulnerabilities.map((vuln, idx) => (
                                                        <div key={idx} className="p-4 bg-red-50 border border-red-200 rounded-lg">
                                                            <div className="flex justify-between items-start mb-2">
                                                                <h4 className="font-semibold text-red-800">{vuln.name || 'Vulnerability'}</h4>
                                                                <span className={`px-2 py-1 rounded text-xs font-semibold ${vuln.severity === 'CRITICAL' ? 'bg-red-600 text-white' :
                                                                    vuln.severity === 'HIGH' ? 'bg-orange-500 text-white' :
                                                                        vuln.severity === 'MEDIUM' ? 'bg-yellow-500 text-white' :
                                                                            'bg-blue-500 text-white'
                                                                    }`}>
                                                                    {vuln.severity || 'UNKNOWN'}
                                                                </span>
                                                            </div>
                                                            <p className="text-sm text-gray-700">{vuln.description || 'No description available'}</p>
                                                            {vuln.evidence && (
                                                                <div className="mt-2 bg-white p-2 rounded border border-red-100 text-xs font-mono overflow-x-auto">
                                                                    {vuln.evidence}
                                                                </div>
                                                            )}
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Reconnaissance Data Section */}
                                    {selectedScan.status === 'COMPLETED' && selectedScan.results?.reconnaissance && (
                                        <div className="mt-6 border-t border-gray-200 pt-6">
                                            <h3 className="font-semibold text-gray-800 mb-4">Reconnaissance Data</h3>

                                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                                {/* Subdirectories */}
                                                <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                                                    <h4 className="font-semibold text-blue-900 mb-2 text-sm">
                                                        📁 Subdirectories ({selectedScan.results.reconnaissance.subdirectories.length})
                                                    </h4>
                                                    <div className="max-h-40 overflow-y-auto space-y-1">
                                                        {selectedScan.results.reconnaissance.subdirectories.map((dir, idx) => (
                                                            <div key={idx} className="text-xs font-mono bg-white px-2 py-1 rounded text-gray-700">{dir}</div>
                                                        ))}
                                                    </div>
                                                </div>

                                                {/* Subdomains */}
                                                <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
                                                    <h4 className="font-semibold text-purple-900 mb-2 text-sm">
                                                        🌐 Subdomains ({selectedScan.results.reconnaissance.subdomains.length})
                                                    </h4>
                                                    <div className="max-h-40 overflow-y-auto space-y-1">
                                                        {selectedScan.results.reconnaissance.subdomains.map((sub, idx) => (
                                                            <div key={idx} className="text-xs font-mono bg-white px-2 py-1 rounded text-gray-700">{sub}</div>
                                                        ))}
                                                    </div>
                                                </div>

                                                {/* Open Ports */}
                                                <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                                                    <h4 className="font-semibold text-green-900 mb-2 text-sm">
                                                        🔓 Open Ports ({selectedScan.results.reconnaissance.open_ports.length})
                                                    </h4>
                                                    <div className="max-h-40 overflow-y-auto space-y-1">
                                                        {selectedScan.results.reconnaissance.open_ports.map((port, idx) => (
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
                                                            <span className="font-semibold text-gray-700">Server:</span> {selectedScan.results.reconnaissance.tech_stack.server}
                                                        </div>
                                                        <div className="bg-white px-2 py-1 rounded">
                                                            <span className="font-semibold text-gray-700">Backend:</span> {selectedScan.results.reconnaissance.tech_stack.backend}
                                                        </div>
                                                        <div className="bg-white px-2 py-1 rounded">
                                                            <span className="font-semibold text-gray-700">Frontend:</span> {selectedScan.results.reconnaissance.tech_stack.frontend}
                                                        </div>
                                                        <div className="bg-white px-2 py-1 rounded">
                                                            <span className="font-semibold text-gray-700">Languages:</span> {selectedScan.results.reconnaissance.tech_stack.languages.join(', ')}
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {selectedScan.status === 'PENDING' && (
                                        <div className="text-center py-8 bg-yellow-50 rounded-lg border border-yellow-200">
                                            <Clock className="w-12 h-12 text-yellow-600 mx-auto mb-2" />
                                            <p className="text-yellow-700 font-semibold">Scan is pending</p>
                                            <p className="text-yellow-600 text-sm mt-1">The scan has not started yet.</p>
                                        </div>
                                    )}

                                    {selectedScan.status === 'RUNNING' && (
                                        <div className="text-center py-8 bg-blue-50 rounded-lg border border-blue-200">
                                            <Activity className="w-12 h-12 text-blue-600 mx-auto mb-2 animate-spin" />
                                            <p className="text-blue-700 font-semibold">Scan in progress</p>
                                            <p className="text-blue-600 text-sm mt-1">Please wait while the scan completes...</p>
                                        </div>
                                    )}

                                    {selectedScan.status === 'FAILED' && (
                                        <div className="text-center py-8 bg-red-50 rounded-lg border border-red-200">
                                            <XCircle className="w-12 h-12 text-red-600 mx-auto mb-2" />
                                            <p className="text-red-700 font-semibold">Scan failed</p>
                                            <p className="text-red-600 text-sm mt-1">The scan encountered an error and could not complete.</p>
                                        </div>
                                    )}
                                </div>
                            </>
                        ) : (
                            <div className="flex flex-col items-center justify-center h-full text-gray-500">
                                <Activity className="w-16 h-16 mb-4 text-gray-300" />
                                <p className="text-lg">Select a scan to view details</p>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* Delete Confirmation Modal */}
            <ConfirmationModal
                isOpen={deleteModal.isOpen}
                onClose={() => setDeleteModal({ ...deleteModal, isOpen: false })}
                onConfirm={handleDeleteScan}
                title="Delete Scan"
                message="Are you sure you want to delete this scan? This action cannot be undone."
                confirmText="Delete Scan"
            />
        </div>
    );
};

export default ProjectDetail;
