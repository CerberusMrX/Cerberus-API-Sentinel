import React, { useEffect, useState } from 'react';
import { FileText, AlertTriangle, CheckCircle, Clock, Trash2 } from 'lucide-react';
import { Link } from 'react-router-dom';
import { scansAPI, projectsAPI } from '../services/api';
import ConfirmationModal from '../components/ConfirmationModal';

const Reports = () => {
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [projects, setProjects] = useState({});
    const [deleteModal, setDeleteModal] = useState({ isOpen: false, scanId: null, scanName: '' });

    useEffect(() => {
        const fetchData = async () => {
            try {
                // Fetch scans
                const scansResponse = await scansAPI.list();
                const scansData = scansResponse.data.results || scansResponse.data;
                setScans(scansData);

                // Fetch projects to get names
                const projectsResponse = await projectsAPI.list();
                const projectsData = projectsResponse.data.results || projectsResponse.data;
                const projectsMap = {};
                projectsData.forEach(project => {
                    projectsMap[project.id] = project;
                });
                setProjects(projectsMap);
            } catch (error) {
                console.error('Failed to fetch data:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, []);

    const confirmDelete = (scan) => {
        const projectName = projects[scan.project]?.name || 'Unknown';
        setDeleteModal({
            isOpen: true,
            scanId: scan.id,
            scanName: `${projectName} - ${scan.id.substring(0, 8)}`
        });
    };

    const handleDelete = async () => {
        if (!deleteModal.scanId) return;

        try {
            await scansAPI.delete(deleteModal.scanId);
            setScans(scans.filter(scan => scan.id !== deleteModal.scanId));
            setDeleteModal({ isOpen: false, scanId: null, scanName: '' });
        } catch (error) {
            console.error('Failed to delete report:', error);
            alert('Failed to delete report. Please try again.');
            setDeleteModal({ isOpen: false, scanId: null, scanName: '' });
        }
    };

    if (loading) return <div className="p-8">Loading reports...</div>;

    return (
        <div className="p-8">
            <h2 className="text-2xl font-bold mb-6 text-gray-800">Scan Reports</h2>

            <div className="bg-white rounded-lg shadow overflow-hidden border border-gray-200">
                <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                        <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Target</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Findings</th>
                            <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                        {scans.map((scan) => (
                            <tr key={scan.id} className="hover:bg-gray-50">
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="text-sm font-medium text-gray-900">
                                        {projects[scan.project]?.name || 'Loading...'}
                                    </div>
                                    <div className="text-sm text-gray-500">
                                        {projects[scan.project]?.target_url || scan.id}
                                    </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                    ${scan.status === 'COMPLETED' ? 'bg-green-100 text-green-800' :
                                            scan.status === 'RUNNING' ? 'bg-blue-100 text-blue-800' :
                                                scan.status === 'FAILED' ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800'}`}>
                                        {scan.status}
                                    </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {new Date(scan.created_at || Date.now()).toLocaleDateString()}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {scan.vulnerability_count || 0} Issues
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                    <div className="flex items-center justify-end gap-2">
                                        <Link to={`/reports/${scan.id}`} className="text-blue-600 hover:text-blue-900 flex items-center gap-1">
                                            <FileText className="w-4 h-4" /> View
                                        </Link>
                                        <button
                                            onClick={() => confirmDelete(scan)}
                                            className="text-red-600 hover:text-red-900 flex items-center gap-1"
                                        >
                                            <Trash2 className="w-4 h-4" /> Delete
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
                {scans.length === 0 && (
                    <div className="p-8 text-center text-gray-500">
                        No scans found. Start a new scan to see results here.
                    </div>
                )}
            </div>

            <ConfirmationModal
                isOpen={deleteModal.isOpen}
                onClose={() => setDeleteModal({ isOpen: false, scanId: null, scanName: '' })}
                onConfirm={handleDelete}
                title="Delete Report"
                message={`Are you sure you want to delete the report "${deleteModal.scanName}"? This action cannot be undone.`}
            />
        </div>
    );
};

export default Reports;
