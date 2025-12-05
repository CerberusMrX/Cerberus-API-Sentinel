import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Plus, Trash2, Edit, Activity } from 'lucide-react';
import { projectsAPI } from '../services/api';
import ConfirmationModal from '../components/ConfirmationModal';
import ScanProgress from '../components/ScanProgress';

const Projects = () => {
    const [projects, setProjects] = useState([]);
    const [loading, setLoading] = useState(true);
    const [scanningProjects, setScanningProjects] = useState(new Set());
    const [showModal, setShowModal] = useState(false);
    const [deleteModal, setDeleteModal] = useState({ isOpen: false, projectId: null, projectName: '' });
    const [scanningProject, setScanningProject] = useState(null);  // For visualization
    const [formData, setFormData] = useState({
        name: '',
        target_url: '',
        description: ''
    });

    useEffect(() => {
        fetchProjects();
    }, []);

    const fetchProjects = async () => {
        try {
            const response = await projectsAPI.list();
            setProjects(response.data.results || response.data);
            setLoading(false);
        } catch (error) {
            console.error('Error fetching projects:', error);
            setLoading(false);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            await projectsAPI.create(formData);
            setShowModal(false);
            setFormData({ name: '', target_url: '', description: '' });
            fetchProjects();
        } catch (error) {
            console.error('Error creating project:', error);
        }
    };

    const confirmDelete = (project) => {
        setDeleteModal({
            isOpen: true,
            projectId: project.id,
            projectName: project.name
        });
    };

    const handleDelete = async () => {
        if (!deleteModal.projectId) return;

        try {
            await projectsAPI.delete(deleteModal.projectId);
            fetchProjects();
        } catch (error) {
            console.error('Error deleting project:', error);
        }
    };

    const handleStartScan = async (project) => {
        // Prevent duplicate scans
        if (scanningProjects.has(project.id)) {
            return;
        }

        setScanningProjects(prev => new Set(prev).add(project.id));

        try {
            const response = await projectsAPI.startScan(project.id);
            const scanData = response.data;

            // Show visualization with scan ID
            setScanningProject({
                ...project,
                scanId: scanData.id  // Store scan ID for WebSocket connection
            });

            // Visualization will handle completion callback
        } catch (error) {
            console.error('Error starting scan:', error);
            alert('Failed to start scan. Please try again.');
            setScanningProject(null);
            setScanningProjects(prev => {
                const next = new Set(prev);
                next.delete(project.id);
                return next;
            });
        }
    };

    const onScanComplete = async () => {
        if (scanningProject) {
            setScanningProjects(prev => {
                const next = new Set(prev);
                next.delete(scanningProject.id);
                return next;
            });
        }
        setScanningProject(null);

        // Refresh projects to get updated scan count
        await fetchProjects();

        alert('Scan completed successfully!');
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-screen">
                <div className="text-2xl text-gray-600">Loading projects...</div>
            </div>
        );
    }

    return (
        <div className="p-8">
            <div className="flex justify-between items-center mb-6">
                <h2 className="text-3xl font-bold text-gray-800">Projects</h2>
                <button
                    onClick={() => setShowModal(true)}
                    className="flex items-center gap-2 bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors shadow-md"
                >
                    <Plus className="w-5 h-5" />
                    New Project
                </button>
            </div>

            {projects.length === 0 ? (
                <div className="text-center py-12 bg-white rounded-lg shadow-md">
                    <p className="text-gray-500 text-lg">No projects yet. Create your first project!</p>
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {projects.map((project) => (
                        <div key={project.id} className="bg-white rounded-lg shadow-md hover:shadow-lg transition-shadow overflow-hidden">
                            <div className="p-6">
                                <div className="flex justify-between items-start mb-4">
                                    <h3 className="text-xl font-bold text-gray-800">{project.name}</h3>
                                    <button
                                        onClick={() => confirmDelete(project)}
                                        className="text-red-500 hover:text-red-700 transition-colors"
                                    >
                                        <Trash2 className="w-5 h-5" />
                                    </button>
                                </div>
                                <p className="text-sm text-gray-600 mb-2 break-all">{project.target_url}</p>
                                <p className="text-gray-500 mb-4">{project.description || 'No description'}</p>
                                <div className="flex items-center text-sm text-gray-500 mb-4">
                                    <Activity className="w-4 h-4 mr-2" />
                                    {project.scan_count || 0} scans
                                </div>
                                <div className="flex gap-2">
                                    <button
                                        onClick={() => handleStartScan(project)}
                                        disabled={scanningProjects.has(project.id)}
                                        className={`flex-1 px-4 py-2 rounded transition-colors ${scanningProjects.has(project.id)
                                            ? 'bg-gray-400 text-white cursor-not-allowed'
                                            : 'bg-green-600 text-white hover:bg-green-700'
                                            }`}
                                    >
                                        {scanningProjects.has(project.id) ? 'Scanning... (~20s)' : 'Start Scan'}
                                    </button>
                                    <Link
                                        to={`/projects/${project.id}`}
                                        className="flex-1 bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 transition-colors text-center"
                                    >
                                        View Details
                                    </Link>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Create Project Modal */}
            {showModal && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                    <div className="bg-white rounded-lg shadow-xl p-8 max-w-md w-full mx-4">
                        <h3 className="text-2xl font-bold mb-4">Create New Project</h3>
                        <form onSubmit={handleSubmit} className="space-y-4">
                            <div>
                                <label className="block text-gray-700 font-medium mb-2">Project Name</label>
                                <input
                                    type="text"
                                    value={formData.name}
                                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                                    className="w-full px-4 py-2 border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                    required
                                />
                            </div>
                            <div>
                                <label className="block text-gray-700 font-medium mb-2">Target URL</label>
                                <input
                                    type="url"
                                    value={formData.target_url}
                                    onChange={(e) => setFormData({ ...formData, target_url: e.target.value })}
                                    className="w-full px-4 py-2 border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                    placeholder="https://api.example.com"
                                    required
                                />
                            </div>
                            <div>
                                <label className="block text-gray-700 font-medium mb-2">Description</label>
                                <textarea
                                    value={formData.description}
                                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                                    className="w-full px-4 py-2 border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                    rows="3"
                                />
                            </div>
                            <div className="flex gap-3 mt-6">
                                <button
                                    type="button"
                                    onClick={() => setShowModal(false)}
                                    className="flex-1 bg-gray-200 text-gray-800 px-4 py-2 rounded hover:bg-gray-300 transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className="flex-1 bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 transition-colors"
                                >
                                    Create
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Scan Visualization Modal */}
            {scanningProject && (
                <div className="fixed inset-0 bg-black bg-opacity-75 z-50 flex items-center justify-center p-8">
                    <div className="w-full h-full max-w-7xl max-h-[90vh] flex flex-col">
                        <ScanProgress
                            targetUrl={scanningProject.target_url}
                            scanId={scanningProject.scanId}
                            onComplete={onScanComplete}
                        />
                    </div>
                </div>
            )}

            {/* Delete Confirmation Modal */}
            <ConfirmationModal
                isOpen={deleteModal.isOpen}
                onClose={() => setDeleteModal({ ...deleteModal, isOpen: false })}
                onConfirm={handleDelete}
                title="Delete Project"
                message={`Are you sure you want to delete "${deleteModal.projectName}"? This action cannot be undone and will delete all associated scans.`}
                confirmText="Delete Project"
            />
        </div>
    );
};

export default Projects;
