import React, { useState } from 'react';
import { Play, Save, AlertCircle, CheckCircle } from 'lucide-react';
import Button from '../components/Button';
import Input from '../components/Input';
import { projectsAPI } from '../services/api';
import ScanProgress from '../components/ScanProgress';

const ScanConfig = () => {
    const [targetUrl, setTargetUrl] = useState('');
    const [scanModules, setScanModules] = useState({
        sqli: true,
        xss: true,
        cmdi: false,
        bola: false,
        ssrf: false,
        xxe: false,
        auth: false,
        access: false,
        misconfig: false,
        data: false,
        nosql: false,
        graphql: false,
        ssti: false,
        ldap: false,
        xpath: false,
        xml: false,
        jwt: false,
        oauth: false,
        hpp: false,
        ratelimit: false,
        mass: false,
        logic: false,
        logging: false,
        idor: false
    });

    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState(null);
    const [scanning, setScanning] = useState(false);
    const [currentProject, setCurrentProject] = useState(null);
    const [currentScanId, setCurrentScanId] = useState(null);

    const handleStartScan = async () => {
        setLoading(true);
        setMessage(null);
        try {
            console.log('Starting scan for URL:', targetUrl);

            let hostname;
            try {
                hostname = new URL(targetUrl).hostname;
            } catch (urlError) {
                console.error('Invalid URL format:', urlError);
                throw new Error('Invalid URL format. Please enter a valid URL.');
            }

            console.log('Creating project for hostname:', hostname);
            const projectResponse = await projectsAPI.create({
                name: `Scan ${hostname}`,
                target_url: targetUrl,
                description: 'Quick scan created from New Scan page'
            });

            console.log('Project created:', projectResponse.data);
            const project = projectResponse.data;
            setCurrentProject(project);

            console.log('Starting scan for project:', project.id);
            const scanResponse = await projectsAPI.startScan(project.id);
            console.log('Scan started:', scanResponse.data);

            // Set the scan ID from the response
            setCurrentScanId(scanResponse.data.id);

            setScanning(true);
            setLoading(false);

            console.log('Scan started successfully');
        } catch (error) {
            console.error('Scan start error:', error);
            console.error('Error response:', error.response);
            const errorMessage = error.message || error.response?.data?.message || 'Failed to start scan. Please try again.';
            setMessage({ type: 'error', text: errorMessage });
            setLoading(false);
            setScanning(false);
        }
    };

    const onScanComplete = () => {
        setScanning(false);
        setMessage({ type: 'success', text: 'Scan completed successfully!' });
        setTargetUrl('');
        setCurrentProject(null);
        setCurrentScanId(null);
    };

    return (
        <div className="p-8 max-w-6xl mx-auto">
            <div className="flex justify-between items-center mb-8">
                <h2 className="text-2xl font-bold text-gray-800">New Scan Configuration</h2>
            </div>

            {message && (
                <div className={`p-4 mb-6 rounded flex items-center gap-2 ${message.type === 'success' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                    {message.type === 'success' ? <CheckCircle className="w-5 h-5" /> : <AlertCircle className="w-5 h-5" />}
                    {message.text}
                </div>
            )}

            <div className="bg-white p-6 rounded-lg shadow-md border border-gray-200 space-y-6">
                <section>
                    <h3 className="text-lg font-semibold mb-4 text-gray-700">Target Information</h3>
                    <Input
                        label="Target URL"
                        placeholder="https://example.com/api"
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
                        className="max-w-xl"
                    />
                </section>

                <section>
                    <h3 className="text-lg font-semibold mb-4 text-gray-700">Scan Modules</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                        {[
                            { id: 'sqli', name: 'SQL Injection' },
                            { id: 'xss', name: 'Cross-Site Scripting (XSS)' },
                            { id: 'cmdi', name: 'Command Injection' },
                            { id: 'bola', name: 'BOLA/IDOR' },
                            { id: 'ssrf', name: 'SSRF' },
                            { id: 'xxe', name: 'XXE' },
                            { id: 'auth', name: 'Broken Authentication' },
                            { id: 'access', name: 'Broken Access Control' },
                            { id: 'misconfig', name: 'Security Misconfiguration' },
                            { id: 'data', name: 'Sensitive Data Exposure' },
                            { id: 'nosql', name: 'NoSQL Injection' },
                            { id: 'graphql', name: 'GraphQL Injection' },
                            { id: 'ssti', name: 'SSTI' },
                            { id: 'ldap', name: 'LDAP Injection' },
                            { id: 'xpath', name: 'XPath Injection' },
                            { id: 'xml', name: 'XML Injection' },
                            { id: 'jwt', name: 'JWT Vulnerabilities' },
                            { id: 'oauth', name: 'OAuth Misconfigurations' },
                            { id: 'hpp', name: 'HTTP Parameter Pollution' },
                            { id: 'ratelimit', name: 'Rate Limiting Issues' },
                            { id: 'mass', name: 'Mass Assignment' },
                            { id: 'logic', name: 'Business Logic Flaws' },
                            { id: 'logging', name: 'Insufficient Logging' },
                            { id: 'idor', name: 'Insecure Direct Object References' }
                        ].map((module) => (
                            <label key={module.id} className="flex items-center p-3 border rounded hover:bg-gray-50 cursor-pointer">
                                <input
                                    type="checkbox"
                                    checked={scanModules[module.id] || false}
                                    onChange={(e) => setScanModules({ ...scanModules, [module.id]: e.target.checked })}
                                    className="mr-3 h-4 w-4 text-blue-600"
                                />
                                <span className="text-sm text-gray-700">{module.name}</span>
                            </label>
                        ))}
                    </div>
                    <button
                        type="button"
                        onClick={() => {
                            const allSelected = Object.values(scanModules).every(v => v);
                            const newModules = {};
                            ['sqli', 'xss', 'cmdi', 'bola', 'ssrf', 'xxe', 'auth', 'access', 'misconfig',
                                'data', 'nosql', 'graphql', 'ssti', 'ldap', 'xpath', 'xml', 'jwt', 'oauth',
                                'hpp', 'ratelimit', 'mass', 'logic', 'logging', 'idor'].forEach(key => {
                                    newModules[key] = !allSelected;
                                });
                            setScanModules(newModules);
                        }}
                        className="mt-3 text-sm text-blue-600 hover:text-blue-700 font-medium"
                    >
                        {Object.values(scanModules).every(v => v) ? 'Deselect All' : 'Select All'}
                    </button>
                </section>

                <div className="pt-4 flex gap-4">
                    <Button onClick={handleStartScan} disabled={loading || !targetUrl} className="flex items-center gap-2">
                        <Play className="w-4 h-4" /> {loading ? 'Starting...' : 'Start Scan'}
                    </Button>
                    <Button className="bg-gray-600 hover:bg-gray-700 flex items-center gap-2">
                        <Save className="w-4 h-4" /> Save Profile
                    </Button>
                </div>
            </div>

            {/* Scan Visualization Modal */}
            {scanning && currentProject && currentScanId && (
                <div className="fixed inset-0 bg-black bg-opacity-75 z-50 flex items-center justify-center p-8">
                    <div className="w-full h-full max-w-7xl max-h-[90vh] flex flex-col">
                        <ScanProgress
                            targetUrl={currentProject.target_url}
                            scanId={currentScanId}
                            onComplete={onScanComplete}
                        />
                    </div>
                </div>
            )}
        </div>
    );
};

export default ScanConfig;
