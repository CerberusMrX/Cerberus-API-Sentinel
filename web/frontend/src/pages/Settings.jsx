import React from 'react';
import { Shield, Code, Terminal } from 'lucide-react';

const Settings = () => {
    return (
        <div className="p-8 max-w-4xl mx-auto">
            <h2 className="text-2xl font-bold mb-6">About Cerberus Sentinel</h2>

            <div className="bg-white p-6 rounded-lg shadow-md border border-gray-200 mb-6">
                <div className="flex items-center gap-4 mb-4">
                    <Shield className="w-12 h-12 text-blue-600" />
                    <div>
                        <h3 className="text-xl font-semibold">Cerberus API Sentinel</h3>
                        <p className="text-gray-600">Professional API Security Scanner v1.0</p>
                    </div>
                </div>
                <p className="text-gray-700 mb-4">
                    Cerberus Sentinel is a comprehensive offensive security tool designed for API penetration testing.
                    It combines a powerful CLI scanner with a modern web dashboard for managing assessments.
                </p>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-md border border-gray-200 mb-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Code className="w-5 h-5" /> Features
                </h3>
                <ul className="space-y-2 text-gray-700">
                    <li className="flex items-start gap-2">
                        <span className="text-blue-600">•</span>
                        <span>SQL Injection (SQLi) Detection</span>
                    </li>
                    <li className="flex items-start gap-2">
                        <span className="text-blue-600">•</span>
                        <span>Cross-Site Scripting (XSS) Testing</span>
                    </li>
                    <li className="flex items-start gap-2">
                        <span className="text-blue-600">•</span>
                        <span>Command Injection Analysis</span>
                    </li>
                    <li className="flex items-start gap-2">
                        <span className="text-blue-600">•</span>
                        <span>BOLA/IDOR Testing</span>
                    </li>
                    <li className="flex items-start gap-2">
                        <span className="text-blue-600">•</span>
                        <span>SSRF & XXE Detection</span>
                    </li>
                    <li className="flex items-start gap-2">
                        <span className="text-blue-600">•</span>
                        <span>Authentication Testing</span>
                    </li>
                </ul>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-md border border-gray-200">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Terminal className="w-5 h-5" /> CLI Usage
                </h3>
                <div className="bg-gray-900 text-white p-4 rounded font-mono text-sm">
                    <div className="mb-2"># Run a scan</div>
                    <div className="text-green-400">cerberus -u https://api.target.com --scan-all</div>
                    <div className="mt-4 mb-2"># Launch GUI mode</div>
                    <div className="text-green-400">cerberus --gui</div>
                </div>
            </div>
        </div>
    );
};

export default Settings;
