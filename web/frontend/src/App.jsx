import React, { useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate } from 'react-router-dom';
import { LayoutDashboard, Shield, Activity, FileText, Plus } from 'lucide-react';
import ScanConfig from './pages/ScanConfig';
import Reports from './pages/Reports';
import ReportDetail from './pages/ReportDetail';
import Login from './pages/Login';
import Projects from './pages/Projects';
import ProjectDetail from './pages/ProjectDetail';

const Sidebar = () => {
  return (
    <div className="w-64 bg-gray-900 text-white h-screen fixed left-0 top-0 p-4 flex flex-col">
      <div className="flex items-center gap-2 mb-8 px-2">
        <Shield className="w-8 h-8 text-blue-500" />
        <h1 className="text-xl font-bold">Cerberus Sentinel</h1>
      </div>
      <nav className="space-y-2 flex-1">
        <Link to="/" className="flex items-center gap-3 px-4 py-2 rounded hover:bg-gray-800 text-gray-300 hover:text-white">
          <LayoutDashboard className="w-5 h-5" /> Dashboard
        </Link>
        <Link to="/scans/new" className="flex items-center gap-3 px-4 py-2 rounded hover:bg-gray-800 text-gray-300 hover:text-white">
          <Plus className="w-5 h-5" /> New Scan
        </Link>
        <Link to="/projects" className="flex items-center gap-3 px-4 py-2 rounded hover:bg-gray-800 text-gray-300 hover:text-white">
          <Activity className="w-5 h-5" /> Projects
        </Link>
        <Link to="/reports" className="flex items-center gap-3 px-4 py-2 rounded hover:bg-gray-800 text-gray-300 hover:text-white">
          <FileText className="w-5 h-5" /> Reports
        </Link>
      </nav>
    </div>
  );
};

const Dashboard = () => (
  <div className="p-8 max-w-6xl mx-auto">
    {/* Header Section */}
    <div className="bg-gradient-to-r from-blue-600 to-blue-800 text-white p-8 rounded-lg shadow-lg mb-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <Shield className="w-12 h-12" />
            <h1 className="text-4xl font-bold">Cerberus API Sentinel</h1>
          </div>
          <p className="text-xl text-blue-100 mb-2">Professional API Security Scanner & Vulnerability Assessment Platform</p>
          <p className="text-sm text-blue-200">Version 1.0 | Author: Sudeepa Wanigarathna</p>
        </div>
      </div>
    </div>

    {/* Description */}
    <div className="bg-white p-6 rounded-lg shadow-md border border-gray-200 mb-6">
      <h2 className="text-2xl font-bold mb-4 text-gray-800">About This Tool</h2>
      <p className="text-gray-700 leading-relaxed">
        Cerberus API Sentinel is a comprehensive offensive security tool designed for professional API penetration testing
        and vulnerability assessment. It provides automated scanning capabilities to identify security weaknesses in RESTful APIs,
        helping security professionals and developers ensure their applications are protected against common and advanced attack vectors.
      </p>
    </div>

    {/* Vulnerability Detection Capabilities */}
    <div className="bg-white p-6 rounded-lg shadow-md border border-gray-200 mb-6">
      <h2 className="text-2xl font-bold mb-4 text-gray-800 flex items-center gap-2">
        <Shield className="w-6 h-6 text-red-600" />
        Vulnerability Detection Capabilities
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {[
          'SQL Injection (SQLi)',
          'Cross-Site Scripting (XSS)',
          'Command Injection',
          'BOLA/IDOR',
          'Server-Side Request Forgery (SSRF)',
          'XML External Entity (XXE)',
          'Broken Authentication',
          'Broken Access Control',
          'Security Misconfiguration',
          'Sensitive Data Exposure',
          'XML Injection',
          'LDAP Injection',
          'XPath Injection',
          'HTTP Parameter Pollution',
          'Server-Side Template Injection (SSTI)',
          'JWT Vulnerabilities',
          'OAuth Misconfigurations',
          'API Rate Limiting Issues',
          'Insecure Direct Object References',
          'Mass Assignment',
          'GraphQL Injection',
          'NoSQL Injection',
          'Business Logic Flaws',
          'Insufficient Logging & Monitoring'
        ].map((vuln, idx) => (
          <div key={idx} className="flex items-start gap-2 p-3 bg-gray-50 rounded border border-gray-200">
            <span className="text-red-600 font-bold">✓</span>
            <span className="text-sm text-gray-700">{vuln}</span>
          </div>
        ))}
      </div>
    </div>

    {/* Features */}
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div className="bg-white p-6 rounded-lg shadow-md border border-gray-200">
        <h3 className="text-xl font-bold mb-4 text-gray-800">Key Features</h3>
        <ul className="space-y-2 text-gray-700">
          <li className="flex items-start gap-2">
            <span className="text-blue-600">•</span>
            <span>Automated vulnerability scanning</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-blue-600">•</span>
            <span>Project-based organization</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-blue-600">•</span>
            <span>Detailed vulnerability reports</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-blue-600">•</span>
            <span>RESTful API integration</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-blue-600">•</span>
            <span>Multiple authentication methods</span>
          </li>
        </ul>
      </div>

      <div className="bg-white p-6 rounded-lg shadow-md border border-gray-200">
        <h3 className="text-xl font-bold mb-4 text-gray-800">Use Cases</h3>
        <ul className="space-y-2 text-gray-700">
          <li className="flex items-start gap-2">
            <span className="text-blue-600">•</span>
            <span>Security assessments & audits</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-blue-600">•</span>
            <span>Penetration testing engagements</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-blue-600">•</span>
            <span>Continuous security monitoring</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-blue-600">•</span>
            <span>DevSecOps integration</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-blue-600">•</span>
            <span>Compliance verification</span>
          </li>
        </ul>
      </div>
    </div>
  </div>
);

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-50">
        <Sidebar />
        <main className="ml-64">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/new-scan" element={<ScanConfig />} />
            <Route path="/scans/new" element={<ScanConfig />} />
            <Route path="/projects" element={<Projects />} />
            <Route path="/projects/:id" element={<ProjectDetail />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/reports/:id" element={<ReportDetail />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;

