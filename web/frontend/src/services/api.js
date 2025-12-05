import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000/api';

// Create axios instance with default config
const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Add auth token to requests
// Token interceptor removed for open source version
// api.interceptors.request.use((config) => {
//     const token = localStorage.getItem('token');
//     if (token) {
//         config.headers.Authorization = `Token ${token}`;
//     }
//     return config;
// });

// Auth API
export const authAPI = {
    register: (userData) => api.post('/auth/register/', userData),
    login: (credentials) => api.post('/auth/login/', credentials),
    logout: () => api.post('/auth/logout/'),
    getProfile: () => api.get('/auth/profile/'),
    updateProfile: (data) => api.patch('/auth/profile/', data),
};

// Projects API
export const projectsAPI = {
    list: () => api.get('/projects/projects/'),
    get: (id) => api.get(`/projects/projects/${id}/`),
    create: (data) => api.post('/projects/projects/', data),
    update: (id, data) => api.patch(`/projects/projects/${id}/`, data),
    delete: (id) => api.delete(`/projects/projects/${id}/`),
    getScans: (id) => api.get(`/projects/projects/${id}/scans/`),
    startScan: (id) => api.post(`/projects/projects/${id}/start_scan/`),
};

// Scans API
export const scansAPI = {
    list: () => api.get('/projects/scans/'),
    get: (id) => api.get(`/projects/scans/${id}/`),
    delete: (id) => api.delete(`/projects/scans/${id}/`),
    cancel: (id) => api.post(`/projects/scans/${id}/cancel/`),
    getVulnerabilities: (id) => api.get(`/projects/scans/${id}/vulnerabilities/`),
};

// Vulnerabilities API
export const vulnerabilitiesAPI = {
    list: () => api.get('/scans/vulnerabilities/'),
    get: (id) => api.get(`/scans/vulnerabilities/${id}/`),
};

// Scan Configurations API
export const configurationsAPI = {
    list: () => api.get('/scans/configurations/'),
    get: (id) => api.get(`/scans/configurations/${id}/`),
    create: (data) => api.post('/scans/configurations/', data),
    update: (id, data) => api.patch(`/scans/configurations/${id}/`, data),
    delete: (id) => api.delete(`/scans/configurations/${id}/`),
};

export default api;
