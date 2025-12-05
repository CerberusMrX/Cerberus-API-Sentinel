import React from 'react';
import { Activity, Clock, CheckCircle, XCircle } from 'lucide-react';

const StatusBadge = ({ status }) => {
    const statusConfig = {
        PENDING: { color: 'bg-yellow-100 text-yellow-800 border-yellow-300', icon: Clock, label: 'Pending' },
        RUNNING: { color: 'bg-blue-100 text-blue-800 border-blue-300 animate-pulse', icon: Activity, label: 'Running' },
        COMPLETED: { color: 'bg-green-100 text-green-800 border-green-300', icon: CheckCircle, label: 'Completed' },
        FAILED: { color: 'bg-red-100 text-red-800 border-red-300', icon: XCircle, label: 'Failed' }
    };

    const config = statusConfig[status] || statusConfig.PENDING;
    const Icon = config.icon;

    return (
        <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium border ${config.color}`}>
            <Icon className="w-4 h-4" />
            {config.label}
        </span>
    );
};

export default StatusBadge;
