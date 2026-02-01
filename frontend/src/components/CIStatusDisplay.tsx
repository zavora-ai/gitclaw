import { useState } from 'react';
import type { CILog } from '../types/api';

interface CIStatusDisplayProps {
  status: 'pending' | 'running' | 'passed' | 'failed';
  logs: CILog[];
}

export function CIStatusDisplay({ status, logs }: CIStatusDisplayProps) {
  const [expanded, setExpanded] = useState(false);

  const statusConfig: Record<string, { color: string; icon: React.ReactNode; label: string }> = {
    pending: {
      color: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
      icon: <ClockIcon />,
      label: 'CI Pending',
    },
    running: {
      color: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
      icon: <SpinnerIcon />,
      label: 'CI Running',
    },
    passed: {
      color: 'text-green-400 bg-green-400/10 border-green-400/30',
      icon: <CheckIcon />,
      label: 'CI Passed',
    },
    failed: {
      color: 'text-red-400 bg-red-400/10 border-red-400/30',
      icon: <XIcon />,
      label: 'CI Failed',
    },
  };

  const config = statusConfig[status];

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className={`w-full flex items-center justify-between px-4 py-3 hover:bg-gray-700/50`}
      >
        <div className="flex items-center gap-3">
          <div className={`p-1.5 rounded-full border ${config.color}`}>
            {config.icon}
          </div>
          <span className="font-medium">{config.label}</span>
        </div>
        <ChevronIcon expanded={expanded} />
      </button>
      {expanded && logs.length > 0 && (
        <div className="border-t border-gray-700">
          {logs.map((log, index) => (
            <CILogStep key={index} log={log} />
          ))}
        </div>
      )}
    </div>
  );
}

interface CILogStepProps {
  log: CILog;
}

function CILogStep({ log }: CILogStepProps) {
  const [expanded, setExpanded] = useState(log.status === 'failed');

  const statusIcons: Record<string, React.ReactNode> = {
    pending: <ClockIcon />,
    running: <SpinnerIcon />,
    passed: <CheckIcon />,
    failed: <XIcon />,
  };

  const statusColors: Record<string, string> = {
    pending: 'text-yellow-400',
    running: 'text-blue-400',
    passed: 'text-green-400',
    failed: 'text-red-400',
  };

  return (
    <div className="border-b border-gray-700 last:border-b-0">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-2 hover:bg-gray-700/30"
      >
        <div className="flex items-center gap-3">
          <span className={statusColors[log.status]}>{statusIcons[log.status]}</span>
          <span className="text-gray-300">{log.step}</span>
        </div>
        {log.finished_at && log.started_at && (
          <span className="text-gray-500 text-sm">
            {formatDuration(log.started_at, log.finished_at)}
          </span>
        )}
      </button>
      {expanded && log.output && (
        <div className="bg-gray-900 px-4 py-3 font-mono text-sm text-gray-300 whitespace-pre-wrap overflow-x-auto max-h-64 overflow-y-auto">
          {log.output}
        </div>
      )}
    </div>
  );
}

function formatDuration(start: string, end: string): string {
  const startTime = new Date(start).getTime();
  const endTime = new Date(end).getTime();
  const durationMs = endTime - startTime;

  if (durationMs < 1000) return `${durationMs}ms`;
  if (durationMs < 60000) return `${(durationMs / 1000).toFixed(1)}s`;
  return `${Math.floor(durationMs / 60000)}m ${Math.floor((durationMs % 60000) / 1000)}s`;
}

function ClockIcon() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
      />
    </svg>
  );
}

function SpinnerIcon() {
  return (
    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
    </svg>
  );
}

function XIcon() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}

function ChevronIcon({ expanded }: { expanded: boolean }) {
  return (
    <svg
      className={`w-4 h-4 text-gray-500 transition-transform ${expanded ? 'rotate-90' : ''}`}
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
    </svg>
  );
}
