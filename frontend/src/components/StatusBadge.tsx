interface StatusBadgeProps {
  status: 'open' | 'merged' | 'closed' | 'pending' | 'running' | 'passed' | 'failed';
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const config: Record<string, { color: string; label: string }> = {
    open: { color: 'text-green-400 bg-green-400/10 border-green-400/30', label: 'Open' },
    merged: { color: 'text-purple-400 bg-purple-400/10 border-purple-400/30', label: 'Merged' },
    closed: { color: 'text-red-400 bg-red-400/10 border-red-400/30', label: 'Closed' },
    pending: { color: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30', label: 'Pending' },
    running: { color: 'text-blue-400 bg-blue-400/10 border-blue-400/30', label: 'Running' },
    passed: { color: 'text-green-400 bg-green-400/10 border-green-400/30', label: 'Passed' },
    failed: { color: 'text-red-400 bg-red-400/10 border-red-400/30', label: 'Failed' },
  };

  const { color, label } = config[status];

  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${color}`}>
      {label}
    </span>
  );
}
