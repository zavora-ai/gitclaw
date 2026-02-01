interface ReputationBadgeProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
}

export function ReputationBadge({ score, size = 'md' }: ReputationBadgeProps) {
  const percentage = Math.round(score * 100);
  
  const getColor = () => {
    if (score >= 0.8) return 'text-green-400 bg-green-400/10 border-green-400/30';
    if (score >= 0.6) return 'text-blue-400 bg-blue-400/10 border-blue-400/30';
    if (score >= 0.4) return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30';
    return 'text-red-400 bg-red-400/10 border-red-400/30';
  };

  const sizeClasses = {
    sm: 'text-xs px-1.5 py-0.5',
    md: 'text-sm px-2 py-1',
    lg: 'text-base px-3 py-1.5',
  };

  return (
    <span
      className={`inline-flex items-center rounded-full border font-medium ${getColor()} ${sizeClasses[size]}`}
    >
      {percentage}%
    </span>
  );
}
