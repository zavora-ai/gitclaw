// GitClaw Logo Component

interface GitClawLogoProps {
  size?: number;
  className?: string;
}

export function GitClawLogo({ size = 40, className = '' }: GitClawLogoProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 200 200"
      width={size}
      height={size}
      className={className}
    >
      <defs>
        <linearGradient id="clawGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" style={{ stopColor: '#3B82F6', stopOpacity: 1 }} />
          <stop offset="50%" style={{ stopColor: '#8B5CF6', stopOpacity: 1 }} />
          <stop offset="100%" style={{ stopColor: '#EC4899', stopOpacity: 1 }} />
        </linearGradient>
        <linearGradient id="bgGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" style={{ stopColor: '#1F2937', stopOpacity: 1 }} />
          <stop offset="100%" style={{ stopColor: '#111827', stopOpacity: 1 }} />
        </linearGradient>
      </defs>

      {/* Background circle */}
      <circle cx="100" cy="100" r="95" fill="url(#bgGradient)" stroke="url(#clawGradient)" strokeWidth="3" />

      {/* Git branch symbol (stylized) */}
      <g transform="translate(100, 100)">
        {/* Main vertical line */}
        <line x1="0" y1="-45" x2="0" y2="45" stroke="url(#clawGradient)" strokeWidth="6" strokeLinecap="round" />

        {/* Branch lines (claw shape) */}
        <line x1="0" y1="-20" x2="-35" y2="-50" stroke="url(#clawGradient)" strokeWidth="5" strokeLinecap="round" />
        <line x1="0" y1="-20" x2="35" y2="-50" stroke="url(#clawGradient)" strokeWidth="5" strokeLinecap="round" />

        {/* Merge lines (claw shape) */}
        <line x1="0" y1="20" x2="-30" y2="45" stroke="url(#clawGradient)" strokeWidth="5" strokeLinecap="round" />
        <line x1="0" y1="20" x2="30" y2="45" stroke="url(#clawGradient)" strokeWidth="5" strokeLinecap="round" />

        {/* Commit nodes */}
        <circle cx="0" cy="-45" r="8" fill="#3B82F6" />
        <circle cx="0" cy="-20" r="8" fill="#8B5CF6" />
        <circle cx="0" cy="20" r="8" fill="#A855F7" />
        <circle cx="0" cy="45" r="8" fill="#EC4899" />

        {/* Branch tip nodes (claw tips) */}
        <circle cx="-35" cy="-50" r="6" fill="#60A5FA" />
        <circle cx="35" cy="-50" r="6" fill="#60A5FA" />
        <circle cx="-30" cy="45" r="6" fill="#F472B6" />
        <circle cx="30" cy="45" r="6" fill="#F472B6" />
      </g>

      {/* AI circuit pattern accent */}
      <g opacity="0.3">
        <circle cx="40" cy="60" r="3" fill="#3B82F6" />
        <circle cx="160" cy="60" r="3" fill="#EC4899" />
        <circle cx="40" cy="140" r="3" fill="#8B5CF6" />
        <circle cx="160" cy="140" r="3" fill="#A855F7" />
        <line x1="40" y1="60" x2="55" y2="75" stroke="#3B82F6" strokeWidth="1" />
        <line x1="160" y1="60" x2="145" y2="75" stroke="#EC4899" strokeWidth="1" />
        <line x1="40" y1="140" x2="55" y2="125" stroke="#8B5CF6" strokeWidth="1" />
        <line x1="160" y1="140" x2="145" y2="125" stroke="#A855F7" strokeWidth="1" />
      </g>
    </svg>
  );
}
