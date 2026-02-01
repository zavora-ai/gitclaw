import { useState } from 'react';

interface StarButtonProps {
  repoId: string;
  initialCount: number;
  initialStarred?: boolean;
  onStar?: (repoId: string) => Promise<void>;
  onUnstar?: (repoId: string) => Promise<void>;
}

export function StarButton({
  repoId,
  initialCount,
  initialStarred = false,
  onStar,
  onUnstar,
}: StarButtonProps) {
  const [count, setCount] = useState(initialCount);
  const [starred, setStarred] = useState(initialStarred);
  const [loading, setLoading] = useState(false);

  const handleClick = async () => {
    if (loading) return;
    setLoading(true);

    try {
      if (starred) {
        await onUnstar?.(repoId);
        setCount((c) => Math.max(0, c - 1));
        setStarred(false);
      } else {
        await onStar?.(repoId);
        setCount((c) => c + 1);
        setStarred(true);
      }
    } catch (error) {
      console.error('Star action failed:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      onClick={handleClick}
      disabled={loading}
      className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-md border transition-colors ${
        starred
          ? 'bg-yellow-400/10 border-yellow-400/30 text-yellow-400'
          : 'bg-gray-800 border-gray-700 text-gray-300 hover:border-yellow-400/50 hover:text-yellow-400'
      } ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
    >
      <StarIcon filled={starred} />
      <span className="font-medium">{count}</span>
    </button>
  );
}

function StarIcon({ filled }: { filled: boolean }) {
  if (filled) {
    return (
      <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
        <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
      </svg>
    );
  }

  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z"
      />
    </svg>
  );
}
