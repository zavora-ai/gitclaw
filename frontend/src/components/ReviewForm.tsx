import { useState } from 'react';

interface ReviewFormProps {
  onSubmit: (verdict: 'approve' | 'request_changes' | 'comment', body: string) => Promise<void>;
  disabled?: boolean;
}

export function ReviewForm({ onSubmit, disabled = false }: ReviewFormProps) {
  const [verdict, setVerdict] = useState<'approve' | 'request_changes' | 'comment'>('comment');
  const [body, setBody] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (submitting || disabled) return;

    setSubmitting(true);
    try {
      await onSubmit(verdict, body);
      setBody('');
      setVerdict('comment');
    } catch (error) {
      console.error('Failed to submit review:', error);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="bg-gray-800 rounded-lg border border-gray-700 p-4">
      <h3 className="text-lg font-semibold mb-4">Submit Review</h3>
      
      <div className="mb-4">
        <label className="block text-sm text-gray-400 mb-2">Review Comment</label>
        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          placeholder="Leave a comment..."
          rows={4}
          className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-gray-300 placeholder-gray-500 focus:outline-none focus:border-blue-500 resize-none"
          disabled={disabled || submitting}
        />
      </div>

      <div className="mb-4">
        <label className="block text-sm text-gray-400 mb-2">Verdict</label>
        <div className="flex gap-3">
          <VerdictButton
            selected={verdict === 'comment'}
            onClick={() => setVerdict('comment')}
            disabled={disabled || submitting}
          >
            <CommentIcon />
            Comment
          </VerdictButton>
          <VerdictButton
            selected={verdict === 'approve'}
            onClick={() => setVerdict('approve')}
            disabled={disabled || submitting}
            color="green"
          >
            <CheckIcon />
            Approve
          </VerdictButton>
          <VerdictButton
            selected={verdict === 'request_changes'}
            onClick={() => setVerdict('request_changes')}
            disabled={disabled || submitting}
            color="red"
          >
            <XIcon />
            Request Changes
          </VerdictButton>
        </div>
      </div>

      <button
        type="submit"
        disabled={disabled || submitting}
        className={`w-full py-2 px-4 rounded-lg font-medium transition-colors ${
          disabled || submitting
            ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
            : verdict === 'approve'
            ? 'bg-green-600 hover:bg-green-700 text-white'
            : verdict === 'request_changes'
            ? 'bg-red-600 hover:bg-red-700 text-white'
            : 'bg-blue-600 hover:bg-blue-700 text-white'
        }`}
      >
        {submitting ? 'Submitting...' : 'Submit Review'}
      </button>
    </form>
  );
}

interface VerdictButtonProps {
  selected: boolean;
  onClick: () => void;
  disabled?: boolean;
  color?: 'green' | 'red';
  children: React.ReactNode;
}

function VerdictButton({ selected, onClick, disabled, color, children }: VerdictButtonProps) {
  const baseClasses = 'flex items-center gap-2 px-3 py-2 rounded-lg border transition-colors';
  
  let colorClasses: string;
  if (selected) {
    if (color === 'green') {
      colorClasses = 'bg-green-600/20 border-green-500 text-green-400';
    } else if (color === 'red') {
      colorClasses = 'bg-red-600/20 border-red-500 text-red-400';
    } else {
      colorClasses = 'bg-blue-600/20 border-blue-500 text-blue-400';
    }
  } else {
    colorClasses = 'bg-gray-900 border-gray-700 text-gray-400 hover:border-gray-600';
  }

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`${baseClasses} ${colorClasses} ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
    >
      {children}
    </button>
  );
}

function CommentIcon() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
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
