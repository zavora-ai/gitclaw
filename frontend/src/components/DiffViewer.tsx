import { useState } from 'react';
import type { FileDiff, DiffHunk, DiffLine } from '../types/api';

interface DiffViewerProps {
  diffs: FileDiff[];
}

export function DiffViewer({ diffs }: DiffViewerProps) {
  const [expandedFiles, setExpandedFiles] = useState<Set<string>>(
    new Set(diffs.map((d) => d.path))
  );

  const toggleFile = (path: string) => {
    setExpandedFiles((prev) => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  };

  if (diffs.length === 0) {
    return (
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-8 text-center text-gray-400">
        No changes in this pull request
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {diffs.map((diff) => (
        <FileDiffView
          key={diff.path}
          diff={diff}
          expanded={expandedFiles.has(diff.path)}
          onToggle={() => toggleFile(diff.path)}
        />
      ))}
    </div>
  );
}

interface FileDiffViewProps {
  diff: FileDiff;
  expanded: boolean;
  onToggle: () => void;
}

function FileDiffView({ diff, expanded, onToggle }: FileDiffViewProps) {
  const statusColors: Record<string, string> = {
    added: 'text-green-400',
    modified: 'text-yellow-400',
    deleted: 'text-red-400',
    renamed: 'text-blue-400',
  };

  const statusLabels: Record<string, string> = {
    added: 'Added',
    modified: 'Modified',
    deleted: 'Deleted',
    renamed: 'Renamed',
  };

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-gray-700/50"
      >
        <div className="flex items-center gap-3">
          <ChevronIcon expanded={expanded} />
          <span className={`text-xs font-medium ${statusColors[diff.status]}`}>
            {statusLabels[diff.status]}
          </span>
          <span className="text-gray-300 font-mono text-sm">
            {diff.status === 'renamed' && diff.old_path
              ? `${diff.old_path} → ${diff.path}`
              : diff.path}
          </span>
        </div>
        <DiffStats hunks={diff.hunks} />
      </button>
      {expanded && (
        <div className="border-t border-gray-700">
          {diff.hunks.map((hunk, index) => (
            <HunkView key={index} hunk={hunk} />
          ))}
        </div>
      )}
    </div>
  );
}

interface DiffStatsProps {
  hunks: DiffHunk[];
}

function DiffStats({ hunks }: DiffStatsProps) {
  let additions = 0;
  let deletions = 0;

  for (const hunk of hunks) {
    for (const line of hunk.lines) {
      if (line.type === 'addition') additions++;
      if (line.type === 'deletion') deletions++;
    }
  }

  return (
    <div className="flex items-center gap-2 text-sm">
      {additions > 0 && <span className="text-green-400">+{additions}</span>}
      {deletions > 0 && <span className="text-red-400">-{deletions}</span>}
    </div>
  );
}

interface HunkViewProps {
  hunk: DiffHunk;
}

function HunkView({ hunk }: HunkViewProps) {
  return (
    <div className="font-mono text-sm">
      <div className="bg-gray-700/50 px-4 py-1 text-gray-400 text-xs">
        @@ -{hunk.old_start},{hunk.old_lines} +{hunk.new_start},{hunk.new_lines} @@
      </div>
      <div className="overflow-x-auto">
        {hunk.lines.map((line, index) => (
          <DiffLineView key={index} line={line} />
        ))}
      </div>
    </div>
  );
}

interface DiffLineViewProps {
  line: DiffLine;
}

function DiffLineView({ line }: DiffLineViewProps) {
  const bgColors: Record<string, string> = {
    addition: 'bg-green-900/30',
    deletion: 'bg-red-900/30',
    context: '',
  };

  const textColors: Record<string, string> = {
    addition: 'text-green-300',
    deletion: 'text-red-300',
    context: 'text-gray-300',
  };

  const prefixes: Record<string, string> = {
    addition: '+',
    deletion: '-',
    context: ' ',
  };

  return (
    <div className={`flex ${bgColors[line.type]}`}>
      <span className="select-none text-gray-600 text-right pr-2 pl-2 py-0.5 min-w-[3rem] border-r border-gray-700">
        {line.old_line ?? ''}
      </span>
      <span className="select-none text-gray-600 text-right pr-2 pl-2 py-0.5 min-w-[3rem] border-r border-gray-700">
        {line.new_line ?? ''}
      </span>
      <span className={`px-2 py-0.5 ${textColors[line.type]}`}>
        {prefixes[line.type]}
      </span>
      <span className={`py-0.5 flex-1 whitespace-pre ${textColors[line.type]}`}>
        {line.content}
      </span>
    </div>
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
