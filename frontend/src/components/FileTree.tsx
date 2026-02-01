import type { TreeEntry } from '../services/api';

interface FileTreeProps {
  entries: TreeEntry[];
  onFileSelect: (path: string) => void;
  selectedPath?: string;
  onDirectoryToggle?: (path: string) => void;
  expandedDirs?: Set<string>;
}

export function FileTree({
  entries,
  onFileSelect,
  selectedPath,
  onDirectoryToggle,
  expandedDirs = new Set(),
}: FileTreeProps) {
  // Group entries by parent directory
  const rootEntries = entries.filter((e) => !e.path.includes('/'));

  return (
    <div className="text-sm">
      {rootEntries.map((entry) => (
        <FileTreeNode
          key={entry.path}
          entry={entry}
          allEntries={entries}
          onFileSelect={onFileSelect}
          selectedPath={selectedPath}
          onDirectoryToggle={onDirectoryToggle}
          expandedDirs={expandedDirs}
          depth={0}
        />
      ))}
    </div>
  );
}

interface FileTreeNodeProps {
  entry: TreeEntry;
  allEntries: TreeEntry[];
  onFileSelect: (path: string) => void;
  selectedPath?: string;
  onDirectoryToggle?: (path: string) => void;
  expandedDirs: Set<string>;
  depth: number;
}

function FileTreeNode({
  entry,
  allEntries,
  onFileSelect,
  selectedPath,
  onDirectoryToggle,
  expandedDirs,
  depth,
}: FileTreeNodeProps) {
  const isExpanded = expandedDirs.has(entry.path);
  const isSelected = selectedPath === entry.path;
  const isDirectory = entry.type === 'directory';

  const childEntries = allEntries.filter(
    (e) =>
      e.path.startsWith(entry.path + '/') &&
      !e.path.slice(entry.path.length + 1).includes('/')
  );

  const handleClick = () => {
    if (isDirectory) {
      onDirectoryToggle?.(entry.path);
    } else {
      onFileSelect(entry.path);
    }
  };

  return (
    <div>
      <button
        onClick={handleClick}
        className={`w-full text-left px-2 py-1 flex items-center gap-2 hover:bg-gray-800 rounded ${
          isSelected ? 'bg-gray-800 text-blue-400' : 'text-gray-300'
        }`}
        style={{ paddingLeft: `${depth * 16 + 8}px` }}
      >
        {isDirectory ? (
          <ChevronIcon expanded={isExpanded} />
        ) : (
          <span className="w-4" />
        )}
        {isDirectory ? <FolderIcon open={isExpanded} /> : <FileIcon name={entry.name} />}
        <span className="truncate">{entry.name}</span>
      </button>
      {isDirectory && isExpanded && (
        <div>
          {childEntries.map((child) => (
            <FileTreeNode
              key={child.path}
              entry={child}
              allEntries={allEntries}
              onFileSelect={onFileSelect}
              selectedPath={selectedPath}
              onDirectoryToggle={onDirectoryToggle}
              expandedDirs={expandedDirs}
              depth={depth + 1}
            />
          ))}
        </div>
      )}
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

function FolderIcon({ open }: { open: boolean }) {
  if (open) {
    return (
      <svg className="w-4 h-4 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
        <path
          fillRule="evenodd"
          d="M2 6a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1H8a3 3 0 00-3 3v1.5a1.5 1.5 0 01-3 0V6z"
          clipRule="evenodd"
        />
        <path d="M6 12a2 2 0 012-2h8a2 2 0 012 2v2a2 2 0 01-2 2H2h2a2 2 0 002-2v-2z" />
      </svg>
    );
  }
  return (
    <svg className="w-4 h-4 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
      <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
    </svg>
  );
}

function FileIcon({ name }: { name: string }) {
  const ext = name.split('.').pop()?.toLowerCase() || '';
  
  const iconColors: Record<string, string> = {
    ts: 'text-blue-400',
    tsx: 'text-blue-400',
    js: 'text-yellow-400',
    jsx: 'text-yellow-400',
    rs: 'text-orange-400',
    py: 'text-green-400',
    go: 'text-cyan-400',
    md: 'text-gray-400',
    json: 'text-yellow-300',
    toml: 'text-gray-400',
    yaml: 'text-pink-400',
    yml: 'text-pink-400',
    sql: 'text-blue-300',
  };

  const color = iconColors[ext] || 'text-gray-400';

  return (
    <svg className={`w-4 h-4 ${color}`} fill="currentColor" viewBox="0 0 20 20">
      <path
        fillRule="evenodd"
        d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z"
        clipRule="evenodd"
      />
    </svg>
  );
}
