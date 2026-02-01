import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { StarButton } from '../components/StarButton';
import { CodeViewer } from '../components/CodeViewer';
import { FileTree } from '../components/FileTree';
import type { Repository, Commit } from '../types/api';
import type { TreeEntry } from '../services/api';
import * as api from '../services/api';

export function RepositoryBrowser() {
  const { owner, name } = useParams<{ owner: string; name: string }>();
  const [repo, setRepo] = useState<Repository | null>(null);
  const [branches, setBranches] = useState<string[]>([]);
  const [selectedBranch, setSelectedBranch] = useState<string>('');
  const [commits, setCommits] = useState<Commit[]>([]);
  const [tree, setTree] = useState<TreeEntry[]>([]);
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [fileContent, setFileContent] = useState<string | null>(null);
  const [expandedDirs, setExpandedDirs] = useState<Set<string>>(new Set());
  const [starCount, setStarCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<'code' | 'commits'>('code');

  useEffect(() => {
    if (!owner || !name) return;
    const ownerName: string = owner;
    const repoName: string = name;

    async function loadRepo() {
      setLoading(true);
      setError(null);

      try {
        const repoData = await api.getRepositoryByOwnerAndName(ownerName, repoName);
        setRepo(repoData);
        setStarCount(repoData.star_count ?? 0);

        const branchesData = await api.getRepositoryBranches(repoData.repo_id);
        setBranches(branchesData);
        setSelectedBranch(repoData.default_branch);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load repository');
      } finally {
        setLoading(false);
      }
    }

    loadRepo();
  }, [owner, name]);

  useEffect(() => {
    if (!repo || !selectedBranch) return;
    const currentRepo: Repository = repo;

    async function loadBranchData() {
      try {
        const [treeData, commitsData] = await Promise.all([
          api.getRepositoryTree(currentRepo.repo_id, undefined, selectedBranch),
          api.getRepositoryCommits(currentRepo.repo_id, selectedBranch),
        ]);
        setTree(treeData);
        setCommits(commitsData);
        setSelectedFile(null);
        setFileContent(null);
      } catch (err) {
        console.error('Failed to load branch data:', err);
      }
    }

    loadBranchData();
  }, [repo, selectedBranch]);

  const handleFileSelect = async (path: string) => {
    if (!repo) return;
    setSelectedFile(path);

    try {
      const content = await api.getRepositoryFile(repo.repo_id, path, selectedBranch);
      setFileContent(content);
    } catch (err) {
      console.error('Failed to load file:', err);
      setFileContent('// Failed to load file content');
    }
  };

  const handleDirectoryToggle = (path: string) => {
    setExpandedDirs((prev) => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  };

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center py-12">
          <div className="text-gray-400">Loading repository...</div>
        </div>
      </Layout>
    );
  }

  if (error || !repo) {
    return (
      <Layout>
        <div className="text-center py-12">
          <h1 className="text-2xl font-bold text-red-400 mb-2">Error</h1>
          <p className="text-gray-400">{error || 'Repository not found'}</p>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-6">
        {/* Repository Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold mb-1">
              <Link to={`/agents/${repo.owner_id}`} className="text-gray-400 hover:text-blue-400">
                {owner}
              </Link>
              <span className="text-gray-600 mx-2">/</span>
              <span className="text-white">{name}</span>
            </h1>
            {repo.description && (
              <p className="text-gray-400">{repo.description}</p>
            )}
          </div>
          <StarButton
            repoId={repo.repo_id}
            initialCount={starCount}
            onStar={api.starRepo}
            onUnstar={api.unstarRepo}
          />
        </div>

        {/* Branch Selector and View Tabs */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <BranchSelector
              branches={branches}
              selected={selectedBranch}
              onChange={setSelectedBranch}
            />
            <div className="flex rounded-lg border border-gray-700 overflow-hidden">
              <button
                onClick={() => setView('code')}
                className={`px-4 py-2 text-sm ${
                  view === 'code'
                    ? 'bg-gray-700 text-white'
                    : 'bg-gray-800 text-gray-400 hover:text-white'
                }`}
              >
                Code
              </button>
              <button
                onClick={() => setView('commits')}
                className={`px-4 py-2 text-sm ${
                  view === 'commits'
                    ? 'bg-gray-700 text-white'
                    : 'bg-gray-800 text-gray-400 hover:text-white'
                }`}
              >
                Commits
              </button>
            </div>
          </div>
          <Link
            to={`/repos/${owner}/${name}/pulls`}
            className="text-blue-400 hover:underline text-sm"
          >
            View Pull Requests →
          </Link>
        </div>

        {/* Content Area */}
        {view === 'code' ? (
          <div className="grid grid-cols-4 gap-6">
            {/* File Tree */}
            <div className="col-span-1 bg-gray-800 rounded-lg border border-gray-700 p-2 max-h-[600px] overflow-y-auto">
              <FileTree
                entries={tree}
                onFileSelect={handleFileSelect}
                selectedPath={selectedFile ?? undefined}
                onDirectoryToggle={handleDirectoryToggle}
                expandedDirs={expandedDirs}
              />
            </div>

            {/* Code Viewer */}
            <div className="col-span-3">
              {selectedFile && fileContent !== null ? (
                <CodeViewer content={fileContent} filename={selectedFile} />
              ) : (
                <div className="bg-gray-800 rounded-lg border border-gray-700 p-8 text-center text-gray-400">
                  Select a file to view its contents
                </div>
              )}
            </div>
          </div>
        ) : (
          <CommitHistory commits={commits} />
        )}
      </div>
    </Layout>
  );
}

interface BranchSelectorProps {
  branches: string[];
  selected: string;
  onChange: (branch: string) => void;
}

function BranchSelector({ branches, selected, onChange }: BranchSelectorProps) {
  const [open, setOpen] = useState(false);

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg hover:border-gray-600"
      >
        <BranchIcon />
        <span>{selected}</span>
        <ChevronDownIcon />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute top-full left-0 mt-1 w-48 bg-gray-800 border border-gray-700 rounded-lg shadow-lg z-20 max-h-64 overflow-y-auto">
            {branches.map((branch) => (
              <button
                key={branch}
                onClick={() => {
                  onChange(branch);
                  setOpen(false);
                }}
                className={`w-full text-left px-3 py-2 hover:bg-gray-700 ${
                  branch === selected ? 'text-blue-400' : 'text-gray-300'
                }`}
              >
                {branch}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

interface CommitHistoryProps {
  commits: Commit[];
}

function CommitHistory({ commits }: CommitHistoryProps) {
  if (commits.length === 0) {
    return (
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-8 text-center text-gray-400">
        No commits found
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {commits.map((commit, index) => (
        <div
          key={commit.sha}
          className="bg-gray-800 rounded-lg border border-gray-700 p-4 flex items-start gap-4"
        >
          <div className="flex flex-col items-center">
            <div className="w-3 h-3 rounded-full bg-blue-400" />
            {index < commits.length - 1 && (
              <div className="w-0.5 h-full bg-gray-700 mt-1" />
            )}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-white font-medium truncate">{commit.message}</p>
            <div className="flex items-center gap-3 text-sm text-gray-400 mt-1">
              <span className="font-mono text-xs bg-gray-700 px-2 py-0.5 rounded">
                {commit.sha.slice(0, 7)}
              </span>
              <span>{commit.author_name || commit.author_id.slice(0, 8)}</span>
              <span>{formatDate(commit.created_at)}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function BranchIcon() {
  return (
    <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M13 10V3L4 14h7v7l9-11h-7z"
      />
    </svg>
  );
}

function ChevronDownIcon() {
  return (
    <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
    </svg>
  );
}

function formatDate(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays === 0) return 'today';
  if (diffDays === 1) return 'yesterday';
  if (diffDays < 7) return `${diffDays} days ago`;
  if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
  return date.toLocaleDateString();
}
