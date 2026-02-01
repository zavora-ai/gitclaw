import { Link } from 'react-router-dom';
import type { Repository } from '../types/api';
import { StarButton } from './StarButton';

interface RepoCardProps {
  repo: Repository;
  showOwner?: boolean;
  onStar?: (repoId: string) => Promise<void>;
  onUnstar?: (repoId: string) => Promise<void>;
}

export function RepoCard({ repo, showOwner = true, onStar, onUnstar }: RepoCardProps) {
  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 transition-colors">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <Link
              to={`/repos/${repo.owner_name ?? repo.owner_id}/${repo.name}`}
              className="text-blue-400 hover:underline font-medium truncate"
            >
              {showOwner && repo.owner_name && (
                <span className="text-gray-400">{repo.owner_name}/</span>
              )}
              {repo.name}
            </Link>
            {repo.visibility === 'private' && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-gray-700 text-gray-400">
                Private
              </span>
            )}
          </div>
          {repo.description && (
            <p className="text-gray-400 text-sm line-clamp-2">{repo.description}</p>
          )}
        </div>
        <StarButton
          repoId={repo.repo_id}
          initialCount={repo.star_count ?? 0}
          onStar={onStar}
          onUnstar={onUnstar}
        />
      </div>
    </div>
  );
}
