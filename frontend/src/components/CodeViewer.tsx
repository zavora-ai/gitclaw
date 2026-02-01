interface CodeViewerProps {
  content: string;
  filename: string;
  language?: string;
}

export function CodeViewer({ content, filename, language }: CodeViewerProps) {
  const lines = content.split('\n');
  const detectedLang = language || detectLanguage(filename);

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700">
        <span className="text-sm text-gray-300">{filename}</span>
        <span className="text-xs text-gray-500">{lines.length} lines</span>
      </div>
      <div className="overflow-x-auto">
        <pre className="text-sm">
          <code>
            {lines.map((line, index) => (
              <div key={index} className="flex hover:bg-gray-800/50">
                <span className="select-none text-gray-600 text-right pr-4 pl-4 py-0.5 min-w-[3rem] border-r border-gray-800">
                  {index + 1}
                </span>
                <span className={`pl-4 py-0.5 flex-1 ${getLineClass(line, detectedLang)}`}>
                  {highlightLine(line, detectedLang)}
                </span>
              </div>
            ))}
          </code>
        </pre>
      </div>
    </div>
  );
}

function detectLanguage(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase() || '';
  const langMap: Record<string, string> = {
    ts: 'typescript',
    tsx: 'typescript',
    js: 'javascript',
    jsx: 'javascript',
    rs: 'rust',
    py: 'python',
    go: 'go',
    java: 'java',
    c: 'c',
    cpp: 'cpp',
    h: 'c',
    hpp: 'cpp',
    md: 'markdown',
    json: 'json',
    yaml: 'yaml',
    yml: 'yaml',
    toml: 'toml',
    sql: 'sql',
    sh: 'bash',
    bash: 'bash',
    css: 'css',
    html: 'html',
  };
  return langMap[ext] || 'text';
}

function getLineClass(line: string, lang: string): string {
  const trimmed = line.trim();
  
  // Comments
  if (isComment(trimmed, lang)) {
    return 'text-gray-500';
  }
  
  return 'text-gray-300';
}

function isComment(line: string, lang: string): boolean {
  const singleLineComments: Record<string, string[]> = {
    typescript: ['//', '/*', '*', '*/'],
    javascript: ['//', '/*', '*', '*/'],
    rust: ['//', '/*', '*', '*/'],
    python: ['#'],
    go: ['//', '/*', '*', '*/'],
    java: ['//', '/*', '*', '*/'],
    c: ['//', '/*', '*', '*/'],
    cpp: ['//', '/*', '*', '*/'],
    bash: ['#'],
    yaml: ['#'],
    toml: ['#'],
    sql: ['--'],
  };

  const prefixes = singleLineComments[lang] || [];
  return prefixes.some((prefix) => line.startsWith(prefix));
}

function highlightLine(line: string, lang: string): React.ReactNode {
  // Simple keyword highlighting
  const keywords: Record<string, string[]> = {
    typescript: ['const', 'let', 'var', 'function', 'class', 'interface', 'type', 'import', 'export', 'from', 'return', 'if', 'else', 'for', 'while', 'async', 'await', 'new', 'this', 'extends', 'implements'],
    javascript: ['const', 'let', 'var', 'function', 'class', 'import', 'export', 'from', 'return', 'if', 'else', 'for', 'while', 'async', 'await', 'new', 'this', 'extends'],
    rust: ['fn', 'let', 'mut', 'const', 'struct', 'enum', 'impl', 'trait', 'pub', 'use', 'mod', 'return', 'if', 'else', 'for', 'while', 'loop', 'match', 'async', 'await', 'self', 'Self', 'where'],
    python: ['def', 'class', 'import', 'from', 'return', 'if', 'elif', 'else', 'for', 'while', 'try', 'except', 'finally', 'with', 'as', 'async', 'await', 'self', 'None', 'True', 'False'],
    go: ['func', 'var', 'const', 'type', 'struct', 'interface', 'import', 'package', 'return', 'if', 'else', 'for', 'range', 'switch', 'case', 'default', 'go', 'defer', 'chan'],
  };

  const langKeywords = keywords[lang] || [];
  if (langKeywords.length === 0) return line;

  // Simple regex-based highlighting
  const parts: React.ReactNode[] = [];
  let key = 0;

  // Match strings
  const stringRegex = /(["'`])(?:(?!\1)[^\\]|\\.)*\1/g;
  let lastIndex = 0;
  let match;

  while ((match = stringRegex.exec(line)) !== null) {
    if (match.index > lastIndex) {
      parts.push(
        <span key={key++}>
          {highlightKeywords(line.slice(lastIndex, match.index), langKeywords)}
        </span>
      );
    }
    parts.push(
      <span key={key++} className="text-green-400">
        {match[0]}
      </span>
    );
    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < line.length) {
    parts.push(
      <span key={key++}>
        {highlightKeywords(line.slice(lastIndex), langKeywords)}
      </span>
    );
  }

  return parts.length > 0 ? parts : highlightKeywords(line, langKeywords);
}

function highlightKeywords(text: string, keywords: string[]): React.ReactNode {
  if (keywords.length === 0) return text;

  const pattern = new RegExp(`\\b(${keywords.join('|')})\\b`, 'g');
  const parts: React.ReactNode[] = [];
  let lastIndex = 0;
  let match;
  let key = 0;

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(<span key={key++}>{text.slice(lastIndex, match.index)}</span>);
    }
    parts.push(
      <span key={key++} className="text-purple-400">
        {match[0]}
      </span>
    );
    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < text.length) {
    parts.push(<span key={key++}>{text.slice(lastIndex)}</span>);
  }

  return parts.length > 0 ? parts : text;
}
