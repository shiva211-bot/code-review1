import { executeTrueStaticAnalysis } from '../staticEngine';

export interface ExternalBenchmarkCase {
  id: string;
  source: 'OWASP_BENCHMARK' | 'SECURIBENCH_JS' | 'NODEGOAT' | 'SANS_CWE_TOP25';
  cwe: string;
  name: string;
  expectedVulnerable: boolean;
  description: string;
  code: string;
}

export interface ExternalBenchmarkResult {
  benchmarkId: string;
  name: string;
  source: ExternalBenchmarkCase['source'];
  cwe: string;
  expectedVulnerable: boolean;
  actualVulnerable: boolean;
  classification: 'TP' | 'TN' | 'FP' | 'FN';
  passed: boolean;
  findingsCount: number;
  durationMs: number;
}

export interface ExternalBenchmarkReport {
  timestamp: string;
  totalBenchmarks: number;
  truePositives: number;
  trueNegatives: number;
  falsePositives: number;
  falseNegatives: number;
  precisionPercent: number;
  recallPercent: number;
  specificityPercent: number;
  accuracyPercent: number;
  f1Score: number;
  durationMs: number;
  results: ExternalBenchmarkResult[];
}

export const EXTERNAL_BENCHMARKS: ExternalBenchmarkCase[] = [
  // =========================================================================
  // OWASP Benchmark Adapted JS Suite: CWE-89 (SQL Injection)
  // =========================================================================
  {
    id: 'OWASP-JS-SQLI-001',
    source: 'OWASP_BENCHMARK',
    cwe: 'CWE-89',
    name: 'OWASP-JS-001: Unescaped query string parameter in database query',
    expectedVulnerable: true,
    description: 'Direct string concatenation of HTTP query parameter into SQL query string.',
    code: `const username = req.query.name;
const query = 'SELECT * FROM users WHERE name = \\'' + username + '\\'';
await db.query(query);`,
  },
  {
    id: 'OWASP-JS-SQLI-002',
    source: 'OWASP_BENCHMARK',
    cwe: 'CWE-89',
    name: 'OWASP-JS-002: Prepared statement with positional bind parameters (Safe)',
    expectedVulnerable: false,
    description: 'Safe prepared statement utilizing query parameter binding array.',
    code: `const username = req.query.name;
const query = 'SELECT * FROM users WHERE name = ?';
await db.query(query, [username]);`,
  },
  {
    id: 'OWASP-JS-SQLI-003',
    source: 'OWASP_BENCHMARK',
    cwe: 'CWE-89',
    name: 'OWASP-JS-003: Postgres dollar parameter placeholders (Safe)',
    expectedVulnerable: false,
    description: 'PostgreSQL-style parameterized query with $1 parameter placeholder.',
    code: `const id = req.body.id;
await db.query('SELECT * FROM accounts WHERE id = $1', [id]);`,
  },
  {
    id: 'OWASP-JS-SQLI-004',
    source: 'OWASP_BENCHMARK',
    cwe: 'CWE-89',
    name: 'OWASP-JS-004: Multi-hop variable assignment with SQL concatenation',
    expectedVulnerable: true,
    description: 'Untrusted input assigned across intermediate local variables before SQL execution.',
    code: `const raw = req.body.username;
const processed = raw;
const target = processed;
const sql = 'SELECT * FROM users WHERE username = \\'' + target + '\\'';
await db.query(sql);`,
  },
  {
    id: 'OWASP-JS-SQLI-005',
    source: 'OWASP_BENCHMARK',
    cwe: 'CWE-89',
    name: 'OWASP-JS-005: Explicit numeric cast neutralization with query parameter (Safe)',
    expectedVulnerable: false,
    description: 'Numeric coercion via parseInt with parameterized binding eliminates SQL injection threat.',
    code: `const rawId = req.query.id;
const cleanId = parseInt(rawId, 10);
await db.query('SELECT * FROM items WHERE id = ?', [cleanId]);`,
  },

  // =========================================================================
  // Securibench-JS Adapted: CWE-95 / CWE-78 (Code & Command Injection)
  // =========================================================================
  {
    id: 'SECURIBENCH-JS-EVAL-001',
    source: 'SECURIBENCH_JS',
    cwe: 'CWE-95',
    name: 'Securibench-JS: Untrusted input in eval() sink',
    expectedVulnerable: true,
    description: 'User-provided script executed directly via global eval function.',
    code: `const code = req.body.expression;
eval('var result = ' + code);`,
  },
  {
    id: 'SECURIBENCH-JS-EVAL-002',
    source: 'SECURIBENCH_JS',
    cwe: 'CWE-95',
    name: 'Securibench-JS: Safe JSON.parse parser alternative (Safe)',
    expectedVulnerable: false,
    description: 'Structured JSON parser without dynamic code evaluation sink.',
    code: `const rawPayload = req.body.data;
const parsed = JSON.parse(rawPayload);
console.log(parsed.id);`,
  },
  {
    id: 'SECURIBENCH-JS-CMD-001',
    source: 'SECURIBENCH_JS',
    cwe: 'CWE-78',
    name: 'Securibench-JS: exec() shell command string interpolation',
    expectedVulnerable: true,
    description: 'Shell execution sink receives unvalidated host parameter.',
    code: `const host = req.query.host;
exec('ping -c 1 ' + host);`,
  },
  {
    id: 'SECURIBENCH-JS-CMD-002',
    source: 'SECURIBENCH_JS',
    cwe: 'CWE-78',
    name: 'Securibench-JS: execFile with argument array without shell (Safe)',
    expectedVulnerable: false,
    description: 'execFile passing discrete arguments avoids shell expansion.',
    code: `const host = req.query.host;
execFile('/bin/ping', ['-c', '1', host]);`,
  },

  // =========================================================================
  // NodeGoat Adapted: CWE-22 (Path Traversal) & CWE-79 (XSS)
  // =========================================================================
  {
    id: 'NODEGOAT-PATH-001',
    source: 'NODEGOAT',
    cwe: 'CWE-22',
    name: 'NodeGoat: Path traversal via unvalidated path concatenation',
    expectedVulnerable: true,
    description: 'Arbitrary file system access via unvalidated user directory path.',
    code: `const filename = req.query.file;
const targetPath = '/var/data/uploads/' + filename;
const data = fs.readFileSync(targetPath);`,
  },
  {
    id: 'NODEGOAT-PATH-002',
    source: 'NODEGOAT',
    cwe: 'CWE-22',
    name: 'NodeGoat: Safe path resolution with basename extraction (Safe)',
    expectedVulnerable: false,
    description: 'Path basename sanitizer prevents directory traversal escape.',
    code: `const raw = req.query.file;
const safeName = path.basename(raw);
const safePath = path.join('/var/data/uploads', safeName);
const content = fs.readFileSync(safePath);`,
  },
  {
    id: 'NODEGOAT-XSS-001',
    source: 'NODEGOAT',
    cwe: 'CWE-79',
    name: 'NodeGoat: Reflected cross-site scripting in response body',
    expectedVulnerable: true,
    description: 'Raw query parameter interpolated into HTML response without encoding.',
    code: `const name = req.query.name;
res.send('<h1>Welcome ' + name + '</h1>');`,
  },
  {
    id: 'NODEGOAT-XSS-002',
    source: 'NODEGOAT',
    cwe: 'CWE-79',
    name: 'NodeGoat: HTML entity escaping neutralizes reflected XSS (Safe)',
    expectedVulnerable: false,
    description: 'escapeHtml neutralizes markup characters before rendering into response.',
    code: `const name = req.query.name;
const safeName = escapeHtml(name);
res.send('<h1>Welcome ' + safeName + '</h1>');`,
  },

  // =========================================================================
  // SANS CWE Top 25: Advanced Interprocedural & Architectural Patterns
  // =========================================================================
  {
    id: 'SANS-TOP25-INTERPROC-001',
    source: 'SANS_CWE_TOP25',
    cwe: 'CWE-89',
    name: 'SANS Top 25: Multi-layer DAO pattern with tainted query builder',
    expectedVulnerable: true,
    description: 'Service calls Repository helper which concatenates untrusted filter.',
    code: `function buildFilter(val) {
  return 'WHERE email = \\'' + val + '\\'';
}
function executeSearch(queryFilter) {
  return db.query('SELECT * FROM users ' + queryFilter);
}
const email = req.query.email;
const filter = buildFilter(email);
await executeSearch(filter);`,
  },
  {
    id: 'SANS-TOP25-INTERPROC-002',
    source: 'SANS_CWE_TOP25',
    cwe: 'CWE-89',
    name: 'SANS Top 25: Multi-layer DAO with bound parameterized inputs (Safe)',
    expectedVulnerable: false,
    description: 'Multi-layer query passes query template and bind parameters separately.',
    code: `function buildSafeQuery() {
  return 'SELECT * FROM users WHERE email = ?';
}
function executeSafe(sql, params) {
  return db.query(sql, params);
}
const email = req.query.email;
await executeSafe(buildSafeQuery(), [email]);`,
  },
  {
    id: 'SANS-TOP25-INTERPROC-003',
    source: 'SANS_CWE_TOP25',
    cwe: 'CWE-95',
    name: 'SANS Top 25: Higher-order callback executing untrusted string in setTimeout',
    expectedVulnerable: true,
    description: 'setTimeout with untrusted string argument acts as implicit code execution sink.',
    code: `function scheduleTask(callbackStr) {
  setTimeout(callbackStr, 100);
}
const script = req.query.action;
scheduleTask(script);`,
  },
  {
    id: 'SANS-TOP25-INTERPROC-004',
    source: 'SANS_CWE_TOP25',
    cwe: 'CWE-95',
    name: 'SANS Top 25: Higher-order callback using function reference (Safe)',
    expectedVulnerable: false,
    description: 'setTimeout with function closure rather than string avoids dynamic execution.',
    code: `function scheduleSafe(id) {
  setTimeout(() => {
    console.log('Processing item ' + id);
  }, 100);
}
scheduleSafe(req.query.id);`,
  },
];

export function runExternalBenchmarkSuite(): ExternalBenchmarkReport {
  const startTime = performance.now();
  const results: ExternalBenchmarkResult[] = [];

  let tp = 0;
  let tn = 0;
  let fp = 0;
  let fn = 0;

  for (const b of EXTERNAL_BENCHMARKS) {
    const testStart = performance.now();
    const { analysis, engineData } = executeTrueStaticAnalysis(b.code, 'javascript', `${b.id}.js`);
    const durationMs = Number((performance.now() - testStart).toFixed(2));

    // Determine if analyzer flagged vulnerability
    // Check security findings and taint traces
    const hasSecurityVuln = analysis.findings.some(f => 
      f.category === 'security' && (f.severity === 'critical' || f.severity === 'high')
    ) || (engineData.taintVulnerabilities.length > 0) || (
      engineData.interproceduralVulnerabilities && 
      engineData.interproceduralVulnerabilities.some(ipv => !ipv.sanitized)
    );

    const actualVulnerable = Boolean(hasSecurityVuln);
    const expected = b.expectedVulnerable;

    let classification: 'TP' | 'TN' | 'FP' | 'FN';
    if (expected && actualVulnerable) {
      classification = 'TP';
      tp++;
    } else if (!expected && !actualVulnerable) {
      classification = 'TN';
      tn++;
    } else if (!expected && actualVulnerable) {
      classification = 'FP';
      fp++;
    } else {
      classification = 'FN';
      fn++;
    }

    const passed = classification === 'TP' || classification === 'TN';

    results.push({
      benchmarkId: b.id,
      name: b.name,
      source: b.source,
      cwe: b.cwe,
      expectedVulnerable: expected,
      actualVulnerable,
      classification,
      passed,
      findingsCount: analysis.findings.length,
      durationMs,
    });
  }

  const durationMs = Number((performance.now() - startTime).toFixed(2));
  const total = EXTERNAL_BENCHMARKS.length;

  const precision = (tp + fp) > 0 ? (tp / (tp + fp)) * 100 : 100;
  const recall = (tp + fn) > 0 ? (tp / (tp + fn)) * 100 : 100;
  const specificity = (tn + fp) > 0 ? (tn / (tn + fp)) * 100 : 100;
  const accuracy = total > 0 ? ((tp + tn) / total) * 100 : 100;
  const f1 = (precision + recall) > 0 ? (2 * (precision * recall)) / (precision + recall) : 100;

  return {
    timestamp: new Date().toISOString(),
    totalBenchmarks: total,
    truePositives: tp,
    trueNegatives: tn,
    falsePositives: fp,
    falseNegatives: fn,
    precisionPercent: Number(precision.toFixed(1)),
    recallPercent: Number(recall.toFixed(1)),
    specificityPercent: Number(specificity.toFixed(1)),
    accuracyPercent: Number(accuracy.toFixed(1)),
    f1Score: Number((f1 / 100).toFixed(3)),
    durationMs,
    results,
  };
}
