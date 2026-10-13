import { executeTrueStaticAnalysis } from '../staticEngine';
import { runFlowSensitiveInterproceduralAnalysis } from '../interprocedural/interproceduralTaint';
import { parseSourceCode } from '../ast/parser';
import { joinAbstractValues, isAbstractStateEqual } from '../interprocedural/interproceduralTaint';

export interface SoundnessCheckResult {
  checkId: string;
  name: string;
  principle: 'CONSERVATIVE_APPROXIMATION' | 'MONOTONICITY' | 'SOUND_CONSTANT_JOIN' | 'BRANCH_ISOLATION' | 'THREAT_SPECIFICITY' | 'UNRESOLVED_FLOW_BOUNDING';
  passed: boolean;
  expectedBehavior: string;
  observedBehavior: string;
  evidence: Record<string, any>;
}

export interface SoundnessVerificationReport {
  timestamp: string;
  totalChecks: number;
  passedChecks: number;
  failedChecks: number;
  soundnessChecksPassed: boolean;
  /**
   * @deprecated Legacy alias for soundnessChecksPassed.
   */
  soundnessGuaranteed: boolean;
  qualificationNote: string;
  durationMs: number;
  checks: SoundnessCheckResult[];
}

/**
 * Formal Soundness Verification Suite
 * 
 * Verifies that the static analysis engine adheres to formal abstract interpretation
 * soundness principles, specifically:
 * 1. Conservative Incomplete Analysis: When iteration budget is exhausted, safety is NEVER inferred.
 * 2. Conservative File-Level Risk: File-level risk estimate cannot be 'LOW' when analysis is incomplete.
 * 3. Incomplete Analysis Finding Injection: An explicit INCOMPLETE_ANALYSIS finding is present.
 * 4. Taint Join Monotonicity: Joining any state with TAINTED yields TAINTED.
 * 5. Constant Join Soundness: Joining two differing constants yields UNKNOWN (never a specific constant).
 * 6. Branch-Return Isolation: Returning branches cannot leak variables into post-if merge.
 * 7. Threat-Specific Sanitization: HTML sanitizer cannot neutralize SQL injection.
 */
export function runSoundnessVerificationSuite(): SoundnessVerificationReport {
  const startTime = performance.now();
  const checks: SoundnessCheckResult[] = [];

  // -------------------------------------------------------------------------
  // Check 1: Resource-Limited Analysis Yields Inconclusive (Never Safe)
  // -------------------------------------------------------------------------
  {
    const deeplyRecursiveCode = `
      function deepRec(n, tainted) {
        if (n <= 0) return tainted;
        return deepRec(n - 1, deepRec(n - 2, tainted));
      }
      const data = req.query.val;
      const res = deepRec(10, data);
    `;
    const ast = parseSourceCode(deeplyRecursiveCode, 'recursive_limit.js').ast;
    // Force a tight iteration budget of 1 to ensure resource exhaustion
    const result = runFlowSensitiveInterproceduralAnalysis(ast, 'recursive_limit.js', { maxIterations: 1 });
    
    const passed = result.status === 'resource_limit_exceeded' && !result.converged;
    checks.push({
      checkId: 'SND-01-RESOURCE-LIMIT-STATUS',
      name: 'Resource Budget Limit Flags resource_limit_exceeded',
      principle: 'CONSERVATIVE_APPROXIMATION',
      passed,
      expectedBehavior: "Status must be 'resource_limit_exceeded' and converged must be false",
      observedBehavior: `Status: '${result.status}', converged: ${result.converged}, iterations: ${result.iterations}`,
      evidence: { status: result.status, converged: result.converged, iterations: result.iterations },
    });
  }

  // -------------------------------------------------------------------------
  // Check 2: File-Level Downstream Consumer Never Reports 'LOW' Risk When Incomplete
  // -------------------------------------------------------------------------
  {
    // A program where no obvious AST rule violations exist, but bounded interprocedural analysis exceeds budget
    const boundedCode = `
      function mutualA(n, x) {
        if (n <= 0) return x;
        return mutualB(n - 1, x);
      }
      function mutualB(n, x) {
        if (n <= 0) return x;
        return mutualA(n - 1, x);
      }
      const input = req.query.q;
      const out = mutualA(5, input);
    `;
    // Explicitly restrict iteration budget to 1 to force resource exhaustion
    const { analysis } = executeTrueStaticAnalysis(boundedCode, 'javascript', 'bounded_file.js', { maxIterations: 1 });
    
    // In our engine, when analysis is incomplete due to resource exhaustion,
    // the file-level risk estimate must NEVER evaluate to 'LOW' -> must be 'INCONCLUSIVE'
    const passed = analysis.isInconclusive === true && analysis.metrics.staticRiskEstimate === 'INCONCLUSIVE';
    checks.push({
      checkId: 'SND-02-CONSERVATIVE-RISK-BOUND',
      name: 'Absence of Findings Under Incomplete Analysis Never Yields LOW Risk',
      principle: 'CONSERVATIVE_APPROXIMATION',
      passed,
      expectedBehavior: "If analysis is incomplete, staticRiskEstimate must evaluate to 'INCONCLUSIVE' (never 'LOW')",
      observedBehavior: `isInconclusive: ${analysis.isInconclusive}, staticRiskEstimate: ${analysis.metrics.staticRiskEstimate}`,
      evidence: {
        isInconclusive: analysis.isInconclusive,
        staticRiskEstimate: analysis.metrics.staticRiskEstimate,
        analysisStatus: analysis.analysisStatus,
      },
    });
  }

  // -------------------------------------------------------------------------
  // Check 3: Incomplete Analysis Generates INCOMPLETE_ANALYSIS Warning Finding
  // -------------------------------------------------------------------------
  {
    const deepMutualCode = `
      function a(x) { return b(x); }
      function b(x) { return c(x); }
      function c(x) { return d(x); }
      function d(x) { return a(x); }
      const res = a(req.query.v);
    `;
    // Explicitly restrict iteration budget to 1 to force resource exhaustion
    const { analysis } = executeTrueStaticAnalysis(deepMutualCode, 'javascript', 'deep_cycle.js', { maxIterations: 1 });
    
    // Explicit finding with INCOMPLETE_ANALYSIS and incompleteAnalysisWarning must exist
    const hasIncompleteFinding = analysis.findings.some(f => 
      f.title.includes('INCOMPLETE_ANALYSIS') || f.id.includes('analysis-status')
    );
    const passed = analysis.isInconclusive === true && 
      hasIncompleteFinding && 
      Boolean(analysis.incompleteAnalysisWarning);

    checks.push({
      checkId: 'SND-03-INCOMPLETE-FINDING-PROPAGATION',
      name: 'Explicit INCOMPLETE_ANALYSIS Finding Injected on Resource Limit',
      principle: 'CONSERVATIVE_APPROXIMATION',
      passed,
      expectedBehavior: 'When analysis is inconclusive, explicit INCOMPLETE_ANALYSIS finding must exist in findings list',
      observedBehavior: `isInconclusive: ${analysis.isInconclusive}, hasIncompleteFinding: ${hasIncompleteFinding}, warning: '${analysis.incompleteAnalysisWarning?.slice(0, 50)}...'`,
      evidence: {
        isInconclusive: analysis.isInconclusive,
        findingsCount: analysis.findings.length,
        hasIncompleteFinding,
        hasWarning: Boolean(analysis.incompleteAnalysisWarning),
      },
    });
  }

  // -------------------------------------------------------------------------
  // Check 4: Abstract Domain Join Monotonicity (Tainted || Clean === Tainted)
  // -------------------------------------------------------------------------
  {
    const cleanState: any = { isTainted: false, threat: 'UNTRUSTED', sanitized: false, history: [], stringValue: 'SELECT * FROM safe' };
    const taintedState: any = { isTainted: true, threat: 'SQL_INJECTION', sanitized: false, history: [], stringValue: 'SELECT * FROM users' };
    const joined = joinAbstractValues(cleanState, taintedState);
    
    const passed = Boolean(joined && joined.isTainted === true && joined.threat === 'SQL_INJECTION');
    checks.push({
      checkId: 'SND-04-TAINT-MONOTONICITY',
      name: 'Lattice Monotonicity: Clean ⊔ Tainted = Tainted',
      principle: 'MONOTONICITY',
      passed,
      expectedBehavior: 'Joining clean state with tainted state must always result in tainted state',
      observedBehavior: `isTainted: ${joined?.isTainted}, threat: ${joined?.threat}`,
      evidence: { joined },
    });
  }

  // -------------------------------------------------------------------------
  // Check 5: Sound Constant Joins (Constant Disagreement Yields Unknown)
  // -------------------------------------------------------------------------
  {
    const constA: any = { isTainted: false, threat: 'UNTRUSTED', sanitized: false, history: [], stringValue: 'admin' };
    const constB: any = { isTainted: false, threat: 'UNTRUSTED', sanitized: false, history: [], stringValue: 'public' };
    const joined = joinAbstractValues(constA, constB);
    
    // Different constants joined must produce stringValue = undefined (TOP / unknown)
    const passed = Boolean(joined && joined.stringValue === undefined);
    checks.push({
      checkId: 'SND-05-SOUND-CONSTANT-JOIN',
      name: 'Sound Constant Join: Distinct Constants ⊔ Produces Unknown (Top)',
      principle: 'SOUND_CONSTANT_JOIN',
      passed,
      expectedBehavior: "Joining 'admin' with 'public' must yield undefined (unknown constant), never arbitrarily picking one",
      observedBehavior: `stringValue: ${joined?.stringValue}`,
      evidence: { stringValue: joined?.stringValue },
    });
  }

  // -------------------------------------------------------------------------
  // Check 6: Branch-Return Control Flow Isolation
  // -------------------------------------------------------------------------
  {
    const branchCode = `
      function process(val) {
        let x = 'clean_initial';
        if (val > 10) {
          x = req.query.tainted;
          return x;
        }
        // Branch above returned; x here must remain 'clean_initial'
        await db.query('SELECT * FROM items WHERE id = ' + x);
      }
    `;
    const ast = parseSourceCode(branchCode, 'branch_iso.js').ast;
    const res = runFlowSensitiveInterproceduralAnalysis(ast, 'branch_iso.js');
    
    // The sink on line 9 should NOT be flagged as vulnerable because the tainted branch returned!
    const sinkVuln = res.vulnerabilities.find(v => v.sink.line === 9);
    const passed = !sinkVuln;
    checks.push({
      checkId: 'SND-06-BRANCH-RETURN-ISOLATION',
      name: 'Terminated Returning Branch Does Not Contaminate Post-If Environment',
      principle: 'BRANCH_ISOLATION',
      passed,
      expectedBehavior: 'Variables assigned inside a branch that returns must not flow into statements after the if',
      observedBehavior: sinkVuln ? 'Contamination detected (sink flagged)' : 'Correctly isolated (no sink vulnerability)',
      evidence: { sinkVulnFound: Boolean(sinkVuln) },
    });
  }

  // -------------------------------------------------------------------------
  // Check 7: Threat-Specific Sanitizer Incompatibility
  // -------------------------------------------------------------------------
  {
    const xssSanitizerSqlSink = `
      const user = req.query.user;
      const escaped = escapeHtml(user); // Sanitizes XSS, NOT SQL injection
      const sql = "SELECT * FROM users WHERE name = '" + escaped + "'";
      db.query(sql);
    `;
    const ast = parseSourceCode(xssSanitizerSqlSink, 'sanitizer_mismatch.js').ast;
    const res = runFlowSensitiveInterproceduralAnalysis(ast, 'sanitizer_mismatch.js');
    
    // Should detect SQL injection as UNSANITIZED because escapeHtml does not neutralize SQL injection
    const vuln = res.vulnerabilities.find(v => v.vulnerabilityType === 'SQL_INJECTION');
    const passed = Boolean(vuln && !vuln.sanitized);
    checks.push({
      checkId: 'SND-07-THREAT-SPECIFIC-SANITIZER',
      name: 'Context Incompatible Sanitizer Does Not Neutralize Mismatched Sink',
      principle: 'THREAT_SPECIFICITY',
      passed,
      expectedBehavior: 'escapeHtml must not neutralize SQL_INJECTION sink (remains unsanitized)',
      observedBehavior: vuln ? `Sanitized: ${vuln.sanitized}` : 'No vuln found',
      evidence: { vulnFound: Boolean(vuln), sanitized: vuln?.sanitized },
    });
  }

  // -------------------------------------------------------------------------
  // Check 8: End-to-End Incomplete Result Propagation Across All Consumers
  // -------------------------------------------------------------------------
  {
    const recursiveCode = `
      function deepChain(n, val) {
        if (n <= 0) return val;
        return deepChain(n - 1, val);
      }
      const data = req.query.id;
      const res = deepChain(10, data);
    `;
    // Explicitly restrict iteration budget to 1 to force resource exhaustion
    const { analysis, engineData } = executeTrueStaticAnalysis(
      recursiveCode,
      'javascript',
      'end_to_end_incomplete.js',
      { maxIterations: 1 }
    );

    const hasIncompleteFinding = analysis.findings.some(f => 
      f.id.startsWith('analysis-status') || f.title.includes('INCOMPLETE_ANALYSIS')
    );
    const riskNotLow = analysis.metrics.staticRiskEstimate === 'INCONCLUSIVE';
    const securityCapped = analysis.metrics.securityScore <= 75;
    const warningPresent = Boolean(analysis.incompleteAnalysisWarning);
    const engineDataInconclusive = Boolean(engineData.isInconclusive && engineData.interproceduralAnalysis?.isInconclusive);

    const passed = analysis.isInconclusive === true &&
      analysis.analysisStatus === 'resource_limit_exceeded' &&
      hasIncompleteFinding &&
      riskNotLow &&
      securityCapped &&
      warningPresent &&
      engineDataInconclusive;

    checks.push({
      checkId: 'SND-08-END-TO-END-INCOMPLETE-PROPAGATION',
      name: 'End-to-End Incomplete Analysis Propagation Across File Consumers',
      principle: 'CONSERVATIVE_APPROXIMATION',
      passed,
      expectedBehavior: 'Resource exhaustion must propagate: isInconclusive=true, status=resource_limit_exceeded, staticRisk=INCONCLUSIVE, score<=75, warning finding present',
      observedBehavior: `isInconclusive=${analysis.isInconclusive}, status='${analysis.analysisStatus}', risk='${analysis.metrics.staticRiskEstimate}', score=${analysis.metrics.securityScore}, hasFinding=${hasIncompleteFinding}, engineInconclusive=${engineDataInconclusive}`,
      evidence: {
        isInconclusive: analysis.isInconclusive,
        analysisStatus: analysis.analysisStatus,
        staticRiskEstimate: analysis.metrics.staticRiskEstimate,
        securityScore: analysis.metrics.securityScore,
        hasIncompleteFinding,
        engineDataInconclusive,
      },
    });
  }

  const durationMs = Number((performance.now() - startTime).toFixed(2));
  const passedChecks = checks.filter(c => c.passed).length;
  const failedChecks = checks.length - passedChecks;

  return {
    timestamp: new Date().toISOString(),
    totalChecks: checks.length,
    passedChecks,
    failedChecks,
    soundnessChecksPassed: failedChecks === 0,
    soundnessGuaranteed: failedChecks === 0,
    qualificationNote: 'Executable tests of selected abstract interpretation soundness properties (conservative bounds, monotonicity, constant joins, branch isolation). These tests validate expected invariants on known test cases and do not constitute a formal mathematical proof for arbitrary JavaScript programs.',
    durationMs,
    checks,
  };
}
