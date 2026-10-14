import { runSoundnessVerificationSuite } from '../src/engine/verification/soundnessRunner';
import { runExternalBenchmarkSuite, runSha256TestVectors } from '../src/engine/verification/externalBenchmarks';
import { runMutationTestSuite, runPropertyBasedTests } from '../src/engine/verification/mutationEngine';
import { runInterproceduralVerificationSuite } from '../src/engine/interprocedural/interproceduralRunner';
import { runBenchmarkVerificationSuite } from '../src/engine/verification/testRunner';

interface AssertionRecord {
  suite: string;
  description: string;
  passed: boolean;
  details?: string;
}

const assertions: AssertionRecord[] = [];

function assertCheck(suite: string, description: string, condition: boolean, details?: string): void {
  assertions.push({ suite, description, passed: condition, details });
  if (condition) {
    console.log(`  [ASSERTION PASS] ${description}`);
  } else {
    console.error(`  [ASSERTION FAIL] ${description}${details ? ` -> ${details}` : ''}`);
  }
}

console.log('================================================================');
console.log('       INDEPENDENT REPRODUCIBLE STATIC ANALYSIS TEST SUITE      ');
console.log('================================================================');

// -----------------------------------------------------------------------------
// [1/6] Cryptographic SHA-256 Test Vectors (FIPS 180-4 / WHATWG UTF-8)
// -----------------------------------------------------------------------------
console.log('\n[1/6] Cryptographic SHA-256 Test Vectors & Surrogate Handling');
console.log('----------------------------------------------------------------');
const shaVec = runSha256TestVectors();
console.log(`Test Vectors Evaluated: ${shaVec.passedVectors}/${shaVec.totalVectors} passed.`);

assertCheck(
  'SHA-256 Test Vectors',
  'All 10 test vectors match standard FIPS 180-4 digests',
  shaVec.allPassed && shaVec.passedVectors === shaVec.totalVectors,
  `passed ${shaVec.passedVectors}/${shaVec.totalVectors}`
);

for (const v of shaVec.vectors) {
  assertCheck(
    'SHA-256 Test Vectors',
    `Vector "${v.name}": ${v.description}`,
    v.matchesExpected && v.matchesNodeCrypto,
    `pure: ${v.computedPureDigest}, expected: ${v.expectedDigest}`
  );
}

// -----------------------------------------------------------------------------
// [2/6] Soundness Verification Invariants (SND-01 through SND-08)
// -----------------------------------------------------------------------------
console.log('\n[2/6] Soundness Verification Invariants (SND-01 through SND-08)');
console.log('----------------------------------------------------------------');
const snd = runSoundnessVerificationSuite();
console.log(`Summary: ${snd.passedChecks}/${snd.totalChecks} checks passed. soundnessChecksPassed: ${snd.soundnessChecksPassed}`);

assertCheck(
  'Soundness Invariants',
  'soundnessChecksPassed flag must be strictly true',
  snd.soundnessChecksPassed === true,
  `soundnessChecksPassed=${snd.soundnessChecksPassed}`
);

assertCheck(
  'Soundness Invariants',
  'All 8 soundness checks must execute and pass',
  snd.totalChecks === 8 && snd.passedChecks === 8,
  `passed ${snd.passedChecks}/${snd.totalChecks}`
);

for (const c of snd.checks) {
  assertCheck(
    'Soundness Invariants',
    `${c.checkId}: ${c.name}`,
    c.passed === true,
    `check passed=${c.passed}`
  );
}

// -----------------------------------------------------------------------------
// [3/6] Interprocedural Verification Suite
// -----------------------------------------------------------------------------
console.log('\n[3/6] Interprocedural Verification Suite');
console.log('----------------------------------------------------------------');
const ip = runInterproceduralVerificationSuite();
console.log(`Summary: ${ip.passedCases}/${ip.totalCases} test expectations met.`);
console.log(`suiteExpectationsMet: ${ip.suiteExpectationsMet}, allAnalysesConverged: ${ip.allAnalysesConverged}`);

assertCheck(
  'Interprocedural Analysis',
  'suiteExpectationsMet flag must be strictly true',
  ip.suiteExpectationsMet === true,
  `suiteExpectationsMet=${ip.suiteExpectationsMet}`
);

assertCheck(
  'Interprocedural Analysis',
  'All 53 interprocedural test cases must pass their suite expectations',
  ip.totalCases === 53 && ip.passedCases === 53,
  `passed ${ip.passedCases}/${ip.totalCases}`
);

// Explicitly check the intentional resource bound invariant:
// allAnalysesConverged MUST be false because intentional resource exhaustion bounds
// (e.g. maxIterations: 1 in SND-02/SND-03/SND-08) correctly produce INCOMPLETE_ANALYSIS findings rather than hanging.
assertCheck(
  'Interprocedural Analysis',
  'Intentional resource-bound invariant holds (allAnalysesConverged is false due to intentional maxIterations bounds)',
  ip.allAnalysesConverged === false,
  `allAnalysesConverged=${ip.allAnalysesConverged}`
);

// -----------------------------------------------------------------------------
// [4/6] External Benchmark Suite (20 Cases with Pinned Cryptographic SHA-256)
// -----------------------------------------------------------------------------
console.log('\n[4/6] External Benchmark Suite (20 Cases with Pinned Cryptographic SHA-256)');
console.log('----------------------------------------------------------------');
const ext = runExternalBenchmarkSuite();
console.log(`Overall: ${ext.truePositives + ext.trueNegatives}/${ext.totalBenchmarks} passed.`);
console.log(`Confusion Matrix: TP=${ext.truePositives}, TN=${ext.trueNegatives}, FP=${ext.falsePositives}, FN=${ext.falseNegatives}`);
console.log(`Metrics: Precision=${ext.precisionPercent}%, Recall=${ext.recallPercent}%, Accuracy=${ext.accuracyPercent}%, F1=${ext.f1Score}`);
console.log(`Upstream Official (${ext.upstreamOfficialMetrics.total} cases): TP=${ext.upstreamOfficialMetrics.truePositives}, TN=${ext.upstreamOfficialMetrics.trueNegatives}, FP=${ext.upstreamOfficialMetrics.falsePositives}, FN=${ext.upstreamOfficialMetrics.falseNegatives}`);
console.log(`Locally Authored (${ext.locallyAuthoredMetrics.total} cases): TP=${ext.locallyAuthoredMetrics.truePositives}, TN=${ext.locallyAuthoredMetrics.trueNegatives}, FP=${ext.locallyAuthoredMetrics.falsePositives}, FN=${ext.locallyAuthoredMetrics.falseNegatives}`);
console.log(`Integrity Verification: ${ext.integrityVerifiedCount}/${ext.totalBenchmarks} pinned hashes strictly verified.`);

assertCheck(
  'External Benchmarks',
  'Total benchmark cases must equal exactly 20 (16 upstream official, 4 locally authored)',
  ext.totalBenchmarks === 20 && ext.upstreamOfficialMetrics.total === 16 && ext.locallyAuthoredMetrics.total === 4,
  `total=${ext.totalBenchmarks}, upstream=${ext.upstreamOfficialMetrics.total}, local=${ext.locallyAuthoredMetrics.total}`
);

assertCheck(
  'External Benchmarks',
  'Benchmark accuracy must be 100% on the evaluated test set (TP=10, TN=10, FP=0, FN=0)',
  ext.truePositives === 10 && ext.trueNegatives === 10 && ext.falsePositives === 0 && ext.falseNegatives === 0 && ext.accuracyPercent === 100,
  `TP=${ext.truePositives}, TN=${ext.trueNegatives}, FP=${ext.falsePositives}, FN=${ext.falseNegatives}, Acc=${ext.accuracyPercent}%`
);

assertCheck(
  'External Benchmarks',
  'All 20 evaluated test snippets must match their pre-pinned cryptographic SHA-256 digests',
  ext.allIntegrityVerified === true && ext.integrityVerifiedCount === 20,
  `allIntegrityVerified=${ext.allIntegrityVerified}, verifiedCount=${ext.integrityVerifiedCount}`
);

console.log('\nEvaluated Test Snippet Cryptographic SHA-256 Checksums (FIPS 180-4, 64 Hex Digits):');
for (const r of ext.results) {
  console.log(`  ${r.benchmarkId.padEnd(26)} [${r.classification}] SHA-256: ${r.snippetSha256} ${r.integrityVerified ? '✓ [PINNED MATCH]' : '✗ [MISMATCH]'}`);
  assertCheck(
    'External Benchmarks',
    `Snippet integrity for ${r.benchmarkId}`,
    r.integrityVerified === true && r.passed === true,
    `integrityVerified=${r.integrityVerified}, passed=${r.passed}`
  );
}

// -----------------------------------------------------------------------------
// [5/6] Adversarial Mutation & Combinatorial Property Testing
// -----------------------------------------------------------------------------
console.log('\n[5/6] Adversarial Mutation & Combinatorial Property Testing');
console.log('----------------------------------------------------------------');
const mut = runMutationTestSuite();
console.log(`Adversarial Classification: ${mut.correctlyClassified}/${mut.totalAdversarialCases} (${mut.detectionScorePercent}%)`);

assertCheck(
  'Adversarial Testing',
  'All adversarial cases must be correctly classified',
  mut.totalAdversarialCases > 0 && mut.correctlyClassified === mut.totalAdversarialCases && mut.detectionScorePercent === 100,
  `classified ${mut.correctlyClassified}/${mut.totalAdversarialCases} (${mut.detectionScorePercent}%)`
);

const prop = runPropertyBasedTests();
console.log(`Property Testing: ${prop.passedProperties}/${prop.totalProperties} properties held across ${prop.totalSamplesTested} samples.`);

assertCheck(
  'Property Testing',
  'All property-based tests must hold across randomly generated AST samples',
  prop.totalProperties > 0 && prop.passedProperties === prop.totalProperties,
  `properties held ${prop.passedProperties}/${prop.totalProperties}`
);

// -----------------------------------------------------------------------------
// [6/6] Ground-Truth Security & Reliability Corpus
// -----------------------------------------------------------------------------
console.log('\n[6/6] Ground-Truth Security & Reliability Corpus');
console.log('----------------------------------------------------------------');
const corp = runBenchmarkVerificationSuite();
console.log(`Corpus Result: ${corp.passedTests}/${corp.totalTests} tests passed. overallPassed: ${corp.overallPassed}`);
console.log(`Metrics: Precision=${corp.metrics.precisionPercent}%, Recall=${corp.metrics.recallPercent}%, F1=${corp.metrics.f1Score}`);

assertCheck(
  'Security Corpus',
  'Corpus overallPassed flag must be strictly true and all tests passed',
  corp.overallPassed === true && corp.totalTests > 0 && corp.passedTests === corp.totalTests,
  `passed ${corp.passedTests}/${corp.totalTests}, overallPassed=${corp.overallPassed}`
);

// -----------------------------------------------------------------------------
// Final Evaluation and Non-Zero Process Exit on Any Failure
// -----------------------------------------------------------------------------
const failedAssertions = assertions.filter(a => !a.passed);

if (failedAssertions.length > 0) {
  console.error('\n================================================================');
  console.error(`  VERIFICATION FAILED: ${failedAssertions.length} ASSERTION(S) FAILED!`);
  console.error('================================================================');
  for (const fa of failedAssertions) {
    console.error(`  - [${fa.suite}] ${fa.description}${fa.details ? ` (${fa.details})` : ''}`);
  }
  console.error('================================================================\n');
  process.exit(1);
}

console.log('\n================================================================');
console.log('     ALL SUITES REPRODUCED AND VERIFIED WITHOUT ERRORS          ');
console.log(`     Total Assertions Checked & Passed: ${assertions.length}/${assertions.length} `);
console.log('================================================================\n');
process.exit(0);
