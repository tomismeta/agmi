// Embedded by agmi. The existing Gateway, its configuration and hooks are trusted.
// Authentication stays inside OpenClaw's public CLI transport. No tokens or prompts
// are passed in argv; native diagnostics never enter the result envelope.
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const emit = process.stdout.write.bind(process.stdout);
process.stdout.write = process.stderr.write.bind(process.stderr);
let started = false;
let reported = {};
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_.:/-]{1,256}$/.test(value) ? value : null;
// Match solver.rs: one more JSON escaping pass over the complete request
// allowance, plus envelope/policy/model metadata. Do not reduce guidance/task limits.
const MAX_INPUT_BYTES = 2 * (128 * 1024 + 12 * 64 * 1024) + 16 * 1024;

try {
  let input = '';
  let bytes = 0;
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) {
    bytes += Buffer.byteLength(chunk);
    if (bytes > MAX_INPUT_BYTES) throw new Error('input limit');
    input += chunk;
  }
  const request = JSON.parse(input);
  const require = createRequire(process.argv[1]);
  const { callGatewayFromCli } = await import(pathToFileURL(
    require.resolve('openclaw/plugin-sdk/gateway-runtime')).href);
  if (typeof callGatewayFromCli !== 'function') throw new Error('unsupported native API');
  const runId = identifier(request.invocation_id);
  if (!runId) throw new Error('missing native invocation identity');
  started = true;
  // The inspected agent API exposes a single message, not a privileged policy
  // field. Rust combines policy and envelope here without claiming isolation.
  const response = await callGatewayFromCli('agent', {
    json: true,
    timeout: String(request.timeout_seconds * 1000),
    expectFinal: true,
  }, {
    message: request.prompt,
    model: request.model,
    thinking: request.reasoning,
    deliver: false,
    timeout: request.timeout_seconds,
    modelRun: true,
    promptMode: 'none',
    suppressPromptPersistence: true,
    sessionEffects: 'internal',
    disableMessageTool: true,
    idempotencyKey: runId,
  }, {
    mode: 'backend',
    scopes: ['operator.admin'],
    expectFinal: true,
    progress: false,
  });
  const result = response?.result;
  // Collect independently of output validity, without retaining raw errors/prompts.
  const meta = result?.meta;
  const native = meta?.agentMeta;
  const report = meta?.systemPromptReport;
  const trace = meta?.executionTrace;
  reported = {
    provider: identifier(native?.provider), model: identifier(native?.model),
    runId: identifier(response?.runId),
    reasoning: identifier(meta?.requestShaping?.thinking),
    aborted: typeof meta?.aborted === 'boolean' ? meta.aborted : null,
    fallbackUsed: typeof trace?.fallbackUsed === 'boolean' ? trace.fallbackUsed : null,
    winnerProvider: identifier(trace?.winnerProvider), winnerModel: identifier(trace?.winnerModel),
    toolCount: Array.isArray(report?.tools?.entries) ? report.tools.entries.length : null,
    bootstrapFileCount: Array.isArray(report?.injectedWorkspaceFiles) ? report.injectedWorkspaceFiles.length : null,
  };
  if (response?.status === 'timeout') throw 'timeout';
  if (meta?.aborted === true) throw 'aborted';
  const payloads = result?.payloads;
  if (response?.status !== 'ok' || !Array.isArray(payloads) || payloads.length !== 1
      || typeof payloads[0].text !== 'string'
      || Buffer.byteLength(payloads[0].text) > 65536) {
    throw 'error_payload';
  }
  // Only bounded result data and explicit evidence cross into Rust. Missing
  // evidence remains null, never an inferred safe default.
  emit(JSON.stringify({
    ok: true,
    status: 'ok',
    ...reported,
    final: payloads[0].text,
  }) + '\n');
} catch (error) {
  // A disconnected CLI does not prove that shared-Gateway inference stopped.
  const kind = ['timeout', 'aborted', 'error_payload'].includes(error) ? error : 'exception';
  emit(JSON.stringify({ok: false, status: 'error', ...reported, error: {kind}}) + '\n');
  process.exitCode = started ? 1 : 78;
}
