// Embedded by agmi. The existing Gateway, its configuration and hooks are trusted.
// Authentication stays inside OpenClaw's public CLI transport. No tokens or prompts
// are passed in argv; native diagnostics never enter the result envelope.
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';

const emit = process.stdout.write.bind(process.stdout);
process.stdout.write = process.stderr.write.bind(process.stderr);
let started = false;

try {
  let input = '';
  let bytes = 0;
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) {
    bytes += Buffer.byteLength(chunk);
    if (bytes > 1024 * 1024) throw new Error('input limit');
    input += chunk;
  }
  const request = JSON.parse(input);
  const require = createRequire(process.argv[1]);
  const { callGatewayFromCli } = await import(pathToFileURL(
    require.resolve('openclaw/plugin-sdk/gateway-runtime')).href);
  if (typeof callGatewayFromCli !== 'function') throw new Error('unsupported native API');
  const runId = randomUUID();
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
  if (response?.status === 'timeout') throw 'timeout';
  if (response?.result?.meta?.aborted === true) throw 'aborted';
  const meta = result?.meta;
  const native = meta?.agentMeta;
  const report = meta?.systemPromptReport;
  const trace = meta?.executionTrace;
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
    provider: native?.provider ?? null,
    model: native?.model ?? null,
    runId: response?.runId ?? null,
    requestedRunId: runId,
    reasoning: meta?.requestShaping?.thinking ?? null,
    aborted: meta?.aborted ?? null,
    fallbackUsed: trace?.fallbackUsed ?? null,
    winnerProvider: trace?.winnerProvider ?? null,
    winnerModel: trace?.winnerModel ?? null,
    toolCount: Array.isArray(report?.tools?.entries) ? report.tools.entries.length : null,
    bootstrapFileCount: Array.isArray(report?.injectedWorkspaceFiles) ? report.injectedWorkspaceFiles.length : null,
    final: payloads[0].text,
  }) + '\n');
} catch (error) {
  // A disconnected CLI does not prove that shared-Gateway inference stopped.
  const kind = ['timeout', 'aborted', 'error_payload'].includes(error) ? error : 'exception';
  emit(JSON.stringify({ok: false, status: 'error', error: {kind}}) + '\n');
  process.exitCode = started ? 1 : 78;
}
