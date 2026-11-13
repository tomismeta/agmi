// Invocation-only bridge qualified against omp v18.19.0 (04cd1a7549a02d62ad1d24826198d52507595683).
// Provider factories are trusted native profile code, not a sandbox. Only their
// pending provider registrations enter the live runner; their handlers never do.
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Settings, getAgentDir, discoverSessionExtensionPaths, loadExtensions, z } from "@oh-my-pi/pi-coding-agent";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { lookup } from "@oh-my-pi/pi-coding-agent/config/registry";
import { streamSimple } from "@oh-my-pi/pi-ai";
import type { AssistantMessage } from "@oh-my-pi/pi-ai";
import { setTimeout, clearTimeout } from "node:timers";
import { requireSupportedEffort } from "@oh-my-pi/pi-catalog";
import { VERSION } from "@oh-my-pi/pi-utils/dirs";

const MAX_INPUT = 128 * 1024 + 12 * 64 * 1024;
const MAX_BODY = 2 * MAX_INPUT + 16 * 1024;
const MAX_OUTPUT = 256 * 1024;
const COMMAND = "agmi-omp-once-v1";
const bytes = (s: string) => Buffer.byteLength(s, "utf8");
const bindingShape = {
  protocol: z.literal(1), invocation_id: z.string().regex(/^[A-Za-z0-9_.:/-]{1,256}$/),
  request_digest: z.string().regex(/^[a-f0-9]{64}$/), selection_digest: z.string().regex(/^[a-f0-9]{64}$/),
  provider: z.string().regex(/^[A-Za-z0-9_.:/-]{1,256}$/), model: z.string().regex(/^[A-Za-z0-9_.:/-]{1,256}$/),
  reasoning_effort: z.enum(["off", "minimal", "low", "medium", "high", "xhigh", "max"]),
};
const bootstrapSchema = z.object({
  ...bindingShape, provider_discovery_cwd: z.string().regex(/^\//),
  deadline_unix_ms: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
}).strict();
const bodySchema = z.object({
  ...bindingShape, request_json: z.string(), policy: z.string(),
  timeout_ms: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
}).strict();
class Failure extends Error { constructor(readonly code: string) { super(code); } }
function requireThat(ok: unknown, code: string): asserts ok { if (!ok) throw new Failure(code); }

export default async function (pi: ExtensionAPI) {
  requireThat(VERSION === "18.19.0", "native_api_unsupported");
  const raw = await readFile(new URL("./omp-bootstrap.json", import.meta.url), "utf8");
  requireThat(bytes(raw) <= 16 * 1024, "native_bootstrap");
  const boot = bootstrapSchema.parse(JSON.parse(raw));
  requireThat(boot.deadline_unix_ms > Date.now(), "native_bootstrap");
  const binding = { protocol: 1, invocation_id: boot.invocation_id, request_digest: boot.request_digest,
    selection_digest: boot.selection_digest, provider: boot.provider, model: boot.model,
    reasoning_effort: boot.reasoning_effort };
  const settings = await Settings.loadReadOnly({ cwd: boot.provider_discovery_cwd, agentDir: getAgentDir() });
  const paths = await discoverSessionExtensionPaths({ includeAmbientHooks: true }, boot.provider_discovery_cwd, settings);
  // Do not pass a live event bus/runtime, construct a runner, or attach Extension objects.
  const loaded = await loadExtensions(paths, boot.provider_discovery_cwd);
  requireThat(loaded.errors.length === 0, "native_provider_load");
  for (const { name, config } of loaded.runtime.pendingProviderRegistrations) pi.registerProvider(name, config);

  let consumed = false;
  let duplicateReported = false;
  let ready = false;
  let controller: AbortController | undefined;
  let terminal = false;
  function emitResult(data: Record<string, unknown>) {
    if (terminal) return;
    terminal = true;
    if (typeof data.reason_code === "string") {
      const reasons: Record<string, string> = {
        native_model: "native_api_unsupported", native_effort: "native_api_unsupported",
        native_settings: "native_api_unsupported", native_deadline: "model_deadline_exceeded",
        native_binding: "native_run_binding_mismatch", native_request: "native_run_binding_mismatch",
        native_not_ready: "native_run_binding_mismatch", native_identity: "native_provenance_mismatch",
        native_tool_call: "native_api_unsupported", native_completion: "native_api_unsupported",
        native_output_limit: "native_output_limit", native_stream: "native_process_failed",
      };
      data.reason_code = reasons[data.reason_code] ?? "native_failure";
    }
    pi.appendEntry("agmi_omp_result_v1", { ...binding, ...data });
  }
  function resolve(ctx: ExtensionContext) {
    const model = ctx.modelRegistry.find(boot.provider, boot.model);
    requireThat(model && model.provider === boot.provider && model.id === boot.model, "native_model");
    // These APIs start agent/workflow protocols even with an empty MCP tool list.
    requireThat(!["cursor-agent", "gitlab-duo-agent"].includes(model.api), "native_model");
    if (boot.reasoning_effort === "off") {
      // A generic disableReasoning flag can silently clamp to the lowest tier.
      // Only non-reasoning metadata or a catalog-declared explicit off-path proves exact off.
      requireThat(!model.reasoning || model.thinking?.suppressWhenOff === true, "native_effort");
    } else {
      try { requireSupportedEffort(model, boot.reasoning_effort); }
      catch { throw new Failure("native_effort"); }
    }
    return model;
  }
  function routing() {
    const openrouter = lookup("providers.openrouterVariant");
    const antigravity = lookup("providers.antigravityEndpoint");
    requireThat(openrouter && antigravity, "native_settings");
    const variant = openrouter.get(settings);
    const endpoint = antigravity.get(settings);
    return { openrouterVariant: variant === "default" ? undefined
      : z.enum(["nitro", "floor", "online", "exacto"]).parse(variant),
      antigravityEndpointMode: z.enum(["auto", "production", "sandbox"]).parse(endpoint) };
  }
  pi.on("session_start", async (_event, ctx) => {
    try {
      resolve(ctx);
      routing();
      requireThat(Date.now() < boot.deadline_unix_ms, "native_deadline");
      ready = true;
      pi.appendEntry("agmi_omp_ready_v1", binding);
    } catch (e) { emitResult({ ok: false, reason_code: e instanceof Failure ? e.code : "native_startup" }); }
  });
  pi.on("session_shutdown", async () => { controller?.abort(); });
  pi.registerCommand(COMMAND, {
    description: "Bound, single-use agmi direct inference (invocation-local)",
    handler: async (args, ctx) => {
      // Latch before decoding: invalid input cannot be repaired into a second dispatch.
      if (consumed) {
        if (!duplicateReported) {
          duplicateReported = true;
          pi.appendEntry("agmi_omp_result_v1", { ...binding, ok: false, reason_code: "native_run_binding_mismatch" });
        }
        return;
      }
      consumed = true;
      let timer: NodeJS.Timeout | undefined;
      let final: AssistantMessage | undefined;
      try {
        requireThat(ready && !terminal, "native_not_ready");
        requireThat(args.length <= Math.ceil(MAX_BODY / 3) * 4 && /^[A-Za-z0-9_-]+$/.test(args), "native_request");
        const decoded = Buffer.from(args, "base64url");
        requireThat(decoded.length <= MAX_BODY && decoded.toString("base64url") === args, "native_request");
        const text = new TextDecoder("utf-8", { fatal: true }).decode(decoded);
        const body = bodySchema.parse(JSON.parse(text));
        for (const key of ["protocol", "invocation_id", "request_digest", "selection_digest",
          "provider", "model", "reasoning_effort"] as const) requireThat(body[key] === binding[key], "native_binding");
        requireThat(typeof body.request_json === "string" && bytes(body.request_json) <= MAX_INPUT
          && createHash("sha256").update(body.request_json, "utf8").digest("hex") === boot.request_digest && typeof body.policy === "string"
          && bytes(body.policy) <= 16 * 1024 && Number.isSafeInteger(body.timeout_ms) && body.timeout_ms > 0, "native_binding");
        const request = z.object({ kind: z.string() }).passthrough().parse(JSON.parse(body.request_json));
        const model = resolve(ctx);
        const options = routing();
        const remaining = Math.min(body.timeout_ms, boot.deadline_unix_ms - Date.now());
        requireThat(remaining > 0, "native_deadline");
        controller = new AbortController();
        timer = setTimeout(() => controller?.abort(), remaining);
        // Independent Context: native history, hooks, rules and outer prompts never enter this object.
        const context = { systemPrompt: body.policy, messages: [{ role: "user" as const,
          content: JSON.stringify({ kind: request.kind, request }), timestamp: Date.now() }], tools: [] };
        pi.appendEntry("agmi_omp_dispatch_v1", binding);
        const stream = streamSimple(model, context, {
          ...options, apiKey: ctx.modelRegistry.resolver(model, boot.invocation_id),
          sessionId: boot.invocation_id, signal: controller.signal,
          reasoning: boot.reasoning_effort === "off" ? undefined : boot.reasoning_effort,
          disableReasoning: boot.reasoning_effort === "off", toolChoice: "none",
          disableServerSideFallback: true, maxHttpAttempts: 1, maxTokens: Math.min(MAX_OUTPUT / 4, model.maxTokens),
        });
        let retained = 0;
        for await (const event of stream) {
          requireThat(!controller.signal.aborted, "native_deadline");
          requireThat(!event.type.startsWith("toolcall"), "native_tool_call");
          if (event.type === "text_delta" || event.type === "thinking_delta") {
            retained += bytes(event.delta);
            requireThat(retained <= MAX_OUTPUT, "native_output_limit");
          }
          if (event.type === "error") throw new Failure("native_stream");
          if (event.type === "done") {
            requireThat(!final && event.reason === "stop", "native_completion");
            final = event.message;
          }
        }
        requireThat(final && final.provider === boot.provider && final.model === boot.model, "native_identity");
        requireThat(Array.isArray(final.content) && final.content.every(part => part.type === "text" || part.type === "thinking"), "native_tool_call");
        requireThat(final.content.length <= 4096 && final.content.reduce((size, part) =>
          size + (part.type === "text" ? bytes(part.text) : part.type === "thinking" ? bytes(part.thinking) : MAX_OUTPUT + 1), 0)
          <= MAX_OUTPUT, "native_output_limit");
        const output = final.content.filter(part => part.type === "text").map(part => part.text).join("");
        requireThat(bytes(JSON.stringify(final.content)) <= 6 * MAX_OUTPUT + 4096 && bytes(output) <= MAX_OUTPUT, "native_output_limit");
        emitResult({ ok: true, output, native_provider: final.provider, native_model: final.model });
      } catch (e) {
        controller?.abort();
        const nativeFacts = final && bindingShape.provider.safeParse(final.provider).success
          && bindingShape.model.safeParse(final.model).success
          ? { native_provider: final.provider, native_model: final.model } : {};
        emitResult({ ...nativeFacts, ok: false, reason_code: e instanceof Failure ? e.code : "native_failure" });
      } finally { clearTimeout(timer); controller = undefined; }
    },
  });
}
