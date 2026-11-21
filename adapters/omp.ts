// Invocation-only bridge qualified against omp v19.0.1 (f40f335845f0b136453d12fec8d6057011082766).
// Provider factories are trusted native profile code, not a sandbox. Only their
// pending provider registrations enter the live runner; their handlers never do.
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Settings, getAgentDir, discoverSessionExtensionPaths, loadExtensions, z } from "@oh-my-pi/pi-coding-agent";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { lookup } from "@oh-my-pi/pi-coding-agent/config/registry";
import { streamSimple } from "@oh-my-pi/pi-ai";
import type { AssistantMessage, Model, RawSseEvent, TextSignatureV1 } from "@oh-my-pi/pi-ai";
import { applyWireModelIdTransform } from "@oh-my-pi/pi-ai/providers/openai-shared";
import { setTimeout, clearTimeout } from "node:timers";
import { requireSupportedEffort, resolveWireModelId } from "@oh-my-pi/pi-catalog";
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

function finalText(content: AssistantMessage["content"]): { output: string; output_phase: "final_answer" | null } {
  const unphased: string[] = [];
  const phased: string[] = [];
  let finalId: string | undefined;
  let sawPhase = false;
  for (const part of content) {
    if (part.type !== "text") continue;
    // v19.0.1 Responses attaches TextSignatureV1 to each output message;
    // other transports may omit it or supply only a legacy message id.
    let signature: Partial<TextSignatureV1> | undefined;
    if (part.textSignature?.startsWith("{")) {
      try { signature = JSON.parse(part.textSignature); }
      catch { throw new Failure("native_completion"); }
      requireThat(signature?.v === 1 && typeof signature.id === "string" && signature.id.length > 0, "native_completion");
    }
    const phase = signature?.phase;
    if (phase === undefined) {
      unphased.push(part.text);
    } else {
      sawPhase = true;
      if (phase === "final_answer") {
        requireThat(finalId === undefined || finalId === signature?.id, "native_completion");
        finalId = signature?.id;
        phased.push(part.text);
      } else {
        requireThat(finalId === undefined && (phase === "commentary" || phase === "partial_answer"), "native_completion");
      }
    }
  }
  if (!sawPhase) {
    const output = unphased.join("");
    requireThat(output.trim().length > 0, "native_completion");
    return { output, output_phase: null };
  }
  const output = phased.join("");
  requireThat(!unphased.some(text => text.trim()) && output.trim().length > 0, "native_completion");
  return { output, output_phase: "final_answer" };
}

function isOpenRouter(model: Model): boolean {
  return model.provider === "openrouter" || model.api === "openrouter"
    || model.compat?.wireModelIdMode === "openrouter" || model.baseUrl.toLowerCase().includes("openrouter.ai");
}

function toolEnabledModel(id: string, openrouter: boolean): boolean {
  const [base, ...modifiers] = id.toLowerCase().split(":");
  const model = base.slice(base.lastIndexOf("/") + 1);
  // :online is a router modifier. Known intrinsic search models also search
  // on direct APIs, where their ID may omit the provider namespace.
  return (openrouter && modifiers.includes("online"))
    || /^sonar(?:-(?:pro|reasoning(?:-pro)?|deep-research))?(?:-\d{4}-\d{2}-\d{2})?$/.test(model)
    || /^(?:gpt-4o(?:-mini)?-search-preview|gpt-5-search-api)(?:-|$)/.test(model);
}

function sameModel(served: string, requested: string, openrouter: boolean, upstream: boolean): boolean {
  if (served === requested) return true;
  if (!openrouter) return false;
  // OpenRouter's traffic/pricing modifiers aren't part of the underlying model.
  const strip = (id: string) => id.replace(/(?::(?:nitro|floor|exacto|free))+$/, "");
  const base = strip(requested);
  return strip(served) === base
    // The pinned SDK can decode a native Anthropic model id from the signature
    // of an OpenRouter response. That id doesn't contain the gateway namespace.
    || (upstream && base.startsWith("anthropic/") && served === base.slice("anthropic/".length));
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" ? value as Record<string, unknown> : undefined;
}

// The pinned built-in transports merge extraBody *after* encoding the
// protected model, prompt, effort and tool policy. Only scalar sampling
// tuning is safe to pass through that replacement mechanism.
const SAFE_TUNING_FIELDS: Record<string, true> = {
  temperature: true, top_p: true, top_k: true, min_p: true,
  frequency_penalty: true, presence_penalty: true, repetition_penalty: true,
};

function requireSafeExtraBody(model: Model) {
  for (const compat of [model.compat, model.compatConfig]) {
    const extra = record(compat)?.extraBody;
    if (extra === undefined) continue;
    const body = record(extra);
    requireThat(body && !Array.isArray(body) && Object.entries(body).every(([key, value]) =>
      Object.hasOwn(SAFE_TUNING_FIELDS, key) && typeof value === "number" && Number.isFinite(value)), "native_settings");
  }
}

function wireEvidence(event: RawSseEvent, api: Model["api"]) {
  // The v19.0.1 SDK's AssistantMessage.model is initialized from the catalog.
  // Chat and Responses wire model IDs are not copied into upstreamModel.
  const data = record(JSON.parse(event.data));
  if (!data) return {};
  if ((data.object === "chat.completion.chunk" || api === "openai-completions" || api === "openrouter")
    && Array.isArray(data.choices)) {
    const reason = record(data.choices[0])?.finish_reason;
    return { model: data.model, badStop: reason != null
      && !(typeof reason === "string" && ["stop", "end"].includes(reason.toLowerCase())) };
  }
  if (typeof data.type === "string" && data.type.startsWith("response.")) {
    const response = record(data.response);
    return { model: response?.model, badStop: data.type === "response.incomplete"
      || data.type === "response.failed" || data.type === "response.cancelled"
      || record(data.item)?.type === "web_search_call"
      || ((data.type === "response.completed" || data.type === "response.done")
        && response?.status != null && response.status !== "completed") };
  }
  if (data.type === "message_start") return { model: record(data.message)?.model };
  if (data.type === "message_delta") {
    // The SDK's default "stop" (also used for unfamiliar reasons) is not
    // evidence of completion. Require a supported reason on a message_delta.
    const reason = record(data.delta)?.stop_reason;
    const supported = reason === "end_turn" || reason === "stop_sequence";
    return { anthropicStop: event.event === "message_delta" && supported,
      badStop: reason != null && !supported };
  }
  return {};
}

function reportedIdentifier(value: unknown): string | null {
  const parsed = bindingShape.model.safeParse(value);
  return parsed.success ? parsed.data : null;
}

export default async function (pi: ExtensionAPI) {
  requireThat(VERSION === "19.0.1", "native_api_unsupported");
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
        native_output_limit: "native_output_limit", native_stream: "native_stream_failed",
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
    requireSafeExtraBody(model);
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
  function routing(model: Model, wireModel: string) {
    const openrouter = lookup("providers.openrouterVariant");
    const antigravity = lookup("providers.antigravityEndpoint");
    requireThat(openrouter && antigravity, "native_settings");
    const variant = z.enum(["default", "nitro", "floor", "online", "exacto"]).parse(openrouter.get(settings));
    const routed = isOpenRouter(model);
    requireThat(!(routed && variant === "online") && !toolEnabledModel(model.id, routed)
      && !toolEnabledModel(wireModel, routed), "native_tool_call");
    const endpoint = antigravity.get(settings);
    return { openrouterVariant: variant === "default" || variant === "online" ? undefined : variant,
      antigravityEndpointMode: z.enum(["auto", "production", "sandbox"]).parse(endpoint) };
  }
  pi.on("session_start", async (_event, ctx) => {
    try {
      const model = resolve(ctx);
      routing(model, resolveWireModelId(model, boot.reasoning_effort === "off" ? undefined : boot.reasoning_effort));
      requireThat(Date.now() < boot.deadline_unix_ms, "native_deadline");
      ready = true;
      pi.appendEntry("agmi_omp_ready_v1", binding);
    } catch (e) { emitResult({ ok: false, stage: "startup", reason_code: e instanceof Failure ? e.code : "native_startup" }); }
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
      let wireModel: string | null = null;
      let payloadFailure: Failure | undefined;
      let wireMismatch = false;
      let wireBadStop = false;
      let wireAnthropicStop = false;
      let wireOverflow = false;
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
        const effort = boot.reasoning_effort === "off" ? undefined : boot.reasoning_effort;
        const baseWireModel = resolveWireModelId(model, effort);
        const options = routing(model, baseWireModel);
        const openrouter = isOpenRouter(model);
        const completions = model.api === "openai-completions" || model.api === "openrouter";
        const wireMode = model.compat?.wireModelIdMode;
        const selectedWireModel = completions && wireMode !== undefined
          ? applyWireModelIdTransform(baseWireModel, wireMode, options.openrouterVariant) : baseWireModel;
        let sawPayload = false;
        let requestModel: string | undefined;
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
          reasoning: effort,
          disableReasoning: boot.reasoning_effort === "off", toolChoice: "none",
          disableServerSideFallback: true, maxHttpAttempts: 1, maxTokens: Math.min(MAX_OUTPUT / 4, model.maxTokens),
          onPayload: payload => {
            // This native transport can re-enter the builder with a silently
            // changed effort after the first provider rejects it. A fresh
            // invocation qualifies only the initial catalog-encoded request.
            if (completions && sawPayload) {
              payloadFailure = new Failure("native_effort");
              throw payloadFailure;
            }
            sawPayload = true;
            const request = record(payload);
            if (!request) return;
            const id = request.model;
            if (id === undefined) return;
            if (typeof id !== "string" || !sameModel(id, selectedWireModel, openrouter, false)
              || (requestModel !== undefined && requestModel !== id)) {
              payloadFailure = new Failure("native_identity");
              throw payloadFailure;
            }
            if (toolEnabledModel(id, openrouter)) payloadFailure = new Failure("native_tool_call");
            if (payloadFailure) throw payloadFailure;
            requestModel = id;
          },
          onSseEvent: event => {
            if (event.data === "[DONE]" || !event.data) return;
            if (bytes(event.data) > 6 * MAX_OUTPUT + 4096) { wireOverflow = true; return; }
            try {
              const observed = wireEvidence(event, model.api);
              wireBadStop ||= observed.badStop === true;
              wireAnthropicStop ||= observed.anthropicStop === true;
              if (observed.model == null) return;
              const id = reportedIdentifier(observed.model);
              const matches = id !== null && sameModel(id, requestModel ?? selectedWireModel, openrouter, false);
              // Keep a contradictory value for diagnostics, not a later echo.
              if (!wireMismatch && (wireModel === null || !matches)) wireModel = id;
              wireMismatch ||= !matches;
            } catch { /* The native decoder owns malformed SSE and completion. */ }
          },
        });
        let retained = 0;
        for await (const event of stream) {
          requireThat(!controller.signal.aborted, "native_deadline");
          requireThat(!final, "native_completion");
          requireThat(!event.type.startsWith("toolcall"), "native_tool_call");
          if (event.type === "text_delta" || event.type === "thinking_delta") {
            retained += bytes(event.delta);
            requireThat(retained <= MAX_OUTPUT, "native_output_limit");
          }
          if (event.type === "error") throw new Failure("native_stream");
          if (event.type === "done") {
            final = event.message;
            requireThat(event.reason === "stop" && final.stopReason === "stop" && final.errorMessage == null,
              "native_completion");
          }
        }
        requireThat(!controller.signal.aborted && Date.now() < boot.deadline_unix_ms, "native_deadline");
        if (payloadFailure) throw payloadFailure;
        requireThat(!wireOverflow, "native_output_limit");
        requireThat(!wireMismatch && final && final.provider === boot.provider && final.model === boot.model
          && (final.upstreamModel == null || (reportedIdentifier(final.upstreamModel) !== null
            && sameModel(final.upstreamModel, requestModel ?? selectedWireModel, openrouter, true))), "native_identity");
        requireThat(final.role === "assistant" && final.stopReason === "stop" && final.errorMessage == null
          && final.stopDetails?.type !== "pause_turn" && final.stopDetails?.type !== "compaction"
          && !wireBadStop && (model.api !== "anthropic-messages" || wireAnthropicStop), "native_completion");
        requireThat(Array.isArray(final.content) && final.content.every(part => part.type === "text" || part.type === "thinking"), "native_tool_call");
        requireThat(final.content.length <= 4096 && final.content.reduce((size, part) =>
          size + (part.type === "text" ? bytes(part.text) : part.type === "thinking" ? bytes(part.thinking) : MAX_OUTPUT + 1), 0)
          <= MAX_OUTPUT, "native_output_limit");
        const { output, output_phase } = finalText(final.content);
        requireThat(bytes(JSON.stringify(final.content)) <= 6 * MAX_OUTPUT + 4096 && bytes(output) <= MAX_OUTPUT, "native_output_limit");
        emitResult({ ok: true, output, output_phase, native_provider: final.provider, native_model: final.model,
          wire_model: wireModel, upstream_model: reportedIdentifier(final.upstreamModel),
          upstream_provider: reportedIdentifier(final.upstreamProvider) });
      } catch (e) {
        controller?.abort();
        const nativeFacts = final && bindingShape.provider.safeParse(final.provider).success
          && bindingShape.model.safeParse(final.model).success
          ? { native_provider: final.provider, native_model: final.model } : {};
        emitResult({ ...nativeFacts, wire_model: wireModel, upstream_model: reportedIdentifier(final?.upstreamModel),
          upstream_provider: reportedIdentifier(final?.upstreamProvider),
          ok: false, reason_code: (payloadFailure ?? (e instanceof Failure ? e : undefined))?.code ?? "native_failure" });
      } finally { clearTimeout(timer); controller = undefined; }
    },
  });
}
