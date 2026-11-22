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

const MAX_INPUT = 128 * 1024 + 12 * 64 * 1024;
const MAX_BODY = 2 * MAX_INPUT + 16 * 1024;
const MAX_GO_POST = MAX_BODY + 16 * 1024;
const MAX_OUTPUT = 256 * 1024;
const COMMAND = "agmi-omp-once-v1";
const GO_STOCK_URL = "https://opencode.ai/inference/go/v1";
const GO_SYNTHETIC_KEY = "agmi-loopback-fixture";
const GO_PROBE_POLICY = "AGMI_OMP_POLICY_CANARY: Return the answer only; use no tools.";
const GO_PROBE_MARKER = "AGMI_OMP_USER_DATA_CANARY";
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
  go_mode: z.enum(["stock", "probe", "stock_probe", "fixture"]).optional(),
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

function goMessageText(message: Record<string, unknown>): string | undefined {
  if (!Object.keys(message).every(key => key === "role" || key === "content")) return;
  const { content } = message;
  if (typeof content === "string") return content;
  if (!Array.isArray(content) || content.length !== 1) return;
  const part = record(content[0]);
  if (!part || part.type !== "text" || typeof part.text !== "string") return;
  const cache = record(part.cache_control);
  if (Object.keys(part).every(key => key === "type" || key === "text" || key === "cache_control")
      && (part.cache_control === undefined || (cache?.type === "ephemeral" && Object.keys(cache).length === 1))) {
    return part.text;
  }
}

function requireGoPayload(value: unknown, model: string, effort: string | undefined, policy: string, user: string) {
  const payload = record(value);
  requireThat(payload?.model === model && payload.stream === true, "native_identity");
  requireThat(effort !== undefined && payload.reasoning_effort === effort, "native_effort");
  const messages = payload.messages;
  requireThat(Array.isArray(messages) && messages.length === 2, "native_identity");
  const system = record(messages[0]);
  const input = record(messages[1]);
  requireThat((system?.role === "system" || system?.role === "developer") && goMessageText(system) === policy
    && input?.role === "user" && goMessageText(input) === user, "native_identity");

  // Allow only the direct streaming request and safe encoder variations.
  // A new routing, tool, prompt or fallback field is not safe by default.
  for (const [key, field] of Object.entries(payload)) {
    switch (key) {
      case "model": case "reasoning_effort": case "stream": case "messages": break;
      case "stream_options": {
        const options = record(field);
        requireThat(options?.include_usage === true && Object.keys(options).length === 1, "native_identity");
        break;
      }
      case "max_tokens": case "max_completion_tokens":
        requireThat(typeof field === "number" && Number.isSafeInteger(field) && field > 0 && field <= MAX_OUTPUT / 4, "native_identity");
        break;
      case "store": requireThat(field === false, "native_identity"); break;
      case "prompt_cache_key": requireThat(typeof field === "string", "native_identity"); break;
      case "tools": case "functions": case "plugins": case "fallbacks":
        requireThat(Array.isArray(field) && field.length === 0, "native_tool_call");
        break;
      case "tool_choice": case "function_call": {
        const choice = record(field);
        requireThat(field === null || field === "none" || (choice?.type === "none" && Object.keys(choice).length === 1), "native_tool_call");
        break;
      }
      case "web_search_options": requireThat(field === null, "native_tool_call"); break;
      case "thinking": {
        const thinking = record(field);
        requireThat(thinking?.type === "enabled" && Object.entries(thinking).every(([name, val]) =>
          name === "type" || (name === "effort" && val === effort) || (name === "keep" && val === "all")), "native_effort");
        break;
      }
      case "enable_thinking": case "preserve_thinking":
        requireThat(field === true, "native_effort");
        break;
      case "chat_template_kwargs": {
        const options = record(field);
        requireThat(options && !Array.isArray(options) && Object.entries(options).every(([name, val]) =>
          name === "reasoning_effort" ? val === effort
            : ["thinking", "enable_thinking", "preserve_thinking"].includes(name) && val === true), "native_effort");
        break;
      }
      default:
        requireThat(Object.hasOwn(SAFE_TUNING_FIELDS, key) && typeof field === "number" && Number.isFinite(field), "native_tool_call");
    }
  }
}

function isChatCompletions(api: Model["api"]): boolean {
  return api === "openai-completions" || api === "openrouter";
}

function wireEvidence(event: RawSseEvent, api: Model["api"]) {
  // The v19.0.1 SDK's AssistantMessage.model is initialized from the catalog.
  // Chat and Responses wire model IDs are not copied into upstreamModel.
  const data = record(JSON.parse(event.data));
  if (!data) return {};
  if ((data.object === "chat.completion.chunk" || isChatCompletions(api)) && Array.isArray(data.choices)) {
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
  if (data.type === "message_start") {
    const message = record(data.message);
    return { model: message?.model, anthropicStart: event.event === "message_start" ? message?.id ?? null : null };
  }
  if (data.type === "message_stop") return { anthropicEnd: true };
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
  const raw = await readFile(new URL("./omp-bootstrap.json", import.meta.url), "utf8");
  requireThat(bytes(raw) <= 16 * 1024, "native_bootstrap");
  const boot = bootstrapSchema.parse(JSON.parse(raw));
  requireThat(boot.deadline_unix_ms > Date.now(), "native_bootstrap");
  const binding = { protocol: 1, invocation_id: boot.invocation_id, request_digest: boot.request_digest,
    selection_digest: boot.selection_digest, provider: boot.provider, model: boot.model,
    reasoning_effort: boot.reasoning_effort };
  const stockGo = boot.provider === "opencode-go";
  requireThat(stockGo === (boot.go_mode !== undefined), "native_bootstrap");
  const stockProbe = boot.go_mode === "stock_probe";
  const loopbackGo = boot.go_mode === "probe" || boot.go_mode === "fixture";
  const syntheticGo = stockProbe || loopbackGo;
  const probeResponse = stockProbe ? z.object({
    status: z.union([z.literal(200), z.literal(400)]),
    mime: z.enum(["text/event-stream", "application/json"]),
    body: z.string().max(16 * 1024),
  }).strict().parse(JSON.parse(await readFile(new URL("./omp-probe-response.json", import.meta.url), "utf8"))) : undefined;
  const settings = await Settings.loadReadOnly({ cwd: boot.provider_discovery_cwd, agentDir: getAgentDir() });
  if (!stockGo) {
    const paths = await discoverSessionExtensionPaths({ includeAmbientHooks: true }, boot.provider_discovery_cwd, settings);
    // Do not pass a live event bus/runtime, construct a runner, or attach Extension objects.
    const loaded = await loadExtensions(paths, boot.provider_discovery_cwd);
    requireThat(loaded.errors.length === 0, "native_provider_load");
    for (const { name, config } of loaded.runtime.pendingProviderRegistrations) pi.registerProvider(name, config);
  }

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
        native_auth: "native_auth_unavailable",
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
  function routeDigest(model: Model) {
    // Compare the effective registry route, not the interactive session model.
    // The private qualification profile changes only the base URL and key.
    const fields = { ...model } as Record<string, unknown>;
    for (const key of ["baseUrl", "name", "cost", "contextWindow", "apiKey"]) delete fields[key];
    const canonicalize = (value: unknown): unknown => Array.isArray(value)
      ? value.map(canonicalize)
      : value && typeof value === "object"
        ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
          .map(([key, value]) => [key, canonicalize(value)]))
        : value;
    return createHash("sha256").update(JSON.stringify(canonicalize(fields))).digest("hex");
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
  let readyRoute: { digest: string; url: string } | null = null;
  let syntheticKey: string | undefined;
  pi.on("session_start", async (_event, ctx) => {
    try {
      const model = resolve(ctx);
      const effort = boot.reasoning_effort === "off" ? undefined : boot.reasoning_effort;
      routing(model, stockGo ? boot.model : resolveWireModelId(model, effort));
      requireThat(Date.now() < boot.deadline_unix_ms, "native_deadline");
      if (stockGo) {
        requireThat(model.api === "openai-completions", "native_model");
        const baseUrl = model.baseUrl.replace(/\/$/, "");
        requireThat(loopbackGo ? /^http:\/\/127\.0\.0\.1:[0-9]{1,5}\/v1$/.test(baseUrl) : baseUrl === GO_STOCK_URL, "native_model");
        if (stockProbe) {
          // The sandbox has no real auth store. This proves encoding, not login.
          syntheticKey = GO_SYNTHETIC_KEY;
        } else if (loopbackGo) {
          // Check the effective initial bearer, not the model overlay's apiKey.
          // Pass that checked value to the SDK without account rotation/re-resolution.
          const resolved = await ctx.modelRegistry.resolver(model, boot.invocation_id)({ lastChance: false, error: undefined });
          const key = typeof resolved === "string" ? resolved : resolved?.apiKey;
          // Distinguish a missing key from the deliberate nonempty wrong-bearer proof.
          requireThat(typeof key === "string" && key.length > 0, "native_auth_missing");
          requireThat(key === GO_SYNTHETIC_KEY, "native_auth");
          syntheticKey = key;
        }
        readyRoute = { digest: routeDigest(model), url: model.baseUrl };
      }
      requireThat(Date.now() < boot.deadline_unix_ms, "native_deadline");
      ready = true;
      pi.appendEntry("agmi_omp_ready_v1", readyRoute
        ? { ...binding, route_digest: readyRoute.digest, route_url: readyRoute.url }
        : binding);
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
      let requestFailure: Failure | undefined;
      let wireMismatch = false;
      let wireBadStop = false;
      let anthropicResponse: { id?: string | null; stopped: boolean; ended: boolean } | undefined;
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
        requireThat((boot.go_mode !== "probe" && !stockProbe) || (body.policy === GO_PROBE_POLICY
          && request.kind === "answer" && request.probe === GO_PROBE_MARKER && Object.keys(request).length === 2),
          "native_binding");
        const model = resolve(ctx);
        requireThat(!stockGo || (readyRoute?.url === model.baseUrl && readyRoute?.digest === routeDigest(model)), "native_identity");
        requireThat(!syntheticGo || syntheticKey === GO_SYNTHETIC_KEY, "native_auth");
        const goPostUrl = stockGo && readyRoute ? `${readyRoute.url.replace(/\/$/, "")}/chat/completions` : undefined;
        const effort = boot.reasoning_effort === "off" ? undefined : boot.reasoning_effort;
        // Go's private wire probe qualifies the exact configured catalog ID.
        // An SDK-derived alias is not authority to send work to a different ID.
        const baseWireModel = stockGo ? boot.model : resolveWireModelId(model, effort);
        const options = routing(model, baseWireModel);
        const openrouter = isOpenRouter(model);
        let selectedWireModel = baseWireModel;
        let sawPayload = false;
        let forwardedGoPost = false;
        let requestModel: string | undefined;
        const now = Date.now();
        const deadline = Math.min(now + body.timeout_ms, boot.deadline_unix_ms);
        const remaining = deadline - now;
        requireThat(remaining > 0, "native_deadline");
        const requestController = controller = new AbortController();
        const signal = requestController.signal;
        timer = setTimeout(() => requestController.abort(), remaining);
        // Independent Context: native history, hooks, rules and outer prompts never enter this object.
        const user = JSON.stringify({ kind: request.kind, request });
        const context = { systemPrompt: [body.policy], messages: [{ role: "user" as const,
          content: user, timestamp: now }], tools: [] };
        if (!stockGo) pi.appendEntry("agmi_omp_dispatch_v1", binding);
        const stream = streamSimple(model, context, {
          ...options, apiKey: syntheticGo ? syntheticKey : ctx.modelRegistry.resolver(model, boot.invocation_id),
          fetch: goPostUrl ? (url, init) => {
            if (requestFailure) throw requestFailure;
            let outgoing: RequestInit;
            try {
              requireThat(!forwardedGoPost && !terminal && requestModel !== undefined
                && String(url) === goPostUrl && init?.method === "POST", "native_identity");
              const serialized = init.body;
              requireThat(typeof serialized === "string" && serialized.length <= MAX_GO_POST
                && bytes(serialized) <= MAX_GO_POST, "native_identity");
              const payload: unknown = JSON.parse(serialized);
              requireGoPayload(payload, boot.model, effort, body.policy, user);
              // The native encoder uses JSON.stringify. Reject ambiguous duplicate/escaped
              // members rather than accepting only the values visible to JSON.parse.
              requireThat(JSON.stringify(payload) === serialized, "native_identity");
              const headers = new Headers(init.headers);
              const authorization = headers.get("authorization");
              requireThat(syntheticGo ? authorization === `Bearer ${GO_SYNTHETIC_KEY}`
                : authorization !== null && /^Bearer [A-Za-z0-9._~+/-]+=*$/.test(authorization), "native_auth");
              requireThat(headers.get("content-type")?.toLowerCase() === "application/json"
                && !["host", "content-length", "transfer-encoding", "content-encoding"].some(key => headers.has(key)), "native_identity");
              const effectiveSignal = init.signal ? AbortSignal.any([signal, init.signal]) : signal;
              requireThat(!effectiveSignal.aborted && Date.now() < deadline, "native_deadline");
              // Forward only the checked URL, immutable body and headers snapshot.
              outgoing = { method: "POST", body: serialized, headers, signal: effectiveSignal, redirect: "error" };
            } catch (e) {
              requestFailure = e instanceof Failure ? e : new Failure("native_identity");
              throw requestFailure;
            }
            forwardedGoPost = true;
            pi.appendEntry("agmi_omp_dispatch_v1", binding);
            if (probeResponse) {
              return Promise.resolve(new Response(probeResponse.body, {
                status: probeResponse.status, headers: { "Content-Type": probeResponse.mime },
              }));
            }
            return fetch(goPostUrl, outgoing);
          } : undefined,
          sessionId: boot.invocation_id, signal,
          reasoning: effort,
          disableReasoning: boot.reasoning_effort === "off", toolChoice: "none",
          disableServerSideFallback: true, maxHttpAttempts: 1, maxTokens: Math.min(MAX_OUTPUT / 4, model.maxTokens),
          onPayload: (payload, servingModel) => {
            if (requestFailure) throw requestFailure;
            if (stockGo) {
              try {
                // A caught rejection or a rebuilt payload must never authorize a POST.
                requireThat(requestModel === undefined, "native_effort");
                requireGoPayload(payload, boot.model, effort, body.policy, user);
                requestModel = boot.model;
              } catch (e) {
                requestFailure = e instanceof Failure ? e : new Failure("native_identity");
                throw requestFailure;
              }
              return;
            }
            const transport = servingModel ?? model;
            // Factory also forwards this hook from the shared completions
            // encoder. A rebuilt payload can silently negotiate a new effort.
            if (isChatCompletions(transport.api) && sawPayload) {
              requestFailure = new Failure("native_effort");
              throw requestFailure;
            }
            sawPayload = true;
            const mode = transport.compat?.wireModelIdMode;
            selectedWireModel = isChatCompletions(transport.api) && mode !== undefined
              ? applyWireModelIdTransform(baseWireModel, mode, options.openrouterVariant) : baseWireModel;
            const request = record(payload);
            if (!request) return;
            const id = request.model;
            if (id === undefined) return;
            if (typeof id !== "string" || !sameModel(id, selectedWireModel, openrouter, false)
              || (requestModel !== undefined && requestModel !== id)) {
              requestFailure = new Failure("native_identity");
              throw requestFailure;
            }
            if (toolEnabledModel(id, openrouter)) {
              requestFailure = new Failure("native_tool_call");
              throw requestFailure;
            }
            requestModel = id;
          },
          onResponse: (_response, servingModel) => {
            // The pinned Anthropic transport notifies before reading each
            // HTTP response, including replays that reuse the same payload.
            if ((servingModel ?? model).api === "anthropic-messages") {
              anthropicResponse = { stopped: false, ended: false };
            }
          },
          onSseEvent: (event, servingModel) => {
            if (event.data === "[DONE]" || !event.data) return;
            if (bytes(event.data) > 6 * MAX_OUTPUT + 4096) { wireOverflow = true; return; }
            try {
              const api = (servingModel ?? model).api;
              const observed = wireEvidence(event, api);
              wireBadStop ||= observed.badStop === true;
              if (api === "anthropic-messages" && anthropicResponse) {
                if (observed.anthropicStart !== undefined) {
                  // The SDK can splice a duplicate message_start into the
                  // first artifact. A single unambiguous start is required.
                  anthropicResponse.id = anthropicResponse.id === undefined
                    && typeof observed.anthropicStart === "string" && observed.anthropicStart.length > 0
                    ? observed.anthropicStart : null;
                }
                if (observed.anthropicEnd) anthropicResponse.ended = true;
                if (!anthropicResponse.ended && typeof anthropicResponse.id === "string" && observed.anthropicStop) {
                  anthropicResponse.stopped = true;
                }
              }
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
          requireThat(!signal.aborted, "native_deadline");
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
        requireThat(!signal.aborted && Date.now() < deadline, "native_deadline");
        if (requestFailure) throw requestFailure;
        requireThat(!stockGo || forwardedGoPost, "native_identity");
        requireThat(!wireOverflow, "native_output_limit");
        requireThat(!wireMismatch && final && final.provider === boot.provider && final.model === boot.model
          && (final.upstreamModel == null || (reportedIdentifier(final.upstreamModel) !== null
            && sameModel(final.upstreamModel, requestModel ?? selectedWireModel, openrouter, true))), "native_identity");
        requireThat(final.role === "assistant" && final.stopReason === "stop" && final.errorMessage == null
          && final.stopDetails?.type !== "pause_turn" && final.stopDetails?.type !== "compaction"
          && !wireBadStop, "native_completion");
        if (anthropicResponse || model.api === "anthropic-messages" || final.api === "anthropic-messages") {
          requireThat(anthropicResponse?.stopped && anthropicResponse.id === final.responseId, "native_completion");
        }
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
          ok: false, reason_code: (requestFailure ?? (e instanceof Failure ? e : undefined))?.code ?? "native_failure" });
      } finally { clearTimeout(timer); controller = undefined; }
    },
  });
}
