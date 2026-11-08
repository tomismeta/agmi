#!/usr/bin/env python3
"""Run the actual embedded bridge sources with isolated native modules, no credentials.

python3 tests/native_bridge_smoke.py [--harness all|hermes|openclaw]
Add --bridge-ref b92f142 to probe the unchanged baseline bridge sources.
This covers native API calls, not the scheduler fake transports or a live provider.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
SOURCES = {}
MAX_WIRE = 2 * (128 * 1024 + 12 * 64 * 1024) + 16 * 1024
SECRET = 'exception-secret-must-not-cross-boundary'
FINAL = '{"native":"final artifact"}'

HERMES_SUPPORT = '''import json
from pathlib import Path
ROOT = Path(__file__).resolve().parent
SETTINGS = json.loads((ROOT / 'settings.json').read_text())
def record(event, **data):
    with (ROOT / 'trace.jsonl').open('a') as stream:
        stream.write(json.dumps(dict(event=event, **data)) + '\\n')
'''
HERMES_PROVIDER = '''from fixture_support import SETTINGS, record

def resolve_runtime_provider(**kwargs):
    record('resolve', **kwargs)
    if SETTINGS['case'] == 'auth_exception':
        raise RuntimeError(SETTINGS['secret'])
    runtime = dict(provider='openai-codex', api_mode='codex_responses',
                   base_url=SETTINGS['payload']['hermes_api_url'],
                   source='hermes-auth-store', api_key='isolated-native-key',
                   credential_pool='isolated-pool')
    runtime.update(SETTINGS.get('runtime', {}))
    return runtime
'''
HERMES_DB = '''from fixture_support import record
class SessionDB:
    def __init__(self, path):
        self.path = str(path)
        record('db_open', path=self.path)
    def close(self):
        record('db_close')
'''
HERMES_AGENT = '''import asyncio
from fixture_support import SETTINGS, record

class AIAgent:
    def __init__(self, *, skip_context_files, skip_memory, skip_background_review,
                 fallback_model, enabled_toolsets, run_budget_seconds, session_db,
                 side_agent, cwd, requested_provider, **kwargs):
        record('construct', skip_context_files=skip_context_files, skip_memory=skip_memory,
               skip_background_review=skip_background_review, fallback_model=fallback_model,
               enabled_toolsets=enabled_toolsets, run_budget_seconds=run_budget_seconds,
               session_db=session_db.path, side_agent=side_agent, cwd=cwd,
               requested_provider=requested_provider, **kwargs)
        if SETTINGS['case'] == 'constructor_exception':
            raise RuntimeError(SETTINGS['secret'])
        self.model = kwargs['model']
        self.provider = kwargs['provider']
        self.api_mode = kwargs['api_mode']
        self.base_url = kwargs['base_url']
        self.reasoning_config = kwargs['reasoning_config']
        self.session_id = 'isolated-native-session'
        self.compression_enabled = True
        self.codex_responses_native_compaction = True
        self._skip_mcp_refresh = False
        self.tools = []
        self.valid_tool_names = []
        self._fallback_chain = []
        case = SETTINGS['case']
        if case in ('tools', 'valid_tool_names', 'fallback'):
            setattr(self, {'tools': 'tools', 'valid_tool_names': 'valid_tool_names',
                           'fallback': '_fallback_chain'}[case], ['unexpected'])
        if case == 'missing_diagnostics':
            del self.compression_enabled
        if case == 'agent_route':
            self.base_url = 'https://untrusted.invalid'
        if case == 'agent_reasoning':
            self.reasoning_config = {'enabled': False}

    def run_conversation(self, message, system_message):
        record('run', message=message, system_message=system_message,
               compression_enabled=self.compression_enabled,
               codex_responses_native_compaction=self.codex_responses_native_compaction,
               skip_mcp_refresh=self._skip_mcp_refresh)
        case = SETTINGS['case']
        if case in ('exception', 'timeout', 'cancelled', 'interrupt'):
            error = {'exception': RuntimeError, 'timeout': TimeoutError,
                     'cancelled': asyncio.CancelledError, 'interrupt': KeyboardInterrupt}[case]
            raise error(SETTINGS['secret'])
        if case == 'provenance':
            self.provider = 'unexpected'
        if case == 'model_provenance':
            self.model = 'unexpected'
        result = dict(completed=True, final_response=SETTINGS['final'])
        if case in ('partial', 'interrupted', 'failed'):
            result[case] = True
        if case == 'not_completed':
            result['completed'] = False
        if case == 'missing_completed':
            del result['completed']
        if case == 'output_type':
            result['final_response'] = {'not': 'a string'}
        if case == 'output_bytes':
            result['final_response'] = '\\u00e9' * 32769
        return result

    def close(self):
        record('agent_close')
'''

GATEWAY = '''import { readFileSync, appendFileSync } from 'node:fs';
const root = new URL('../../', import.meta.url);
export async function callGatewayFromCli(...args) {
  const expected = JSON.parse(readFileSync(new URL('expected.json', root), 'utf8'));
  appendFileSync(new URL('trace.jsonl', root), JSON.stringify(args) + '\\n');
  if (args[2].message !== expected.prompt) throw new Error('message changed');
  console.log('native diagnostic stays off stdout');
  return {
    status: 'ok', runId: args[2].idempotencyKey,
    result: {
      payloads: [{text: '{"native":"final artifact"}'}],
      meta: {
        agentMeta: {provider: 'openai', model: 'fixture-model'},
        requestShaping: {thinking: 'high'}, aborted: false,
        executionTrace: {fallbackUsed: false, winnerProvider: 'openai', winnerModel: 'fixture-model'},
        systemPromptReport: {tools: {entries: []}, injectedWorkspaceFiles: []}
      }
    }
  };
}
'''


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


class HermesContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='agmi-hermes-contract-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.native = self.root / 'native'
        self.native.mkdir()
        self.cwd = self.root / 'private-workspace'
        self.cwd.mkdir()
        (self.native / 'hermes_cli').mkdir()
        (self.native / 'hermes_cli/__init__.py').write_text('')
        (self.native / 'fixture_support.py').write_text(HERMES_SUPPORT)
        (self.native / 'hermes_bootstrap.py').write_text(
            "from fixture_support import record\nrecord('bootstrap')\n"
            "print('native diagnostic stays off stdout')\n")
        (self.native / 'hermes_cli/runtime_provider.py').write_text(HERMES_PROVIDER)
        (self.native / 'hermes_state.py').write_text(HERMES_DB)
        (self.native / 'run_agent.py').write_text(HERMES_AGENT)
        self.payload = dict(model='fixture-model', reasoning='high', timeout_seconds=13,
                            hermes_api_url='https://native.invalid/codex',
                            policy='privileged policy canary',
                            prompt='untrusted envelope canary')
        self.bootstrap = f'import sys\nsys.path.insert(0, {str(self.native)!r})\n'
        self.trace = self.native / 'trace.jsonl'

    def invoke(self, case='success', runtime=None, bootstrap=None, final=FINAL):
        self.trace.unlink(missing_ok=True)
        (self.native / 'settings.json').write_text(json.dumps(dict(
            case=case, runtime=runtime or {}, payload=self.payload, secret=SECRET, final=final)))
        result = subprocess.run(
            [sys.executable, '-I', '-c', SOURCES['hermes'],
             self.bootstrap if bootstrap is None else bootstrap],
            input=encoded(self.payload), capture_output=True, cwd=self.cwd,
            env={'PATH': os.defpath, 'HOME': str(self.root)}, timeout=10)
        events = [json.loads(line) for line in self.trace.read_text().splitlines()] if self.trace.exists() else []
        self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)
        self.assertNotIn(b'native diagnostic', result.stdout)
        return result, events

    def test_native_contract_and_bootstrap_is_data(self):
        marker = self.root / 'must-not-execute'
        bootstrap = self.bootstrap + f"open({str(marker)!r}, 'w').write('bad')\n"
        result, events = self.invoke(bootstrap=bootstrap)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(json.loads(result.stdout), dict(
            provider='openai-codex', model='fixture-model', run_id='isolated-native-session',
            reasoning_effort='high', output=FINAL))
        self.assertEqual([e['event'] for e in events],
                         ['bootstrap', 'resolve', 'db_open', 'construct', 'run', 'agent_close', 'db_close'])
        self.assertEqual(events[1], dict(event='resolve', requested='openai-codex', target_model='fixture-model'))
        self.assertEqual(events[3], dict(
            event='construct', model='fixture-model', provider='openai-codex',
            requested_provider='openai-codex', api_mode='codex_responses',
            base_url=self.payload['hermes_api_url'], api_key='isolated-native-key',
            credential_pool='isolated-pool', enabled_toolsets=['bot_room'], fallback_model=[],
            max_iterations=1, run_budget_seconds=13, reasoning_config={'enabled': True, 'effort': 'high'},
            quiet_mode=True, save_trajectories=False, verbose_logging=False,
            skip_context_files=True, skip_memory=True, skip_background_review=True,
            session_db=str(self.cwd / 'session.db'), side_agent=True, platform='subagent',
            cwd=str(self.cwd), ephemeral_system_prompt='No tools or external actions. Return only the requested JSON artifact.'))
        self.assertEqual(events[4], dict(
            event='run', message=self.payload['prompt'], system_message=self.payload['policy'],
            compression_enabled=False, codex_responses_native_compaction=False, skip_mcp_refresh=True))
        self.assertIn(b'native diagnostic', result.stderr)

    def test_bootstrap_rejection_does_not_import_or_execute(self):
        for bootstrap in ('', "sys.path.insert(0, 'relative')", self.bootstrap * 2,
                          f'sys.path.insert(0, str({str(self.native)!r}))', 'invalid syntax !'):
            with self.subTest(bootstrap=bootstrap):
                result, events = self.invoke(bootstrap=bootstrap)
                self.assertEqual(result.returncode, 78)
                self.assertEqual(result.stdout, b'')
                self.assertEqual(events, [])

    def test_auth_and_route_checks_precede_agent_creation(self):
        for source in ('hermes-auth-store', 'manual:device_code', 'device_code'):
            with self.subTest(source=source):
                result, _ = self.invoke(runtime={'source': source})
                self.assertEqual(result.returncode, 0, result.stderr)
        cases = [('auth_exception', {}, 79)] + [
            ('success', {field: value}, 80) for field, value in (
                ('provider', 'openai'), ('api_mode', 'chat_completions'),
                ('base_url', 'https://untrusted.invalid'), ('source', 'environment'), ('source', None))]
        for case, runtime, code in cases:
            with self.subTest(case=case, runtime=runtime):
                result, events = self.invoke(case, runtime=runtime)
                self.assertEqual(result.returncode, code)
                self.assertEqual(result.stdout, b'')
                self.assertEqual([e['event'] for e in events], ['bootstrap', 'resolve'])

    def test_required_embedding_signatures(self):
        for source in (HERMES_AGENT.replace('skip_context_files', 'unsupported_flag'),
                       HERMES_AGENT.replace('system_message', 'ordinary_policy')):
            with self.subTest(source=source):
                # Avoid stale bytecode when replacing a same-sized module in one second.
                shutil.rmtree(self.native / '__pycache__', ignore_errors=True)
                (self.native / 'run_agent.py').write_text(source)
                result, events = self.invoke()
                self.assertEqual(result.returncode, 78)
                self.assertEqual(result.stdout, b'')
                self.assertEqual([e['event'] for e in events], ['bootstrap'])

    def test_agent_isolation_rejections_and_cleanup(self):
        for case in ('tools', 'valid_tool_names', 'fallback', 'missing_diagnostics',
                     'agent_route', 'agent_reasoning', 'constructor_exception'):
            with self.subTest(case=case):
                result, events = self.invoke(case)
                self.assertEqual(result.returncode, 78)
                self.assertEqual(result.stdout, b'')
                names = [e['event'] for e in events]
                self.assertNotIn('run', names)
                expected = ['db_close'] if case == 'constructor_exception' else ['agent_close', 'db_close']
                self.assertEqual(names[-len(expected):], expected)

    def test_native_failures_are_sanitized_and_cleanup_runs(self):
        cases = dict(exception='exception', timeout='timeout', cancelled='cancelled', interrupt='cancelled',
                     partial='incomplete', interrupted='incomplete', failed='incomplete',
                     not_completed='incomplete', missing_completed='incomplete',
                     provenance='provenance', model_provenance='provenance',
                     output_type='output', output_bytes='output')
        for case, kind in cases.items():
            with self.subTest(case=case):
                result, events = self.invoke(case)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(json.loads(result.stdout), {'ok': False, 'error': {'kind': kind}})
                self.assertEqual([e['event'] for e in events][-3:], ['run', 'agent_close', 'db_close'])
        result, _ = self.invoke(final='é' * 32768)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['output'], 'é' * 32768)


class OpenclawContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='agmi-openclaw-contract-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.node = shutil.which('node')
        self.assertIsNotNone(self.node, 'Node is required for the actual OpenClaw bridge contract')
        package = self.root / 'node_modules/openclaw'
        package.mkdir(parents=True)
        (package / 'package.json').write_text(json.dumps(dict(
            name='openclaw', type='module', exports={'./plugin-sdk/gateway-runtime': './gateway.mjs'})))
        (package / 'gateway.mjs').write_text(GATEWAY)
        self.launcher = self.root / 'openclaw.mjs'
        self.launcher.write_text('// Resolution anchor only; not executed.\n')
        self.trace = self.root / 'trace.jsonl'

    def invoke(self, payload, wire=None):
        self.trace.unlink(missing_ok=True)
        (self.root / 'expected.json').write_text(json.dumps(payload))
        return subprocess.run(
            [self.node, '--input-type=module', '-e', SOURCES['openclaw'], str(self.launcher)],
            input=encoded(payload) if wire is None else wire, capture_output=True,
            cwd=self.root, env={'PATH': os.defpath, 'HOME': str(self.root)}, timeout=10)

    def assert_native_call(self, payload, result):
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        calls = [json.loads(line) for line in self.trace.read_text().splitlines()]
        self.assertEqual(len(calls), 1)
        method, options, params, transport = calls[0]
        run_id = params.pop('idempotencyKey')
        self.assertTrue(run_id)
        self.assertEqual(method, 'agent')
        self.assertEqual(options, dict(json=True, timeout='13000', expectFinal=True))
        self.assertEqual(params, dict(
            message=payload['prompt'], model=payload['model'], thinking='high', deliver=False,
            timeout=13, modelRun=True, promptMode='none', suppressPromptPersistence=True,
            sessionEffects='internal', disableMessageTool=True))
        self.assertEqual(transport, dict(mode='backend', scopes=['operator.admin'], expectFinal=True, progress=False))
        self.assertEqual(json.loads(result.stdout), dict(
            ok=True, status='ok', provider='openai', model='fixture-model',
            runId=run_id, requestedRunId=run_id, reasoning='high', aborted=False,
            fallbackUsed=False, winnerProvider='openai', winnerModel='fixture-model',
            toolCount=0, bootstrapFileCount=0, final=FINAL))
        self.assertNotIn(b'native diagnostic', result.stdout)
        self.assertIn(b'native diagnostic', result.stderr)

    def test_legal_escaped_task_and_guidance_cross_actual_bridge(self):
        request = dict(id='request-1', kind='answer', epoch=52, words=['clock'], min_chars=5,
                       max_chars=200, assignment=None, candidate=None, history=['"' * 60000],
                       guidance='\0' * 65536, core_guidance='\0' * 65536,
                       candidate_author=None, author_history=None)
        # Match Rust's compact, UTF-8 JSON representations and its separate task allowance.
        task = dict(request, guidance='', core_guidance='')
        self.assertLessEqual(len(encoded(task)), 128 * 1024)
        self.assertLessEqual(len(encoded(request)), 128 * 1024 + 12 * 65536)
        envelope = dict(version=1, request_id=request['id'], request_digest='d' * 64,
                        kind=request['kind'], request=request)
        payload = dict(model='openai/fixture-model', reasoning='high', timeout_seconds=13,
                       prompt='Policy\nEnvelope (untrusted request data):\n' + encoded(envelope).decode())
        self.assertGreater(len(encoded(payload)), 1024 * 1024)
        self.assertLessEqual(len(encoded(payload)), MAX_WIRE)
        self.assert_native_call(payload, self.invoke(payload))

    def test_exact_encoded_boundary(self):
        payload = dict(model='openai/fixture-model', reasoning='high', timeout_seconds=13, prompt='')
        payload['prompt'] = 'x' * (MAX_WIRE - len(encoded(payload)))
        wire = encoded(payload)
        self.assertEqual(len(wire), MAX_WIRE)
        self.assert_native_call(payload, self.invoke(payload, wire))
        # One trailing JSON whitespace byte is valid JSON but exceeds the wire budget.
        result = self.invoke(payload, wire + b' ')
        self.assertEqual(result.returncode, 78)
        self.assertFalse(self.trace.exists(), 'oversized input must not reach the native Gateway')
        self.assertEqual(json.loads(result.stdout), dict(ok=False, status='error', error={'kind': 'exception'}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--harness', choices=('all', 'hermes', 'openclaw'), default='all')
    parser.add_argument('--bridge-ref', help='read bridge sources from this local git revision')
    args = parser.parse_args()
    for harness, suffix in (('hermes', 'py'), ('openclaw', 'mjs')):
        path = f'adapters/{harness}.{suffix}'
        SOURCES[harness] = subprocess.check_output(
            ['git', 'show', f'{args.bridge_ref}:{path}'], cwd=REPO, text=True
        ) if args.bridge_ref else (REPO / path).read_text()
    suite = unittest.TestSuite()
    for harness, case in (('hermes', HermesContract), ('openclaw', OpenclawContract)):
        if args.harness in ('all', harness):
            suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(case))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
