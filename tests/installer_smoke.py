#!/usr/bin/env python3
import hashlib, json, os, pathlib, shutil, subprocess, sys, tempfile
binary = pathlib.Path(sys.argv[1]).resolve()
installer = pathlib.Path(__file__).resolve().parents[1] / 'deploy/install-user.sh'
if sys.platform != 'linux':
    raise SystemExit('Run this GNU/Linux installer regression on Linux.')
with tempfile.TemporaryDirectory(prefix='agmi-installer-race-') as d:
    root = pathlib.Path(d); home = root/'home'; home.mkdir(mode=0o700)
    tools = root/'tools'; tools.mkdir()
    candidate = root/'candidate'; shutil.copy2(binary, candidate)
    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    marker = root/'executed'
    script = '''#!/usr/bin/env python3
import os, pathlib, subprocess, sys
candidate = pathlib.Path(os.environ['AGMI_RACE_CANDIDATE'])
if str(candidate) in sys.argv[1:] and not pathlib.Path(os.environ['AGMI_RACE_SWAPPED']).exists():
    temporary = candidate.with_suffix('.replacement')
    temporary.write_text('#!/bin/sh\\nprintf executed > "$AGMI_ATTACK_MARKER"\\nexit 1\\n')
    temporary.chmod(0o700); temporary.replace(candidate)
    pathlib.Path(os.environ['AGMI_RACE_SWAPPED']).touch()
raise SystemExit(subprocess.run(['/usr/bin/du', *sys.argv[1:]]).returncode)
'''
    (tools/'du').write_text(script); (tools/'du').chmod(0o700)
    for name in ('systemctl','systemd-analyze'):
        (tools/name).write_text('#!/bin/sh\nexit 0\n'); (tools/name).chmod(0o700)
    env = dict(os.environ, HOME=str(home), PATH=str(tools)+':'+os.environ['PATH'],
               AGMI_RACE_CANDIDATE=str(candidate), AGMI_RACE_SWAPPED=str(root/'swapped'), AGMI_ATTACK_MARKER=str(marker))
    result = subprocess.run(['sh', str(installer), 'stage', str(candidate), '--sha256', digest], env=env, capture_output=True, text=True)
    assert result.returncode != 0, result.stdout
    assert (root/'swapped').exists(), result.stderr
    observed = marker.exists()
    assert not observed, 'A candidate replaced after verification was executed'
    assert not (home/'.local/share/agmi/releases/current').exists()
    print(json.dumps({'scenario':'candidate_replaced_after_hash','unverified_candidate_executed':observed,'pointer_changed':False}))
