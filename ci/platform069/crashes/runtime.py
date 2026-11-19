"""Composable exact-D27 launch-cache request; no executable, identity or budget edits."""
from copy import deepcopy
from pathlib import Path
import hashlib
import plistlib

ICON_LABEL = 'com.apple.iconservices.iconservicesagent'
ICON_ENVIRONMENT = {'FORCE_SOFTWARE_RENDERER': '0', 'CI_ENABLE_METAL_GPU': '0'}


def merge_icon_environment(environment):
    output = deepcopy(environment or {})
    selected = output.setdefault(ICON_LABEL, {})
    for key, value in ICON_ENVIRONMENT.items():
        if key in selected and selected[key] != value:
            raise ValueError('Conflicting icon renderer environment: ' + key)
        selected[key] = value
    return output


def selected_jobs(cache):
    data = plistlib.loads(Path(cache).read_bytes())
    wanted = {ICON_LABEL, 'com.apple.filesystems.fskitd', 'com.apple.pfd', 'com.apple.bluetoothd', 'com.apple.aonsensed'}
    output = {}
    for path, job in data['LaunchDaemons'].items():
        label = job.get('Label')
        if label in wanted:
            if label in output:
                raise ValueError('Ambiguous original job: ' + label)
            output[label] = {'cache_key': path, 'job': deepcopy(job)}
    if set(output) != wanted:
        raise ValueError('Incomplete D27 job inventory:' + repr(set(output)))
    return output


def apply_to_cache_bytes(raw):
    """Compose on main/radio's cache; preserve every other field and top-level tree.

    Serialization/signing belongs to main. Returned dictionary can be passed to
    the official cache builder's job_environment after merging its own values.
    """
    before = plistlib.loads(raw)
    after = deepcopy(before)
    matches = [job for job in after['LaunchDaemons'].values() if job.get('Label') == ICON_LABEL]
    if len(matches) != 1:
        raise ValueError('Expected one D27 icon agent in actual runtime cache')
    values = matches[0].setdefault('EnvironmentVariables', {})
    for key, value in ICON_ENVIRONMENT.items():
        if key in values and values[key] != value:
            raise ValueError('Conflicting selected icon environment:' + key)
        values[key] = value
    changed = []
    for key, old in before['LaunchDaemons'].items():
        if old != after['LaunchDaemons'][key]:
            expected = deepcopy(old)
            expected.setdefault('EnvironmentVariables', {}).update(ICON_ENVIRONMENT)
            if old.get('Label') != ICON_LABEL or expected != after['LaunchDaemons'][key]:
                raise ValueError('Unexpected runtime cache mutation')
            changed.append(key)
    if any(before[key] != after[key] for key in before if key != 'LaunchDaemons'):
        raise ValueError('Non-daemon cache fields changed')
    return after, {'source_sha256': hashlib.sha256(raw).hexdigest(), 'changed_jobs': changed,
                   'job_environment': {ICON_LABEL: ICON_ENVIRONMENT}, 'budgets_and_identity_unchanged': True,
                   'no_disabled_jobs': True, 'owner_serializer_and_detached_signing_required': True}
