"""Two explicit069 XNU choices, each checked against the real request capacity."""
import copy
import json
import tomllib

from darwin_boot_args import validate
from platform069.skip_setup import menu_entry

BASELINE_IMAGE_SHA='0712a1914bbdec7fcedf119635430444db182b5c3e833422d325b03cda851ab1'
PROTECTED={
    'data-persist':'0','qcom-usb-debug':'0','sony-touch':'1','touch-hid':'1',
    'gpu-power':'9','gpu-metal':'1','sheng-gpu-addon':'1','fb-gpu':'1',
    'smp':'1','sheng-smp':'1','banner':'0','boot-diag-resume':'0',
    'first-frame-diag':'0','gpu-trace':'0','sheng-gpu-trace':'0',
}
ALLOWED={'cpufreq','cpufreq-cap','vsync','gpu-dcvs','gpu-dcvs-min','gpu-fence-wake',
    'gpu-pause-us','sony-platform-performance','sony-buttons','sony-buttons-read-qualified',
    'sony-buttons-pon-apid','sony-display-timing','sony-perf-samples','storage-probe',
    'wifi','bluetooth','backlight','sony-wifi','sony-bluetooth','sony-wcn',
    'sony-oled-backlight','sony-backlight','panel120'}


def updated_arguments(before,changes):
    tokens=before.split()
    if tokens.count('build-tag=PDX068')!=1:raise ValueError('Exact068 tag required')
    keys=[token.split('=',1)[0] for token in tokens]
    if len(keys)!=len(set(keys)):raise ValueError('Duplicate baseline boot argument')
    for key,value in PROTECTED.items():
        if tokens.count(key+'='+value)!=1:raise ValueError('Protected physical baseline argument differs: '+key)
    for key,value in changes.items():
        if key not in ALLOWED or not isinstance(value,int) or isinstance(value,bool) or value<0:
            raise ValueError('Unreviewed069 boot argument: '+key)
        if key == 'panel120' and value not in (0,1):
            raise ValueError('panel120 must be 0 or 1')
        token=key+'='+str(value)
        if key in keys:tokens[keys.index(key)]=token
        else:keys.append(key);tokens.append(token)
    tokens[tokens.index('build-tag=PDX068')]='build-tag=PDX069'
    arguments=' '.join(tokens);validate(arguments);return arguments


def validate_choices(config,arguments):
    if (config['boot']['default']!='xnu' or config['boot']['timeout']!=-1 or
            config['kits']['autoload'] is not False):raise ValueError('Manual normal default must remain unchanged')
    entries=config['entry'];ids=[entry['id'] for entry in entries]
    if len(ids)!=len(set(ids)):raise ValueError('Duplicate menu choice')
    choices={entry['id']:entry for entry in entries if entry['type']=='xnu'}
    if set(choices)!={'xnu','xnu-skip-setup'}:raise ValueError('Exactly normal and Skip Setup XNU choices required')
    normal=choices['xnu'];skip=choices['xnu-skip-setup']
    if (normal.get('confirm') or normal['initrd']!='Payloads/scratch-data.img' or
            normal['path']!='Payloads/kernel.macho' or normal['args']!=arguments or
            skip!=menu_entry(normal,'Payloads/scratch-data-skip-setup.img')):
        raise ValueError('Normal or Skip Setup path/policy changed')
    return {name:validate(entry['args']) for name,entry in choices.items()}


def render(before,arguments):
    original=tomllib.loads(before)
    if any(entry['id']=='xnu-skip-setup' for entry in original['entry']):raise ValueError('Baseline already has Skip Setup')
    expected=copy.deepcopy(original);normal=next(entry for entry in expected['entry'] if entry['id']=='xnu')
    if before.count(json.dumps(normal['args']))!=1:raise ValueError('Unique baseline argument string required')
    text=before.replace(json.dumps(normal['args']),json.dumps(arguments))
    old_title=expected['ui']['title'];title=old_title.replace('PAC-ABI-068','PAC-ABI-069')
    if old_title==title or text.count(json.dumps(old_title))!=1:raise ValueError('Unique068 menu title required')
    text=text.replace(json.dumps(old_title),json.dumps(title));expected['ui']['title']=title;normal['args']=arguments
    skip=menu_entry(normal,'Payloads/scratch-data-skip-setup.img')
    index=expected['entry'].index(normal)+1;expected['entry'].insert(index,skip)
    sections=text.split('[[entry]]')
    if len(sections)!=len(original['entry'])+1:raise ValueError('Unexpected menu section syntax')
    section='[[entry]]\n'+''.join(name+' = '+json.dumps(value)+'\n' for name,value in skip.items())
    # The qualified baseline normal entry is first. All action entries stay in
    # their original order and retain their exact text.
    if original['entry'][0]['id']!='xnu':raise ValueError('Normal baseline choice must remain first')
    text=sections[0]+'[[entry]]'+sections[1]+section+''.join('[[entry]]'+part for part in sections[2:])
    actual=tomllib.loads(text)
    if actual!=expected:raise ValueError('Unintended menu edit')
    return text,validate_choices(actual,arguments)
