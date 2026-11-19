"""Extract and apply the official Skip Setup preference policy, not activation records."""
import ast
import copy
import hashlib
from pathlib import Path
import plistlib

OFFICIAL_SHA='6a1d6275e55e1b835b63c26e6b42a2f8c1a4b66a81cd2ce1433d1668f4e9000a'
PREFERENCES=('com.apple.migration','com.apple.springboard','com.apple.purplebuddy',
             'com.apple.purplebuddy.notbackedup','com.apple.managedconfiguration.notbackedup')
BUILD='24A446'


def official_values(script,build=BUILD,no_auto_dim=False):
    raw=Path(script).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=OFFICIAL_SHA:raise ValueError('Pinned official Skip Setup source changed')
    if build!=BUILD:raise ValueError('D27 target build must remain24A446')
    tree=ast.parse(raw.decode());main=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
    result={}
    for node in ast.walk(main):
        if not isinstance(node,ast.Call) or not isinstance(node.func,ast.Name) or node.func.id!='merge_pref':continue
        if len(node.args)!=3 or not isinstance(node.args[1],ast.Constant):raise ValueError('Unexpected official merge interface')
        name=node.args[1].value
        if name not in PREFERENCES or name in result:raise ValueError('Unknown or duplicate official preference')
        # Evaluate only a pinned policy expression. No filesystem, imports or
        # script main/hdiutil calls are executed by this extractor.
        expression=ast.Expression(node.args[2]);ast.fix_missing_locations(expression)
        values=eval(compile(expression,str(script),'eval'),{'__builtins__':{}},{'BUILD':build,'no_auto_dim':no_auto_dim})
        if not isinstance(values,dict):raise ValueError('Official preference is not a dictionary')
        result[name]=values
    if set(result)!=set(PREFERENCES):raise ValueError('Incomplete official Skip Setup policy')
    return result


def merge_existing(existing,values):
    if not isinstance(existing,dict) or not isinstance(values,dict):raise ValueError('Preference root must be a dictionary')
    result=copy.deepcopy(existing);result.update(copy.deepcopy(values));return result


def encode_preferences(existing,values):
    return {name:plistlib.dumps(merge_existing(existing.get(name,{}),policy),fmt=plistlib.FMT_BINARY)
            for name,policy in values.items()}


def menu_entry(normal,skip_seed_path):
    """An additional explicit menu choice; never change the normal entry/default."""
    if normal.get('id')!='xnu' or normal.get('type')!='xnu' or normal.get('confirm'):
        raise ValueError('Expected the qualified normal XNU entry')
    if skip_seed_path!='Payloads/scratch-data-skip-setup.img':raise ValueError('Unexpected seed path')
    result=copy.deepcopy(normal);result.update(id='xnu-skip-setup',title='Boot iOS - Skip Setup (initial settings)',initrd=skip_seed_path)
    return result
