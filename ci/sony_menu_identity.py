"""Keep the Sony menu's OS label consistent with its D27 iOS payload."""
import re
import tomllib

def correct_title(text):
    before=tomllib.loads(text)
    title=before.get('ui',{}).get('title','')
    if 'iPadOS27' not in title:
        if 'iOS 27' in title:return text
        raise ValueError('Unknown Sony menu OS title')
    if not title.startswith('Sony PDX234 ') or 'D27' not in title:
        raise ValueError('Not the Sony D27 menu')
    entry=next(e for e in before['entry'] if e['id']=='xnu')
    if 'iPhone14,7' not in entry['title'] or '24A446' not in entry['title']:
        raise ValueError('Unexpected payload identity')
    replacement=title.replace('iPadOS27','iOS 27')
    pattern=r'(?m)^(title\s*=\s*")'+re.escape(title)+r'("\s*)$'
    result,count=re.subn(pattern,lambda m:m[1]+replacement+m[2],text)
    if count!=1:raise ValueError('Ambiguous menu title')
    after=tomllib.loads(result);after['ui']['title']=title
    if after!=before:raise ValueError('Non-title configuration changed')
    return result

def select_ios_default(text):
    text=correct_title(text)
    before=tomllib.loads(text)
    if before['boot']['default']=='xnu':return text
    if before['boot']['default']!='restart':raise ValueError('Unknown default boot selection')
    result,count=re.subn(r'(?m)^default\s*=\s*"restart"\s*$', 'default = "xnu"',text)
    if count!=1:raise ValueError('Ambiguous boot default')
    after=tomllib.loads(result);after['boot']['default']='restart'
    if after!=before:raise ValueError('Other boot configuration changed')
    return result
