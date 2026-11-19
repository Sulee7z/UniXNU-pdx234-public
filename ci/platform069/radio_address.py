"""Wi-Fi-only early publication overlay qualified against build007."""
import hashlib


ADDRESS_BODIES = {
    'bool boardMac(': 'e3fda429b3c79388bd249b7b1995e58556f0d3acc84513b2ce252adc5b516d06',
    'int macFile(': '6add1280716fccd971e9b038ebeef509eb4e46395998b97f077df1253c236f6d',
    'void publishMac(': 'c4bde74789dc668515c82e200e277d54261ba131e2b95825f37254ea7ec4cca5',
}


def function(text: str, signature: str) -> str:
    if text.count(signature) != 1:
        raise ValueError('Require one radio function: ' + signature)
    start = text.index(signature)
    opening = text.index('{', start)
    depth = 1
    at = opening + 1
    while depth:
        if at >= len(text):
            raise ValueError('Unterminated radio source body')
        if text[at] == '{':
            depth += 1
        elif text[at] == '}':
            depth -= 1
        at += 1
    return text[start:at]


def validate_bodies(text: str) -> dict:
    hashes = {signature: hashlib.sha256(function(text, signature).encode()).hexdigest()
              for signature in ADDRESS_BODIES}
    if hashes != ADDRESS_BODIES:
        raise ValueError('Pinned radio address-source ABI changed')
    return hashes


def wifi(text: str) -> str:
    """Publish after provider/ITS prerequisites, before scheduling the bounded worker."""
    validate_bodies(text)
    signature = 'extern "C" void native_sony_wifi_start(void)'
    start = function(text, signature)
    if text.count('extern "C" int native_sony_wifi_publish(void);') or 'addressError069' in start:
        raise ValueError('Wi-Fi early publication overlay was already applied')
    schedule_anchor = '    uint32_t expected=0;\n'
    if (start.count(schedule_anchor) != 1 or 'if(ready){native_wifi_stats[0]=(uint32_t)-ready;return;}\n' not in start or
            start.index('if(ready)') > start.index(schedule_anchor) or 'stage < 1) return;' not in start):
        raise ValueError('Actual Sony Wi-Fi readiness/worker scheduling anchor differs')
    insert = ('    const int addressError069=native_sony_wifi_publish();\n'
              '    if(addressError069){native_wifi_stats[0]=(uint32_t)-addressError069;return;}\n')
    changed = start.replace(schedule_anchor, insert + schedule_anchor)
    # No duplicate callback or MAC generation policy: only a synchronous checked
    # call at the already-selected Wi-Fi entry. Firmware qualification stays in
    # the bounded worker; existing worker publishMac and source logic stay intact.
    return 'extern "C" int native_sony_wifi_publish(void);\n' + text.replace(start, changed)
