"""Generate Shadowrocket native privacy rules from public upstreams."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import datetime
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import tomllib
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError


DOMAIN_OPTIONS = {'pre-matching', 'extended-matching', 'no-resolve'}
EXTRA_TYPES = {'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'IP-CIDR', 'IP-CIDR6',
               'IP-ASN', 'GEOIP', 'PROCESS-NAME', 'PROCESS-PATH', 'URL-REGEX',
               'USER-AGENT', 'DST-PORT', 'SRC-PORT', 'SRC-IP', 'PROTOCOL',
               'AND', 'OR', 'NOT'}
LIMIT = 24_000_000


@dataclass
class Parsed:
    source: dict
    domains: set
    extras: set
    skipped_other_policies: int
    sha256: str
    fallback: bool = False
    protected: set = field(default_factory=set)


def domain(value):
    value = value.strip().lower().rstrip('.')
    if not re.fullmatch(r'[a-z0-9_-]+(?:\.[a-z0-9_-]+)*', value):
        raise ValueError('Invalid domain in source')
    if len(value) > 253 or any(len(label) > 63 for label in value.split('.')):
        raise ValueError('Oversized domain in source')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('An IP address cannot be used as a domain rule')


def parse(source, body):
    text = body.decode('utf-8-sig')
    if '<html' in text[:1024].lower() or text.lstrip().startswith('<!DOCTYPE'):
        raise ValueError('HTML received instead of rules')
    domains, extras, protected = set(), set(), set()
    skipped = 0
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(('#', ';', '//')):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line.lower()
            continue
        if source['format'] == 'module' and section != '[rule]':
            continue
        if source['format'] == 'domainset':
            kind = 'DOMAIN-SUFFIX' if line.startswith('.') else 'DOMAIN'
            domains.add((kind, domain(line.lstrip('.')), ()))
            continue
        fields = [field.strip() for field in line.split(',')]
        kind = fields[0].upper()
        if kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
            if len(fields) < 2:
                raise ValueError('Incomplete domain rule')
            name = domain(fields[1])
            tail = fields[2:]
            if source['format'] == 'module' and not tail:
                raise ValueError('Module rule missing policy')
            if tail and tail[0].upper() not in {option.upper() for option in DOMAIN_OPTIONS}:
                policy = tail.pop(0).upper()
                if policy != source['policy']:
                    skipped += 1
                    if source['use'] == 'routing':
                        raise ValueError('Routing source has a different policy; preserve its ordered exceptions')
                    # A mixed feature module may deliberately allow a child or
                    # use another response policy. Do not preempt it at DNS time.
                    protected.add((kind, name))
                    continue
            options = tuple(option.lower() for option in tail)
            if any(option not in DOMAIN_OPTIONS for option in options):
                raise ValueError('Unknown domain option; refusing to widen its scope')
            domains.add((kind, name, options))
        elif source['use'] == 'routing':
            if kind not in EXTRA_TYPES or len(fields) < 2:
                raise ValueError('Unsupported routing rule; refusing to silently drop it')
            # Preserve regexes and logical conditions as raw rules, including commas.
            policies = list(re.finditer(r',\s*(DIRECT|REJECT)\s*(?=,|$)', line, re.I))
            if policies:
                if policies[-1][1].upper() != source['policy']:
                    raise ValueError('Extra rule policy differs from source policy')
                extras.add(line)
            elif source['format'] == 'module':
                raise ValueError('Module extra rule missing policy')
            else:
                options = []
                while fields[-1].lower() in DOMAIN_OPTIONS:
                    options.insert(0, fields.pop().lower())
                extras.add(','.join(fields + [source['policy']] + options))
    if len(domains) < source.get('min_domains', 1):
        raise ValueError('Source domain count fell below its configured minimum')
    return Parsed(source, domains, extras, skipped, hashlib.sha256(body).hexdigest(), protected=protected)


def parents(name):
    labels = name.split('.')
    return {'.'.join(labels[index:]) for index in range(len(labels))}


def scopes_overlap(left, right):
    left_kind, left_name = left
    right_kind, right_name = right
    if left_kind == 'DOMAIN' and right_kind == 'DOMAIN':
        return left_name == right_name
    if left_kind == 'DOMAIN':
        return right_name in parents(left_name)
    if right_kind == 'DOMAIN':
        return left_name in parents(right_name)
    return left_name in parents(right_name) or right_name in parents(left_name)


def build(parsed, checks, corrections=None):
    corrections = corrections or {}
    routing = {'DIRECT': set(), 'REJECT': set()}
    extras = {'DIRECT': set(), 'REJECT': set()}
    sources = []
    candidates = {}
    protected = set()
    for item in parsed:
        protected.update(item.protected)
    protected.update(('DOMAIN', domain(name)) for name in corrections.get('allow', {}).get('exact', []))
    protected.update(('DOMAIN-SUFFIX', domain(name)) for name in corrections.get('allow', {}).get('suffix', []))
    for item in parsed:
        policy = item.source['policy']
        for kind, name, options in item.domains:
            if item.source['use'] == 'routing':
                routing[policy].add(','.join((kind, name, policy, *options)))
            if policy == 'REJECT' and (item.source['use'] == 'routing' or item.source.get('early', False)):
                candidates.setdefault((kind, name), set()).update(options)
        if item.source['use'] == 'routing':
            extras[policy].update(item.extras)
        sources.append({'name': item.source['name'], 'url': item.source['url'],
                        'sha256': item.sha256, 'domains': len(item.domains),
                        'extra_rules': len(item.extras),
                        'fallback': item.fallback,
                        'fallback_recorded': item.source.get('fallback_recorded') if item.fallback else None,
                        'skipped_other_policies': item.skipped_other_policies})
    early, deferred = [], []
    for scope, options in sorted(candidates.items()):
        if any(scopes_overlap(scope, exception) for exception in protected):
            deferred.append({'kind': scope[0], 'domain': scope[1], 'reason': 'overlaps explicit exception or another feature policy'})
            continue
        options.add('pre-matching')
        early.append(','.join((*scope, 'REJECT', *sorted(options))))
    for name in checks.get('early', []):
        if not any(row.split(',')[1] == name or
                   (row.startswith('DOMAIN-SUFFIX,') and row.split(',')[1] in parents(name))
                   for row in early):
            raise ValueError('A required native early-reject check failed')
    for name in checks.get('early_unbound', []):
        if any(row.split(',')[1] == name or
               (row.startswith('DOMAIN-SUFFIX,') and row.split(',')[1] in parents(name))
               for row in early):
            raise ValueError('A normal control was included in the early-reject module')
    files = {}
    files['native-reject.module'] = (
        '#!name=Shadowrocket Privacy Reject\n'
        '#!desc=Whole-domain native pre-matching; explicit exceptions are deferred.\n'
        '# Source hashes: manifest.json.\n'
        '[Rule]\n'
        + '\n'.join(early) + '\n')
    deferred_scopes = {(item['kind'], item['domain']) for item in deferred}
    deferred_rows = sorted(row for row in routing['REJECT']
                           if tuple(row.split(',')[:2]) in deferred_scopes)
    deferred_rows += sorted(extras['REJECT'])
    def reject_without_policy(row):
        matches = list(re.finditer(r',\s*REJECT\s*(?=,|$)', row, re.I))
        match = matches[-1]
        return row[:match.start()] + row[match.end():]
    files['reject-deferred.list'] = (
        '# Connection-stage fallback only; keep specific normal routing before this reference.\n'
        + ('\n'.join(reject_without_policy(row) for row in deferred_rows) + '\n' if deferred_rows else ''))
    def direct_without_policy(row):
        matches = list(re.finditer(r',\s*DIRECT\s*(?=,|$)', row, re.I))
        if not matches:
            raise ValueError('Output routing rule missing policy')
        match = matches[-1]
        return row[:match.start()] + row[match.end():]
    direct_rows = sorted(routing['DIRECT']) + sorted(extras['DIRECT'])
    files['direct.list'] = (
        '# Generated DIRECT rules; source hashes: manifest.json\n'
        + '\n'.join(direct_without_policy(row) for row in direct_rows) + '\n')
    manifest = {'sources': sources,
                'routing_direct_rules': len(routing['DIRECT']) + len(extras['DIRECT']),
                'native_early_reject_rules': len(early),
                'native_deferred_rules': deferred,
                'native_protected_scopes': len(protected),
                'deferred_connection_rules': len(deferred_rows),
                'coverage_checks': checks,
                'files': {name: {'bytes': len(body.encode()),
                                 'sha256': hashlib.sha256(body.encode()).hexdigest()}
                          for name, body in files.items()}}
    files['manifest.json'] = json.dumps(manifest, ensure_ascii=False, indent=2) + '\n'
    return files


def fetch(source, source_root=Path('.')):
    try:
        request = Request(source['url'], headers={'User-Agent': 'shadowrocket-policy/1.0'})
        with urlopen(request, timeout=45) as response:
            if urlsplit(response.url).scheme != 'https':
                raise ValueError('Upstream redirected away from HTTPS')
            body = response.read(LIMIT + 1)
        if len(body) > LIMIT:
            raise ValueError('Upstream exceeds size limit')
        return parse(source, body)
    except Exception as error:
        if source.get('fallback') and source['use'] == 'dns':
            recorded = datetime.date.fromisoformat(source['fallback_recorded'])
            age = (datetime.date.today() - recorded).days
            if not 0 <= age <= source['fallback_max_days']:
                raise ValueError(source['name'] + ': cached DNS scope expired; refresh it explicitly') from None
            body = (source_root / source['fallback']).read_bytes()
            item = parse(source, body)
            item.fallback = True
            return item
        # Only controlled identifiers; never dump an upstream response body.
        detail = str(error) if type(error) is ValueError else type(error).__name__
        if isinstance(error, HTTPError):
            detail += ' ' + str(error.code)
        raise ValueError(source['name'] + ': ' + detail) from None


def write_outputs(directory, files):
    # Downloads, parsing and coverage checks finish before any output is touched.
    directory.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        fd, temporary = tempfile.mkstemp(prefix='.generation-', dir=directory)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
                stream.write(body)
            os.chmod(temporary, 0o644)
            os.replace(temporary, directory / name)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def load_manifest(path):
    config = tomllib.loads(path.read_text(encoding='utf-8'))
    sources = config['sources']
    if not sources or len({source['name'] for source in sources}) != len(sources):
        raise ValueError('Sources must have unique names')
    for source in sources:
        url = urlsplit(source['url'])
        if (url.scheme != 'https' or not url.hostname or url.username or url.password
                or url.query or url.fragment):
            raise ValueError('Sources must be public HTTPS URLs without credentials or query strings')
        if source['format'] not in ('module', 'rules', 'domainset') or source['policy'] not in ('DIRECT', 'REJECT'):
            raise ValueError('Unsupported source format or policy')
        if source['use'] not in ('routing', 'dns'):
            raise ValueError('Unsupported source use')
        if source['use'] == 'dns' and source['policy'] != 'REJECT':
            raise ValueError('DNS-only sources may only contribute REJECT scope')
        if type(source.get('early', False)) is not bool or (source.get('early') and source['policy'] != 'REJECT'):
            raise ValueError('Early promotion must be an explicit boolean on a REJECT source')
        if 'fallback' in source:
            fallback = Path(source['fallback'])
            if fallback.is_absolute() or '..' in fallback.parts or source['use'] != 'dns':
                raise ValueError('Fallback must be a repository-local DNS scope snapshot')
    return sources, config.get('checks', {})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources', type=Path, default=Path('sources.toml'))
    parser.add_argument('--output', type=Path, default=Path('generated'))
    parser.add_argument('--corrections', type=Path, default=Path('corrections.toml'))
    args = parser.parse_args()
    sources, checks = load_manifest(args.sources)
    with ThreadPoolExecutor(max_workers=4) as pool:
        parsed = list(pool.map(lambda source: fetch(source, args.sources.parent), sources))
    corrections = tomllib.loads(args.corrections.read_text(encoding='utf-8'))
    files = build(parsed, checks, corrections)
    write_outputs(args.output, files)
    print(json.dumps(json.loads(files['manifest.json']), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Do not print arbitrary upstream response bodies or redirect URLs.
        message = str(error) if type(error) is ValueError else type(error).__name__
        raise SystemExit('Generation failed: ' + message + '. Publication skipped.') from None
