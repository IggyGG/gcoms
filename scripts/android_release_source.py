"""Cluster Forgejo source intake with the original server activity clock.

Forgejo activity IDs and creation times survive delayed polling and coordinator
restarts. Commit author dates and client observation times are never push times.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from android_release import write_json

MAX_RESPONSE = 4 * 1024 ** 2
MAX_PAGES = 32
PAGE_SIZE = 100
PROMOTION = 'refs/tags/android-release/'


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        raise ValueError('Forgejo credentials cannot follow a redirect')


def repository_name(value):
    if not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value):
        raise ValueError('explicit Forgejo owner/repository required')
    if any(part in ('.', '..') for part in value.split('/')):
        raise ValueError('unsafe Forgejo repository path')
    return value


def event(row, repository, project, now=None):
    """Extract only an authenticated repository's genuine source/tag pushes."""
    now = time.time() if now is None else now
    if row.get('repo', {}).get('full_name') != repository:
        raise ValueError('Forgejo activity belongs to a different repository')
    if type(row.get('id')) is not int or row['id'] <= 0:
        raise ValueError('positive server activity ID required')
    kind, ref = row.get('op_type'), row.get('ref_name')
    if kind not in ('commit_repo', 'push_tag') or not isinstance(ref, str):
        return None
    if ref.startswith(PROMOTION):
        if project != 'gcoms' or kind != 'push_tag' or not re.fullmatch('[0-9a-f]{64}', ref[len(PROMOTION):]):
            return None
    elif kind != 'commit_repo' or not (ref == 'refs/heads/main' or ref.startswith('refs/heads/agent/')):
        return None
    if not re.fullmatch('[A-Za-z0-9_./-]+', ref):
        return None
    content = row.get('content')
    if not content:
        return None  # Forgejo emits a separate content-less notification row.
    if not isinstance(content, str) or len(content.encode()) > MAX_RESPONSE:
        raise ValueError('Forgejo push content exceeds its bound')
    push = json.loads(content)
    commit = push.get('HeadCommit', {}).get('Sha1')
    if not isinstance(commit, str) or not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('Forgejo push is missing its exact commit')
    created = row.get('created')
    if not isinstance(created, str):
        raise ValueError('original Forgejo activity creation time required')
    timestamp = datetime.fromisoformat(created.replace('Z', '+00:00'))
    if timestamp.tzinfo is None:
        raise ValueError('Forgejo push timestamp must include a timezone')
    pushed_at = timestamp.astimezone(timezone.utc).timestamp()
    if pushed_at <= 0 or pushed_at > now:
        raise ValueError('invalid original Forgejo push time')
    return {'schema': 1, 'project': project, 'repository': repository,
            'ref': ref, 'commit': commit, 'pushed_at': int(pushed_at),
            'forgejo_activity_id': row['id'], 'forgejo_created': created}


class Forgejo:
    def __init__(self, config, opener=None):
        endpoint = urlsplit(config['url'])
        if (endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username
                or endpoint.password or endpoint.query or endpoint.fragment or endpoint.path not in ('', '/')):
            raise ValueError('verified HTTPS Forgejo origin required')
        self.origin = config['url'].rstrip('/')
        self.token_file = Path(config['token_file'])
        self.opener = opener or build_opener(NoRedirect())

    def read(self, path):
        token = self.token_file.read_text().strip()
        if not token or len(token) > 4096 or '\n' in token or '\r' in token:
            raise ValueError('invalid Forgejo service token')
        request = Request(self.origin + '/api/v1/' + path,
                          headers={'Authorization': 'token ' + token, 'Accept': 'application/json'})
        with self.opener.open(request, timeout=15) as response:
            body = response.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            raise ValueError('Forgejo response exceeds its bound')
        return json.loads(body)

    def activities(self, repository, after):
        repository_name(repository)
        if type(after) is not int or after < 0:
            raise ValueError('nonnegative persisted activity cursor required')
        seen = {}
        for page in range(1, MAX_PAGES + 1):
            rows = self.read('repos/' + quote(repository, safe='/') +
                             '/activities/feeds?limit=' + str(PAGE_SIZE) + '&page=' + str(page))
            if not isinstance(rows, list) or len(rows) > PAGE_SIZE:
                raise ValueError('invalid Forgejo activity page')
            complete = len(rows) < PAGE_SIZE
            for row in rows:
                identity = row.get('id')
                if type(identity) is not int or identity <= 0:
                    raise ValueError('invalid Forgejo activity identity')
                if row.get('repo', {}).get('full_name') != repository:
                    raise ValueError('activity page changed repository')
                if identity <= after:
                    complete = True
                    continue
                if identity in seen and seen[identity] != row:
                    raise ValueError('immutable Forgejo activity changed between pages')
                seen[identity] = row
            if complete:
                return [seen[key] for key in sorted(seen)]
        # Do not advance over an unobserved gap, including during recovery.
        raise ValueError('Forgejo activity backlog exceeds one bounded intake; cursor retained')


def ingest(config, client=None):
    client = client or Forgejo(config['forgejo'])
    state = Path(config['state'])
    cursors_path = state / 'source-cursors.json'
    cursors = json.loads(cursors_path.read_text()) if cursors_path.exists() else {}
    accepted = []
    projects = {row['project']: row['cluster_repository'] for row in config['sources'].values()}
    for project, repository in sorted(projects.items()):
        repository_name(repository)
        if repository not in cursors:
            raise ValueError('source intake needs an explicit audited migration cursor')
        rows = client.activities(repository, cursors[repository])
        for row in rows:
            value = event(row, repository, project)
            if value is None:
                continue
            name = project + '-' + str(value['forgejo_activity_id']) + '.json'
            destination = Path(config['event_directory']) / name
            if destination.exists():
                if json.loads(destination.read_text()) != value:
                    raise ValueError('original source event changed')
            else:
                write_json(destination, value)
            accepted.append(value)
        if rows:
            # Events are fsynced first. An interrupted cursor update safely
            # re-observes the same events; it cannot create a new push clock.
            cursors[repository] = max(row['id'] for row in rows)
            write_json(cursors_path, cursors)
    return accepted
