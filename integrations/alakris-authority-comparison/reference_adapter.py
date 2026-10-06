"""Executable synthetic executor fixture. This is not an Alakris product result."""
import hashlib
import json

class Executor:
    def __init__(self):
        self.effects = []
        self.revoked = False
        self.online = True
        self.seen = set()
        self.issued = {}

    def dispatch(self, action, now, veto=False):
        canonical = json.dumps(action, sort_keys=True, separators=(',', ':')).encode()
        action_hash = hashlib.sha256(canonical).hexdigest()
        allowed = self.online and not self.revoked and not veto and now <= action['deadline']
        decision = {'allowed': allowed, 'utc_seconds': now, 'action_hash': action_hash}
        dispatch = {'token': action['id'], 'action_hash': action_hash} if allowed else None
        if dispatch:
            self.issued[action['id']] = action_hash
        else:
            # A later denial invalidates an earlier dispatch for this request.
            self.issued.pop(action['id'], None)
        return decision, dispatch

    def commit(self, action, dispatch, now):
        action_hash = hashlib.sha256(json.dumps(action, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        allowed = dispatch is not None and self.issued.get(action['id']) == action_hash and dispatch.get('token') == action['id'] and dispatch['action_hash'] == action_hash and not self.revoked and self.online and now <= action['deadline'] and action['id'] not in self.seen
        if allowed:
            self.seen.add(action['id'])
            self.effects.append(action['id'])
        return {'committed': allowed, 'utc_seconds': now, 'total_effects': len(self.effects)}

def run_cases():
    records = []
    for case in ('binding_veto', 'revoked_stale', 'unreachable', 'post_dispatch_revoke'):
        executor = Executor()
        action = {'id': case, 'target': 'synthetic-counter', 'deadline': 20, 'operation': 'increment'}
        if case == 'revoked_stale':
            executor.revoked = True
        if case == 'unreachable':
            executor.online = False
        decision, dispatch = executor.dispatch(action, 10, veto=case == 'binding_veto')
        if case == 'post_dispatch_revoke':
            executor.revoked = True
        effect = executor.commit(action, dispatch, 11)
        executor.revoked = False
        executor.online = True
        expired_decision, expired_dispatch = executor.dispatch(action, 21)
        expired_effect = executor.commit(action, expired_dispatch, 21)
        records.append({'case_id': case, 'basis': 'synthetic_fixture', 'decision': decision, 'dispatch': dispatch,
                        'effect': effect, 'after_deadline': {'decision': expired_decision, 'effect': expired_effect},
                        'independent_vendor_reproduction': False})
    return records

if __name__ == '__main__':
    print(json.dumps(run_cases(), indent=2))
