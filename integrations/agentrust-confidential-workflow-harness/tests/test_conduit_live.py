import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from harness.conduit_live import run


def receipt(action, session, previous="", **detail):
    record = {"schema":"frequency-conduit-receipt/1", "node":"vps-377a113a",
              "status":"PASS","action":action,"request_id":"test","ts":1,
              "prev_hash":previous,"detail":{"session_id":session, **detail}}
    record["hash"]=hashlib.sha256(json.dumps(record,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return record

class ConduitLiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cli=str(Path(self.tmp.name)/"cli")
        Path(self.cli).touch()
        self.session="session-1"
        self.started=receipt("job_start",self.session)
        self.finished=receipt("job_poll",self.session,self.started["hash"])
    def transport(self,cli,action,params):
        if action=="job_start":
            return {"ok":True, "receipt":self.started,
                    "result":{"session_id":self.session,"intent":"inspect",
                              "commit_sha":"abc","network":False}}
        return {"ok":True,"receipt":self.finished,
                "result":{"session_id":self.session,"running":False,"exit_code":0,
                          "commit_sha":"abc","commit_sha_end":"abc",
                          "worktree_clean_start":True,"worktree_clean_end":True}}
    def invoke(self,**opts):
        return run(transaction_id="txn-1",repo="/home/ubuntu/src/integrations",
                   cli=self.cli,transport=self.transport,**opts)
    def test_valid_receipts(self):
        self.assertEqual(self.invoke().outcome,"observed-live-conduit-inspect")
    def test_cmcp_denial(self):
        self.assertEqual(self.invoke(tool_allowed=False).outcome,"refused-cmcp")
    def test_receipt_tampering(self):
        self.finished["detail"]["session_id"]="substituted"
        self.assertEqual(self.invoke().outcome,"untrusted-or-unsuccessful-result")
    def test_receipt_linkage(self):
        self.finished["prev_hash"]="wrong"
        data={k:v for k,v in self.finished.items() if k!="hash"}
        self.finished["hash"]=hashlib.sha256(json.dumps(data,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        self.assertEqual(self.invoke().outcome,"untrusted-or-unsuccessful-result")
    def test_unobserved_finish(self):
        def transport(cli,action,params):
            if action=="job_poll":
                return {"ok":False}
            return self.transport(cli,action,params)
        out=run(transaction_id="txn-1",repo="/home/ubuntu/src/integrations",
                cli=self.cli,transport=transport)
        self.assertEqual(out.outcome,"unknown-unobserved-result")
    def test_stale_commit(self):
        original=self.transport
        def transport(cli,action,params):
            result=original(cli,action,params)
            if action=="job_poll":
                result["result"]["commit_sha_end"]="changed"
            return result
        self.transport=transport
        self.assertEqual(self.invoke().outcome,"untrusted-or-unsuccessful-result")
