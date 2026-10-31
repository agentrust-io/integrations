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
        self.started=receipt("job_start",self.session, transaction_id="txn-1")
        self.finished=receipt("job_poll",self.session,self.started["hash"], transaction_id="txn-1")
    def transport(self,cli,action,params):
        if action=="job_start":
            return {"ok":True, "receipt":self.started,
                    "result":{"transaction_id":"txn-1","session_id":self.session,"intent":"inspect",
                              "commit_sha":"a" * 40,"network":False,
                              "repo":"/home/ubuntu/src/integrations"}}
        return {"ok":True,"receipt":self.finished,
                "result":{"transaction_id":"txn-1","session_id":self.session,"running":False,"exit_code":0,
                          "commit_sha":"a" * 40,"commit_sha_end":"a" * 40,
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

    def test_wrong_repository_is_rejected(self):
        original = self.transport
        def transport(cli, action, params):
            response = original(cli, action, params)
            if action == "job_start":
                response["result"]["repo"] = "/other/repository"
            return response
        self.transport = transport
        self.assertEqual(self.invoke().outcome, "untrusted-start")

    def test_missing_repository_is_rejected(self):
        original = self.transport
        def transport(cli, action, params):
            response = original(cli, action, params)
            if action == "job_start":
                del response["result"]["repo"]
            return response
        self.transport = transport
        self.assertEqual(self.invoke().outcome, "untrusted-start")

    def test_rehashed_failed_finish_is_rejected(self):
        self.finished["status"] = "FAIL"
        payload = {k: v for k, v in self.finished.items() if k != "hash"}
        self.finished["hash"] = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(self.invoke().outcome, "untrusted-or-unsuccessful-result")

    def test_requests_carry_transaction(self):
        original = self.transport
        def transport(cli, action, params):
            self.assertEqual(params["transaction_id"], "txn-1")
            return original(cli, action, params)
        self.transport = transport
        self.assertEqual(self.invoke().outcome, "observed-live-conduit-inspect")

    def test_unbound_transactions_are_rejected(self):
        original = self.transport
        for action in ("job_start", "job_poll"):
            for location in ("result", "detail"):
                for value in (None, "another-transaction"):
                    def transport(cli, requested, params):
                        import copy
                        response = copy.deepcopy(original(cli, requested, params))
                        if requested == action:
                            target = response["result"] if location == "result" else response["receipt"]["detail"]
                            target["transaction_id"] = value
                            record = response["receipt"]
                            material = {k: v for k, v in record.items() if k != "hash"}
                            record["hash"] = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                        return response
                    self.transport = transport
                    with self.subTest(action=action, location=location, value=value):
                        self.assertIn(self.invoke().outcome, {"untrusted-start", "untrusted-or-unsuccessful-result"})

    def test_missing_and_invalid_commit_is_rejected(self):
        original = self.transport
        for value in (None, "", "abc", "g" * 40):
            def transport(cli, action, params):
                response = original(cli, action, params)
                response["result"]["commit_sha"] = value
                response["result"]["commit_sha_end"] = value
                return response
            self.transport = transport
            with self.subTest(value=value):
                self.assertEqual(self.invoke().outcome, "untrusted-start")

    def test_malformed_nested_responses_are_unknown(self):
        original = self.transport
        for action in ("job_start", "job_poll"):
            for field in ("response", "result", "receipt", "detail"):
                for malformed in ([], None, "bad"):
                    def transport(cli, requested, params):
                        import copy
                        response = copy.deepcopy(original(cli, requested, params))
                        if requested == action:
                            if field == "response":
                                return malformed
                            if field == "detail":
                                response["receipt"]["detail"] = malformed
                            else:
                                response[field] = malformed
                        return response
                    self.transport = transport
                    with self.subTest(action=action, field=field, malformed=malformed):
                        self.assertEqual(self.invoke().outcome, "unknown-transport-or-protocol")
