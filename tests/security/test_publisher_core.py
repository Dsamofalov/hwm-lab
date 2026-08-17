from security.publisher_test_support import *  # noqa: F401,F403

class PublisherCore(PublisherSecurityBase):
    def test_expected_head_success_moves_only_requested_branch_and_dispatches_exact_head(self):
        before_other = self.backend.branches["agent/infra-0014-sandbox-a"]
        result = self.publish()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["expected_head"], BASE)
        self.assertEqual(result["observed_head_before"], BASE)
        self.assertEqual(result["new_head"], result["commit_sha"])
        self.assertEqual(self.backend.created_commits[0][2], BASE)
        self.assertEqual(self.backend.branches["agent/infra-0013-controlled-task-branch-publisher"], result["new_head"])
        self.assertEqual(self.backend.branches["agent/infra-0014-sandbox-a"], before_other)
        self.assertEqual(result["ci_dispatch"]["head_sha"], result["new_head"])
        self.assertEqual(self.backend.dispatch_calls[0][3], result["new_head"])

    def test_expected_head_race_fails_without_overwriting_competing_writer(self):
        self.backend.race_branch = "agent/infra-0013-controlled-task-branch-publisher"
        result = self.publish()
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"]["code"], "EXPECTED_HEAD_MISMATCH")
        self.assertEqual(self.backend.branches["agent/infra-0013-controlled-task-branch-publisher"], RACE)
        self.assertEqual(self.backend.dispatch_calls, [])
        self.assertTrue(self.backend.created_commits)  # unreachable object is not reported as publication
        self.assertNotIn("new_head", result)

    def test_initial_expected_head_mismatch_creates_no_candidate_objects(self):
        req = request(expected=RACE)
        result = self.publish(req)
        self.assertEqual(result["error"]["code"], "EXPECTED_HEAD_MISMATCH")
        self.assertEqual(self.backend.created_commits, [])
        self.assertEqual(self.backend.cas_calls, [])

    def test_idempotent_success_replay_does_not_mutate_or_redispatch(self):
        req = request()
        first = self.publish(req)
        self.backend.results.append(copy.deepcopy(first))
        commits = len(self.backend.created_commits); dispatches = len(self.backend.dispatch_calls); head = self.backend.branches[req["task_branch"]]
        replay = self.publish(req)
        self.assertEqual(replay["status"], "success")
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["new_head"], first["new_head"])
        self.assertEqual(len(self.backend.created_commits), commits)
        self.assertEqual(len(self.backend.dispatch_calls), dispatches)
        self.assertEqual(self.backend.branches[req["task_branch"]], head)

    def test_request_id_reuse_with_different_normalized_request(self):
        req = request()
        fp = request_fingerprint(req)
        self.backend.results.append({
            "schema": "hwm-publish-result/bootstrap-v1", "request_id": req["request_id"], "status": "error",
            "repository": req["repository"], "task_issue": req["task_issue"], "task_branch": req["task_branch"],
            "expected_head": req["expected_head"], "observed_head_before": req["expected_head"],
            "request_fingerprint": fp, "idempotent_replay": False,
            "error": {"code": "INTERNAL_ERROR", "message": "old", "retryable": False},
        })
        changed = copy.deepcopy(req); changed["changes"][0]["path"] = "sandbox/other.txt"
        result = self.publish(changed)
        self.assertEqual(result["error"]["code"], "REQUEST_ID_REUSE")
        self.assertEqual(self.backend.created_commits, [])

    def test_request_id_collision_detected_from_durable_request_history(self):
        req = request()
        changed = copy.deepcopy(req); changed["changes"][0]["path"] = "sandbox/other.txt"
        self.backend.request_fingerprints[req["request_id"]] = [request_fingerprint(changed)]
        result = self.publish(req)
        self.assertEqual(result["error"]["code"], "REQUEST_ID_REUSE")

    def test_same_branch_concurrency_allows_only_one_cas_winner(self):
        req1 = request(request_id="pub-0013-race1")
        req2 = request(request_id="pub-0013-race2", changes=[{"op": "add", "path": "sandbox/two.txt", "blob_sha": MAL, "mode": "100644"}])
        results = []
        threads = [threading.Thread(target=lambda r=r: results.append(self.publish(r))) for r in (req1, req2)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(sorted(r["status"] for r in results), ["error", "success"])
        self.assertEqual(len(self.backend.dispatch_calls), 1)
        self.assertIn("EXPECTED_HEAD_MISMATCH", {r.get("error", {}).get("code") for r in results})

    def test_distinct_task_branches_execute_independently(self):
        self.backend.create_delay = 0.15
        req1 = request(issue=14, branch="agent/infra-0014-sandbox-a", expected=BASE, request_id="pub-0014-parallel")
        req2 = request(issue=15, branch="agent/infra-0015-sandbox-b", expected=BASE2, request_id="pub-0015-parallel",
                       changes=[{"op": "add", "path": "sandbox/two.txt", "blob_sha": MAL, "mode": "100644"}])
        results = []
        threads = [threading.Thread(target=lambda r=r: results.append(self.publisher.handle_event(event(r)))) for r in (req1, req2)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual([r["status"] for r in results].count("success"), 2)
        self.assertGreaterEqual(self.backend.max_active_create, 2)

