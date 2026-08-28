from __future__ import annotations
import hashlib,json,os,shutil,stat,subprocess,tempfile,unittest,urllib.request
from pathlib import Path
import jsonschema
from graphify_acceptance_runtime import ExactRuntimeSession
from graphify_builder import policy,runtime,wheelhouse

ROOT=Path(__file__).parents[1].resolve()
GIT="/usr/bin/git"
REAL_PRODUCT_SHA="8fd669336b36064e842252d69fb4016cc526a9d4"
TRIPWIRE=Path("/tmp/hwm-i10-0073-product-executed")
UPSTREAM_RAW=f"https://raw.githubusercontent.com/Graphify-Labs/graphify/{policy.UPSTREAM_COMMIT}/"
CONTROL_RAW="https://raw.githubusercontent.com/Dsamofalov/hwm-control/8a5b6347e562a1312207ab3fbcea9cede51a2f23/schemas/"
SCHEMAS={"snapshot":("graph-snapshot.v1.schema.json",policy.SNAPSHOT_SCHEMA_BLOB_SHA),"metadata":("graph-metadata.v1.schema.json",policy.METADATA_SCHEMA_BLOB_SHA),"health":("graph-health.v1.schema.json",policy.HEALTH_SCHEMA_BLOB_SHA)}
HEALTH_DETAIL_MAX=4096
HEALTH_DIAGNOSTIC_READ_MAX=8192

def _env(extra=None):
 e={"PATH":"/usr/bin:/bin","HOME":"/nonexistent","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_TERMINAL_PROMPT":"0","GIT_OPTIONAL_LOCKS":"0","GIT_LFS_SKIP_SMUDGE":"1","LC_ALL":"C","LANG":"C"}
 if extra:e.update(extra)
 return e
def _git(root,*args,env=None):
 r=subprocess.run([GIT,"-c","core.hooksPath=/dev/null","-c","core.fsmonitor=false","-c","submodule.recurse=false",*args],cwd=root,env=_env(env),shell=False,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=False)
 if r.returncode: raise AssertionError(f"trusted Git failed {args!r}: {r.stderr[-1000:]}")
 return r.stdout.strip()
def _fixture(root,repo=policy.PRODUCT_REPOSITORY,detach=True):
 root.mkdir(parents=True);_git(root,"init","-q","--initial-branch=main");_git(root,"config","user.name","HWM Fixture");_git(root,"config","user.email","fixture@example.invalid");_git(root,"remote","add","origin",f"https://github.com/{repo}.git")
 (root/"pkg").mkdir();(root/"pkg/a.py").write_text("class A:\n pass\ndef f():\n return A()\n")
 trip="from pathlib import Path\nPath('/tmp/hwm-i10-0073-product-executed').write_text('executed')\n"
 (root/"sitecustomize.py").write_text(trip);(root/"setup.py").write_text(trip)
 _git(root,"add","--all");fixed={"GIT_AUTHOR_DATE":"2000-01-01T00:00:00Z","GIT_COMMITTER_DATE":"2000-01-01T00:00:00Z"};_git(root,"commit","-q","-m","fixture",env=fixed);sha=_git(root,"rev-parse","HEAD")
 if detach:_git(root,"checkout","-q","--detach",sha)
 return sha
def _real_product(root):
 root.mkdir();_git(root,"init","-q","--initial-branch=main");_git(root,"remote","add","origin","https://github.com/Dsamofalov/hwm_predictor.git");_git(root,"fetch","--no-tags","--no-recurse-submodules","--depth=1","origin",REAL_PRODUCT_SHA);_git(root,"checkout","-q","--detach",REAL_PRODUCT_SHA)
 if _git(root,"rev-parse","--verify","HEAD^{commit}")!=REAL_PRODUCT_SHA: raise AssertionError("real product SHA drift")
def _readonly(root):
 for p in sorted([*root.rglob("*"),root],key=lambda x:len(x.parts),reverse=True):
  try:p.chmod(p.stat().st_mode&~0o222)
  except FileNotFoundError:pass
def _writable(root):
 if not root.exists():return
 for p in [root,*root.rglob("*")]:
  try:p.chmod(p.stat().st_mode|(stat.S_IWUSR|stat.S_IXUSR if p.is_dir() else stat.S_IWUSR))
  except FileNotFoundError:pass
def _fetch(url,blob=None):
 req=urllib.request.Request(url,headers={"User-Agent":"hwm-i10-0073-integration-v2/1"})
 with urllib.request.urlopen(req,timeout=60) as r:data=r.read()
 if blob and wheelhouse.git_blob_sha(data)!=blob:raise AssertionError("authority blob drift")
 return data
def _proof(path,sha):path.write_text(json.dumps({"repository":policy.PRODUCT_REPOSITORY,"product_sha":sha}))
def _authority(base):
 a=base/"authority";a.mkdir();(a/"uv.lock").write_bytes(_fetch(UPSTREAM_RAW+"uv.lock",policy.UPSTREAM_UV_LOCK_BLOB_SHA))
 for n in ("LICENSE","LICENSE-MIT","NOTICE"):(a/n).write_bytes(_fetch(UPSTREAM_RAW+n))
 w=base/"wheelhouse";m=wheelhouse.prepare_wheelhouse(a/"uv.lock",w,a);wheelhouse.verify_wheelhouse(w)
 g=[x for x in m["artifacts"] if x["name"]==policy.GRAPHIFY_PACKAGE]
 if len(g)!=1 or g[0]["filename"]!=policy.GRAPHIFY_WHEEL or g[0]["sha256"]!=policy.GRAPHIFY_WHEEL_SHA256:raise AssertionError("Graphify wheel drift")
 if {"openai","anthropic","mcp","neo4j","falkordb","boto3","psycopg"}&{x["name"] for x in m["artifacts"]}:raise AssertionError("provider package present")
 if m["optional_extras"]!=[] or m["build_time_resolution"] is not False:raise AssertionError("wheelhouse closure drift")
 return w,m
def _schemas():
 return {k:json.loads(_fetch(CONTROL_RAW+n,b)) for k,(n,b) in SCHEMAS.items()}
def _health_text(value,limit):
 if not isinstance(value,str):raise ValueError("health diagnostic field is not text")
 return value[:limit]
def _health_diagnostic(out):
 path=out/"health.json"
 try:
  if not stat.S_ISREG(path.lstat().st_mode):return "health_diagnostic=malformed"
  with path.open("rb") as handle:raw=handle.read(HEALTH_DIAGNOSTIC_READ_MAX+1)
 except FileNotFoundError:return "health_diagnostic=missing"
 except OSError:return "health_diagnostic=unreadable"
 if len(raw)>HEALTH_DIAGNOSTIC_READ_MAX:return f"health_diagnostic=oversized_or_unbounded limit={HEALTH_DIAGNOSTIC_READ_MAX}"
 try:
  obj=json.loads(raw.decode("utf-8"))
  if not isinstance(obj,dict):raise ValueError("health diagnostic root is not an object")
  safe={"schema":_health_text(obj["schema"],128),"state":_health_text(obj["state"],128),"reason_code":_health_text(obj["reason_code"],256),"detail":_health_text(obj.get("detail",""),HEALTH_DETAIL_MAX)}
 except (KeyError,TypeError,ValueError,UnicodeDecodeError,json.JSONDecodeError):return "health_diagnostic=malformed"
 return "health_diagnostic="+json.dumps(safe,ensure_ascii=True,sort_keys=True,separators=(",",":"))

class HealthDiagnosticTests(unittest.TestCase):
 def test_failure_health_diagnostic_is_bounded_and_explicit(self):
  with tempfile.TemporaryDirectory() as d:
   out=Path(d);hidden="SHOULD-NOT-EMIT"
   health={"schema":"hwm-graph-health/v1","state":"incompatible_upstream_output","reason_code":"malformed_or_incompatible_graphify_output","detail":"Graphify internal failure","requested_product_sha":hidden,"credential":hidden}
   (out/"health.json").write_text(json.dumps(health),encoding="utf-8");diag=_health_diagnostic(out)
   self.assertEqual(diag,'health_diagnostic={"detail":"Graphify internal failure","reason_code":"malformed_or_incompatible_graphify_output","schema":"hwm-graph-health/v1","state":"incompatible_upstream_output"}');self.assertNotIn(hidden,diag)
   (out/"health.json").unlink();self.assertEqual(_health_diagnostic(out),"health_diagnostic=missing")
   (out/"health.json").write_bytes(b"{not-json");self.assertEqual(_health_diagnostic(out),"health_diagnostic=malformed")
   tail="TAIL-SHOULD-NOT-EMIT";health["detail"]="d"*HEALTH_DETAIL_MAX+tail;(out/"health.json").write_text(json.dumps(health),encoding="utf-8");diag=_health_diagnostic(out);self.assertNotIn(tail,diag);self.assertEqual(len(json.loads(diag.split("=",1)[1])["detail"]),HEALTH_DETAIL_MAX)
   secret="UNBOUNDED-SHOULD-NOT-EMIT";health["detail"]=secret+"z"*(HEALTH_DIAGNOSTIC_READ_MAX+100);(out/"health.json").write_text(json.dumps(health),encoding="utf-8");diag=_health_diagnostic(out);self.assertEqual(diag,f"health_diagnostic=oversized_or_unbounded limit={HEALTH_DIAGNOSTIC_READ_MAX}");self.assertNotIn(secret,diag)

class ExactCheckoutBindingTests(unittest.TestCase):
 def test_binding_and_runtime_bridge_fail_closed(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d);clean=b/"clean";sha=_fixture(clean);p=b/"proof";_proof(p,sha)
   self.assertEqual(runtime.verify_git_checkout(clean,sha),{"repository":policy.PRODUCT_REPOSITORY,"product_sha":sha});runtime.validate_source_proof(p,sha)
   dirty=b/"dirty";dsha=_fixture(dirty);(dirty/"pkg/a.py").write_text("tampered\n")
   with self.assertRaisesRegex(runtime.BoundaryError,"dirty tracked"):runtime.verify_git_checkout(dirty,dsha)
   wrong=b/"wrong";wsha=_fixture(wrong,"hwm-tests/not-the-product")
   with self.assertRaisesRegex(runtime.BoundaryError,"repository identity mismatch"):runtime.verify_git_checkout(wrong,wsha)
   attached=b/"attached";asha=_fixture(attached,detach=False)
   with self.assertRaisesRegex(runtime.BoundaryError,"detached"):runtime.verify_git_checkout(attached,asha)
  rs=(ROOT/"graphify_builder/runtime.py").read_text();sh=(ROOT/"graphify_builder/run_github_hosted.sh").read_text()
  self.assertEqual(runtime.TRUSTED_GIT,Path("/usr/bin/git"));self.assertIn('\"core.hooksPath=/dev/null\"',rs);self.assertIn("shell=False",rs);self.assertNotIn("shell=True",rs)
  self.assertIn("ExactRuntimeSession",sh);self.assertNotIn("/opt/hostedtoolcache",sh);self.assertNotIn("actions/setup-python",sh)

class RealGraphifyIntegrationTests(unittest.TestCase):
 def _run(self,executor,python,product,sha,proof,wheelhouse_root,out):
  cmd=["/usr/bin/env","PATH=/usr/bin:/bin",f"PYTHONPATH={ROOT}","PYTHONSAFEPATH=1","PYTHONNOUSERSITE=1","PYTHONDONTWRITEBYTECODE=1","GITHUB_ACTIONS=true","RUNNER_OS=Linux","RUNNER_ARCH=X64",f"RUNNER_TEMP={os.environ['RUNNER_TEMP']}",f"GITHUB_RUN_ID={os.environ.get('GITHUB_RUN_ID','')}",str(python),"-m","graphify_builder.run","--product-root",str(product),"--product-sha",sha,"--source-proof",str(proof),"--wheelhouse",str(wheelhouse_root),"--output",str(out)]
  try:return executor.run("product_parsing",cmd,timeout=policy.BUILDER_TIMEOUT_SECONDS+60)
  except subprocess.CalledProcessError as e:self.fail(f"Graphify rc={e.returncode}; {_health_diagnostic(out)}; stdout={(e.stdout or '')[-2500:]}; stderr={(e.stderr or '')[-3500:]}")
 def _check(self,out,sha,schemas):
  raw=(out/"snapshot.json").read_bytes();snap=json.loads(raw);meta=json.loads((out/"metadata.json").read_text());health=json.loads((out/"health.json").read_text())
  jsonschema.Draft202012Validator(schemas["snapshot"]).validate(snap);jsonschema.Draft202012Validator(schemas["metadata"],format_checker=jsonschema.FormatChecker()).validate(meta);jsonschema.Draft202012Validator(schemas["health"]).validate(health)
  self.assertLessEqual(len(raw),policy.MAX_SNAPSHOT_BYTES);self.assertEqual((snap["product_sha"],meta["product_sha"],health["requested_product_sha"],health["snapshot_product_sha"]),(sha,sha,sha,sha));self.assertEqual(health["state"],"healthy_current");self.assertTrue(health["usable"])
  digest=hashlib.sha256(raw).hexdigest();self.assertEqual(meta["snapshot_sha256"],digest);return raw,digest
 def test_runtime_v2_graphify_determinism_and_exact_product(self):
  self.assertEqual((os.environ.get("GITHUB_ACTIONS"),os.environ.get("RUNNER_OS"),os.environ.get("RUNNER_ARCH")),("true","Linux","X64"))
  self.assertEqual(policy.EXACT_GRAPHIFY_COMMAND,("python","-m","graphify","extract",".","--code-only","--no-cluster","--no-viz"));self.assertEqual(policy.BUILDER_TIMEOUT_SECONDS,900);self.assertEqual(policy.MAX_SNAPSHOT_BYTES,67108864);self.assertEqual(policy.SUPPLY_CHAIN_BLOB_SHA,"f42132a2f52d1d7af84155a56a86fca2fe4d8605")
  self.assertEqual([n for n in policy.PROVIDER_ENVIRONMENT_DENY if os.environ.get(n)],[])
  TRIPWIRE.unlink(missing_ok=True);base=Path(tempfile.mkdtemp(prefix="hwm-real-graphify-v2-"));session=ExactRuntimeSession(os.environ["RUNNER_TEMP"]);paths=[];real=base/"real-product"
  try:
   schemas=_schemas();wh,manifest=_authority(base);_real_product(real);self.assertEqual(runtime.verify_git_checkout(real,REAL_PRODUCT_SHA),{"repository":policy.PRODUCT_REPOSITORY,"product_sha":REAL_PRODUCT_SHA});rp=base/"real.proof";_proof(rp,REAL_PRODUCT_SHA);runtime.validate_source_proof(rp,REAL_PRODUCT_SHA);_readonly(real);runtime.assert_product_read_only(real);runtime.verify_git_checkout(real,REAL_PRODUCT_SHA)
   session.prepare();self.assertIsNotNone(session.python);self.assertIsNotNone(session.provenance);assert session.python is not None and session.provenance is not None;p=session.provenance
   self.assertEqual((p.executable_report,p.artifact_bytes,p.artifact_sha256,p.redirect_count,p.final_host,p.canonical_inventory_sha256),("CPython 3.12.10",121612690,"b9bd943c5fc9244f796deef42c59d29ab9278d8a718851c67de6b44846320f33",1,"release-assets.githubusercontent.com","266fbc38be6ffdc9c565953d44cc208e74d6db8a2f038186580fd4904279f3db"));executor=session.seal_network()
   g=[x for x in manifest["artifacts"] if x["name"]==policy.GRAPHIFY_PACKAGE][0];print(f"integration_runtime={p.executable_report} artifact_sha256={p.artifact_sha256} inventory_sha256={p.canonical_inventory_sha256}");print(f"integration_wheel={g['filename']} sha256={g['sha256']} network=denied")
   raws=[];digests=[];shas=[]
   for i in range(1,4):
    f=base/f"fixture-{i}";paths.append(f);sha=_fixture(f);shas.append(sha);proof=base/f"fixture-{i}.proof";_proof(proof,sha);runtime.verify_git_checkout(f,sha);runtime.validate_source_proof(proof,sha);_readonly(f);runtime.assert_product_read_only(f);runtime.verify_git_checkout(f,sha);out=base/f"fixture-out-{i}";r=self._run(executor,session.python,f,sha,proof,wh,out);self.assertIn("hwm_graphify_command="+" ".join(policy.EXACT_GRAPHIFY_COMMAND),r.stdout);self.assertIn(f"hwm_graphify_wheel={policy.GRAPHIFY_WHEEL} sha256={policy.GRAPHIFY_WHEEL_SHA256}",r.stdout);self.assertFalse(TRIPWIRE.exists());raw,digest=self._check(out,sha,schemas);raws.append(raw);digests.append(digest);print(f"integration_fixture_run={i} canonical_sha256={digest} bytes={len(raw)}")
   self.assertEqual(len(set(shas)),1);self.assertEqual(raws[0],raws[1]);self.assertEqual(raws[1],raws[2]);self.assertEqual(len(set(digests)),1);self.assertFalse(TRIPWIRE.exists());print(f"integration_three_run_digest={digests[0]} runs=3 identical=true")
   out=base/"real-output";rr=self._run(executor,session.python,real,REAL_PRODUCT_SHA,rp,wh,out);self.assertIn("hwm_graphify_command="+" ".join(policy.EXACT_GRAPHIFY_COMMAND),rr.stdout);self.assertIn(f"hwm_graphify_wheel={policy.GRAPHIFY_WHEEL} sha256={policy.GRAPHIFY_WHEEL_SHA256}",rr.stdout);_,rd=self._check(out,REAL_PRODUCT_SHA,schemas);print(f"integration_real_product_sha={REAL_PRODUCT_SHA} canonical_sha256={rd} network=denied timer_seconds={policy.BUILDER_TIMEOUT_SECONDS}");print("integration_production_graph_publication=none temporary_outputs_only=true")
  finally:
   session.cleanup();self.assertFalse(session.install_root.exists());self.assertFalse(session.scratch_root.exists());TRIPWIRE.unlink(missing_ok=True)
   for p in paths:_writable(p)
   _writable(real);shutil.rmtree(base,ignore_errors=False)
  self.assertFalse(base.exists());print("integration_runtime_cleanup=true")

if __name__=="__main__":unittest.main()
