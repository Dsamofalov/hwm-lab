from __future__ import annotations
import hashlib,json,signal,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest import mock
from graphify_builder import normalize,policy,run,runtime,wheelhouse,worker
SHA="8fd669336b36064e842252d69fb4016cc526a9d4"
def graph(): return {"nodes":[{"id":"b","type":"function","label":"pkg.beta","source_file":"pkg/b.py","source_location":"L8-L10"},{"id":"a","type":"class","label":"pkg.Alpha","source_file":"pkg/a.py","source_location":"L2-L6"}],"edges":[{"source":"a","target":"b","relation":"calls"}],"metadata":{"generated_at":"ignored"}}
def d4_class_node(): return {"_callable":True,"_callable_class":False,"_origin":"source","file_type":"code","id":"pkg_a_a","label":"A","source_file":"a.py","source_location":"L1"}
def d4_function_node(): return {"_callable":False,"_origin":"source","file_type":"code","id":"pkg_a_f","label":"f()","source_file":"a.py","source_location":"L3"}
def d4_file_node(): return {"id":"pkg_a","label":"a.py","file_type":"code","source_file":"a.py","source_location":"L1"}
class T(unittest.TestCase):
 def test_01_exact_sha_and_three_run_determinism(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d);(r/"pkg").mkdir(); xs=[normalize.normalize_graph(graph(),SHA,r) for _ in range(3)]
   self.assertEqual(xs[0],xs[1]);self.assertEqual(xs[1],xs[2]);self.assertEqual(xs[0][0]["product_sha"],SHA);self.assertEqual(hashlib.sha256(xs[0][1]).hexdigest(),xs[0][2])
 def test_02_product_is_data_not_executed(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d)/"p";r.mkdir();mark=Path(d)/"ran"
   for n in ("sitecustomize.py","graphify.py","setup.py"): (r/n).write_text(f"open({str(mark)!r},'w').write('bad')")
   for p in [r,*r.rglob('*')]:p.chmod(p.stat().st_mode&~0o222)
   runtime.assert_product_read_only(r);self.assertFalse(mark.exists());e=worker._safe_graphify_env(Path('/trusted/venv/bin'),Path('/o'),Path('/h'));self.assertNotIn('PYTHONPATH',e);self.assertEqual(e['PYTHONSAFEPATH'],'1')
 def test_03_exact_supply_chain_runtime_and_size_pins(self):
  self.assertEqual((policy.SUPPLY_CHAIN_SCHEMA,policy.SUPPLY_CHAIN_BLOB_SHA),("hwm-graphify-supply-chain/v2","f42132a2f52d1d7af84155a56a86fca2fe4d8605"));self.assertEqual((policy.UPSTREAM_TAG,policy.UPSTREAM_COMMIT),("v0.9.38","10ad921b423b767dd8a947bbf0fbcc2e95038ad3"));self.assertEqual(policy.UPSTREAM_UV_LOCK_BLOB_SHA,"8573a9e9d6a4b681c469b9e25a70e309e7da53f3");self.assertEqual((policy.GRAPHIFY_VERSION,policy.GRAPHIFY_WHEEL),("0.9.38","graphifyy-0.9.38-py3-none-any.whl"));self.assertEqual(policy.GRAPHIFY_WHEEL_SHA256,"1335aa0805565279208a47059f8cb0994970ec3dd2155d753d12da425b9d7ee5");self.assertEqual((policy.RUNTIME_VERSION,policy.RUNTIME_PLATFORM),("3.12.10","linux-x86_64"));self.assertEqual(policy.MAX_SNAPSHOT_BYTES,67108864)
 def test_04_exact_structural_command_only(self): self.assertEqual(policy.EXACT_GRAPHIFY_COMMAND,("python","-m","graphify","extract",".","--code-only","--no-cluster","--no-viz"))
 def test_05_start_boundary_precedes_clock_and_spawn(self):
  ev=[]
  class P:
   pid=1;returncode=1
   def wait(self,timeout):ev.append('wait');return 1
   def poll(self):return 1
  with tempfile.TemporaryDirectory() as d:
   b=Path(d);c=run.BuildConfig(b/'p',SHA,b/'proof',b/'w',b/'out');cl=iter([1.,1.,1.1]);run.run_disposable(c,preflight=lambda*a:ev.append('boundary'),clock=lambda:(ev.append('clock') or next(cl)),popen_factory=lambda*a,**k:(ev.append('spawn') or P()))
  self.assertLess(ev.index('boundary'),ev.index('clock'));self.assertLess(ev.index('boundary'),ev.index('spawn'))
 def test_06_provider_semantic_docs_api_model_mcp_db_denied(self):
  expected=("ANTHROPIC_API_KEY","AZURE_OPENAI_API_KEY","AZURE_OPENAI_ENDPOINT","AWS_ACCESS_KEY_ID","AWS_PROFILE","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN","DATABASE_URL","DEEPSEEK_API_KEY","FALKORDB_HOST","FALKORDB_PASSWORD","FALKORDB_PORT","GEMINI_API_KEY","GOOGLE_API_KEY","GOOGLE_APPLICATION_CREDENTIALS","MOONSHOT_API_KEY","NEO4J_PASSWORD","NEO4J_URI","NEO4J_USERNAME","OLLAMA_HOST","OPENAI_API_KEY","OPENAI_BASE_URL","PGDATABASE","PGHOST","PGPASSWORD","PGPORT","PGUSER")
  self.assertEqual(policy.PROVIDER_ENVIRONMENT_DENY,expected);self.assertTrue({"openai","anthropic","gemini","bedrock","pdf","mcp","neo4j","falkordb","postgres"}<=policy.FORBIDDEN_OPTIONAL_CAPABILITIES)
  for k in ("OPENAI_API_KEY","NEO4J_URI"):
   with self.assertRaises(runtime.BoundaryError):runtime.assert_sensitive_environment_absent({k:'x'})
 def test_07_github_hosted_disposable_required(self):
  runtime.assert_github_hosted_disposable({"GITHUB_ACTIONS":"true","RUNNER_OS":"Linux","RUNNER_ARCH":"X64","RUNNER_TEMP":"/tmp/x"})
  with self.assertRaises(runtime.BoundaryError):runtime.assert_github_hosted_disposable({"GITHUB_ACTIONS":"true","RUNNER_OS":"Linux","RUNNER_ARCH":"X64","RUNNER_TEMP":"relative"})
  s=(Path(__file__).parents[1]/'graphify_builder/run_github_hosted.sh').read_text();self.assertIn('unshare --net',s);self.assertIn('setpriv --reuid',s);self.assertIn('Phase A',s);self.assertIn('Phase B',s)
 def test_08_network_policy_fails_closed(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d);n=b/'net';n.mkdir();(n/'lo').mkdir();(n/'eth0').mkdir();r=b/'route';r.write_text('Iface Destination Gateway\n')
   with self.assertRaises(runtime.BoundaryError):runtime.assert_network_denied(n,r)
   (n/'eth0').rmdir();runtime.assert_network_denied(n,r)
 def test_09_timeout_exact_integer_monotonic_boundaries(self):
  self.assertIs(type(policy.BUILDER_TIMEOUT_SECONDS),int);self.assertEqual(policy.BUILDER_TIMEOUT_SECONDS,900);self.assertIs(run.run_disposable.__kwdefaults__['clock'],time.monotonic);self.assertEqual(policy.TIMEOUT_CLOCK,'monotonic');self.assertEqual(policy.TIMEOUT_START_BOUNDARY,'verified-wheelhouse-ready, network-denied, read-only-exact-source-ready');self.assertEqual(policy.TIMEOUT_END_BOUNDARY,'canonical-artifact-emission-complete')
 def test_10_timeout_scope_complete(self): self.assertEqual(worker.STAGE_ORDER,policy.TIMEOUT_SCOPE);self.assertEqual(policy.TIMEOUT_SCOPE,("offline-installation","exact-structural-graphify-invocation","output-parsing","normalization","schema-validation","digest-calculation","canonical-artifact-emission"))
 def test_11_timeout_kills_tree_discards_partial_health_only(self):
  kills=[]
  class P:
   pid=42;returncode=None
   def wait(self,timeout):(out/'snapshot.json').write_text('x');(out/'metadata.json').write_text('x');raise subprocess.TimeoutExpired('w',timeout)
   def poll(self):return None
  with tempfile.TemporaryDirectory() as d:
   b=Path(d);out=b/'out';c=run.BuildConfig(b/'p',SHA,b/'proof',b/'w',out);cl=iter([0.,0.]);rc=run.run_disposable(c,preflight=lambda*a:None,clock=lambda:next(cl),popen_factory=lambda*a,**k:P(),sleep=lambda _:None,killpg=lambda p,s:kills.append((p,s)))
   h=json.loads((out/'health.json').read_text());self.assertEqual(rc,124);self.assertFalse((out/'snapshot.json').exists() or (out/'metadata.json').exists());self.assertIn((42,signal.SIGTERM),kills);self.assertIn((42,signal.SIGKILL),kills);self.assertEqual((h['state'],h['usable'],h['snapshot_product_sha']),('timeout_incomplete_build',False,None));self.assertNotIn('snapshot_sha256',h)
 def test_12_exact_900_completion_is_still_timeout(self):
  class P:
   pid=9;returncode=0
   def wait(self,timeout):(out/'snapshot.json').write_text('x');return 0
   def poll(self):return 0
  with tempfile.TemporaryDirectory() as d:
   b=Path(d);out=b/'out';cl=iter([0.,0.,900.]);rc=run.run_disposable(run.BuildConfig(b/'p',SHA,b/'proof',b/'w',out),preflight=lambda*a:None,clock=lambda:next(cl),popen_factory=lambda*a,**k:P(),sleep=lambda _:None,killpg=lambda*a:None);self.assertEqual(rc,124);self.assertFalse((out/'snapshot.json').exists())
 def test_13_retry_clean_same_inputs_only(self):
  self.assertEqual((policy.RETRY_POLICY,policy.RETRY_PARTIAL_OUTPUT_REUSE,policy.RETRY_EXACT_INPUTS_POLICY),("clean-disposable-reexecution-only","forbidden","same-exact-inputs"))
  with tempfile.TemporaryDirectory() as d:
   b=Path(d);o=b/'o';o.mkdir();(o/'partial').write_text('x')
   with self.assertRaisesRegex(RuntimeError,'partial output reuse'):run.run_disposable(run.BuildConfig(b/'p',SHA,b/'proof',b/'w',o),preflight=lambda*a:None)
 def test_14_max_size_fail_closed(self):
  with tempfile.TemporaryDirectory() as d,mock.patch.object(normalize,'MAX_SNAPSHOT_BYTES',10):
   r=Path(d);(r/'pkg').mkdir()
   with self.assertRaises(normalize.OversizedSnapshotError):normalize.normalize_graph(graph(),SHA,r)
 def test_15_malformed_graph_fail_closed(self):
  with tempfile.TemporaryDirectory() as d:
   for bad in ({},{"nodes":[],"edges":"x"},{"nodes":[{"id":"x"}],"edges":[]}):
    with self.assertRaises(normalize.GraphOutputError):normalize.normalize_graph(bad,SHA,Path(d))
 def test_15a_pinned_graphify_file_node_kind_compatibility(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d);(r/"pkg").mkdir();node={"id":"pkg_a","label":"a.py","file_type":"code","source_file":"pkg/a.py","source_location":"L1"};g={"nodes":[node],"edges":[]};xs=[normalize.normalize_graph(g,SHA,r) for _ in range(3)]
   self.assertEqual(xs[0],xs[1]);self.assertEqual(xs[1],xs[2]);self.assertEqual((xs[0][0]["nodes"][0]["kind"],xs[0][0]["nodes"][0]["path"],xs[0][0]["nodes"][0]["qualified_name"]),("file","pkg/a.py","a.py"));self.assertEqual(hashlib.sha256(xs[0][1]).hexdigest(),xs[0][2])
   for fields,expected in (({"type":"class"},"class"),({"kind":"function"},"function"),({"node_type":"module"},"module"),({"type":"class","kind":"function","node_type":"module"},"class")):
    n=dict(node);n.update(fields);self.assertEqual(normalize._node_kind(n),expected)
   for bad in ({**node,"label":"not-a.py"},{**node,"file_type":"document"},{**node,"type":{}},{**node,"type":[]},{**node,"type":None}):
    with self.subTest(bad=bad):
     with self.assertRaisesRegex(normalize.GraphOutputError,"node kind must be text"):normalize._node_kind(bad)
 def test_15b_missing_discriminator_inventory_complete_deterministic_bounded(self):
  secret_dir='/host/private/'+'D'*200;source_file=secret_dir+'/'+('P'*200+'.py');long_id='I'*300;long_label='L'*300
  explicit=[{"id":"type-node","type":"class","label":"ExplicitType","file_type":"code","source_file":"pkg/e.py","source_location":"L2-L5"},{"id":"kind-node","kind":"function","label":"ExplicitKind","file_type":"code","source_file":"pkg/k.py","source_location":"L3-L6"},{"id":"node-type-node","node_type":"module","label":"ExplicitNodeType","file_type":"code","source_file":"pkg/n.py","source_location":"L1"}]
  file_node={"id":"file-node","label":"a.py","file_type":"code","source_file":"pkg/a.py","source_location":"L1"}
  unresolved=[{"id":long_id,"label":long_label,"file_type":"code","source_file":source_file,"source_location":"L2-L5"},{"id":"fn","label":"beta","file_type":"code","source_file":"pkg/a.py","source_location":"L8-L10"},{"id":"scoped","label":"gamma","file_type":"code","source_file":"pkg/a.py","source_location":"L9","symbol_scope":["local"]},{"id":"minimal","label":"delta","source_file":"pkg/a.py","source_location":None}]
  def inventory(nodes):
   with self.assertRaisesRegex(normalize.GraphOutputError,'missing node discriminator inventory') as cm:normalize.normalize_graph({"nodes":nodes,"edges":[]},SHA,Path('/tmp/not-used'))
   message=str(cm.exception);return message,json.loads(message.split(': ',1)[1])
  first,payload=inventory([*explicit,file_node,*unresolved]);second,payload2=inventory([*reversed(unresolved),file_node,*reversed(explicit)])
  self.assertEqual(first,second);self.assertEqual(payload,payload2);self.assertLess(len(first),4096);self.assertEqual(payload['total'],4);self.assertEqual([g['count'] for g in payload['groups']],[1,2,1]);self.assertEqual([g['keys'] for g in payload['groups']],[['file_type','id','label','source_file','source_location','symbol_scope'],['file_type','id','label','source_file','source_location'],['id','label','source_file','source_location']])
  self.assertEqual(payload['groups'][0]['key_types']['symbol_scope'],'array');self.assertEqual(payload['groups'][1]['key_types'],{'file_type':'string','id':'string','label':'string','source_file':'string','source_location':'string'});self.assertEqual(payload['groups'][2]['key_types']['source_location'],'null');self.assertFalse(payload['groups'][2]['representatives'][0]['file_type']['present']);self.assertEqual(payload['groups'][2]['representatives'][0]['file_type']['type'],'missing')
  for group in payload['groups']:
   for rep in group['representatives']:
    self.assertEqual(set(rep),{'id','label','source_file','source_location','file_type'})
    for field in ('id','label','source_file','source_location','file_type'):
     self.assertIn('present',rep[field]);self.assertIn('type',rep[field])
     if isinstance(rep[field].get('value'),str):self.assertLessEqual(len(rep[field]['value']),64)
  self.assertNotIn(secret_dir,first);self.assertNotIn(source_file,first);self.assertNotIn(long_id,first);self.assertNotIn(long_label,first)
  for excluded in ('type-node','kind-node','node-type-node','file-node'):self.assertNotIn(excluded,first)
 def test_15c_missing_discriminator_preflight_rejects_malformed_and_preserves_success(self):
  for bad,message in (({"nodes":[1],"edges":[]},'Graphify node is not an object'),({"nodes":[{"id":"x",1:"bad"}],"edges":[]},'Graphify node key must be text'),({"nodes":[{"label":"x"}],"edges":[]},'Graphify node id is unusable')):
   with self.subTest(message=message):
    with self.assertRaisesRegex(normalize.GraphOutputError,message):normalize.normalize_graph(bad,SHA,Path('/tmp/not-used'))
  malformed={"id":"x","label":"x.py","file_type":"code","source_file":"x.py","source_location":"L1","type":{}}
  with self.assertRaisesRegex(normalize.GraphOutputError,'node kind must be text'):normalize.normalize_graph({"nodes":[malformed],"edges":[]},SHA,Path('/tmp/not-used'))
  with tempfile.TemporaryDirectory() as d:
   r=Path(d);(r/'pkg').mkdir();snapshot,encoded,digest=normalize.normalize_graph(graph(),SHA,r);self.assertEqual([n['kind'] for n in snapshot['nodes']],['class','function']);self.assertEqual(hashlib.sha256(encoded).hexdigest(),digest)
 def test_15d_exact_d3_class_signature_maps_class(self):
  self.assertEqual(normalize._node_kind(d4_class_node()),"class")
 def test_15e_exact_d3_function_signature_maps_function(self):
  self.assertEqual(normalize._node_kind(d4_function_node()),"function")
 def test_15f_d4_exact_shapes_are_closed_and_type_strict(self):
  for base in (d4_class_node,d4_function_node):
   n=base();n["extra"]=True
   with self.subTest(shape=base.__name__,case="extra"):
    with self.assertRaises(normalize.GraphOutputError):normalize._node_kind(n)
  for base,field in ((d4_class_node,"_origin"),(d4_function_node,"_origin")):
   n=base();del n[field]
   with self.subTest(shape=base.__name__,case="removed"):
    with self.assertRaises(normalize.GraphOutputError):normalize._node_kind(n)
  for base,field,value in ((d4_class_node,"_callable",1),(d4_class_node,"_callable_class",1),(d4_class_node,"_origin",1),(d4_function_node,"_callable",1),(d4_function_node,"_origin",1),(d4_class_node,"file_type","document"),(d4_function_node,"file_type","document")):
   n=base();n[field]=value
   with self.subTest(shape=base.__name__,field=field,value=value):
    with self.assertRaises(normalize.GraphOutputError):normalize._node_kind(n)
  for base in (d4_class_node,d4_function_node):
   for field in ("id","label","source_file","source_location"):
    n=base();n[field]=7
    with self.subTest(shape=base.__name__,field=field):
     with self.assertRaises(normalize.GraphOutputError):normalize._node_kind(n)
   n=base();n["source_location"]="L1-L2"
   with self.subTest(shape=base.__name__,case="line-range"):
    with self.assertRaises(normalize.GraphOutputError):normalize._node_kind(n)
  n=d4_class_node();n["_callable"]=False;n["_callable_class"]=True;n["_origin"]="other";self.assertEqual(normalize._node_kind(n),"class")
  n=d4_function_node();n["_callable"]=True;n["_origin"]="other";self.assertEqual(normalize._node_kind(n),"function")
 def test_15g_d4_preserves_d2_and_explicit_precedence_and_fails_ambiguous_closed(self):
  self.assertEqual(normalize._node_kind(d4_file_node()),"file")
  n=d4_class_node();n.update({"type":"module","kind":"function","node_type":"class"});self.assertEqual(normalize._node_kind(n),"module")
  n=d4_function_node();n.update({"kind":"module","node_type":"class"});self.assertEqual(normalize._node_kind(n),"module")
  n=d4_function_node();n["node_type"]="module";self.assertEqual(normalize._node_kind(n),"module")
  n=d4_class_node();n["type"]={}
  with self.assertRaisesRegex(normalize.GraphOutputError,"node kind must be text"):normalize._node_kind(n)
  for base in (d4_class_node,d4_function_node):
   n=base();n["label"]="a.py"
   with self.subTest(shape=base.__name__,case="d2-basename"):
    self.assertEqual(normalize._node_kind(n),"file")
  with mock.patch.object(normalize,"_d3_compat_node_kind",return_value="class"):
   with self.assertRaisesRegex(normalize.GraphOutputError,"ambiguous missing-discriminator node kind"):normalize._missing_discriminator_kind(d4_file_node())
 def test_15h_d4_unknown_reduced_extended_and_line_shapes_remain_fail_closed(self):
  bad=(
   {**d4_function_node(),"symbol_scope":["local"]},
   {k:v for k,v in d4_function_node().items() if k!="source_location"},
   {**d4_class_node(),"symbol_scope":["local"]},
   {k:v for k,v in d4_class_node().items() if k!="source_location"},
  )
  for node in bad:
   with self.subTest(keys=sorted(node)):
    with self.assertRaises(normalize.GraphOutputError):normalize._node_kind(node)
  with tempfile.TemporaryDirectory() as d:
   r=Path(d);(r/"pkg").mkdir();snapshot,encoded,digest=normalize.normalize_graph(graph(),SHA,r);self.assertEqual([n["kind"] for n in snapshot["nodes"]],["class","function"]);self.assertEqual(hashlib.sha256(encoded).hexdigest(),digest)
 def test_15i_d4_file_class_function_three_run_determinism(self):
  g={"nodes":[d4_file_node(),d4_class_node(),d4_function_node()],"edges":[{"source":"pkg_a","target":"pkg_a_a","relation":"contains"},{"source":"pkg_a_a","target":"pkg_a_f","relation":"calls"}]}
  with tempfile.TemporaryDirectory() as d:xs=[normalize.normalize_graph(g,SHA,Path(d)) for _ in range(3)]
  self.assertEqual(xs[0],xs[1]);self.assertEqual(xs[1],xs[2]);self.assertEqual(hashlib.sha256(xs[0][1]).hexdigest(),xs[0][2]);self.assertEqual({n["qualified_name"]:n["kind"] for n in xs[0][0]["nodes"]},{"a.py":"file","A":"class","f()":"function"})
 def test_16_source_proof_exact_sha(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'p';p.write_text(json.dumps({"repository":"Dsamofalov/hwm_predictor","product_sha":"0"*40}))
   with self.assertRaises(runtime.BoundaryError):runtime.validate_source_proof(p,SHA)
   p.write_text(json.dumps({"repository":"Dsamofalov/hwm_predictor","product_sha":SHA}));runtime.validate_source_proof(p,SHA)
 def test_17_sdist_host_and_hash_mismatch_fail_closed(self):
  with self.assertRaises(wheelhouse.WheelhouseError):wheelhouse._validate_download_url('https://files.pythonhosted.org/x/graphifyy-0.9.38.tar.gz','graphifyy-0.9.38.tar.gz')
  with self.assertRaises(wheelhouse.WheelhouseError):wheelhouse._validate_download_url('https://example.com/x/a.whl','a.whl')
 def test_18_default_lock_closure_has_no_optional_extras(self):
  lock={"version":1,"revision":3,"package":[{"name":"graphifyy","version":"0.9.31","source":{"editable":"."},"dependencies":[{"name":"networkx"}],"optional-dependencies":{"openai":[{"name":"openai"}],"mcp":[{"name":"mcp"}]}},{"name":"networkx","version":"3.6.1","source":{"registry":"https://pypi.org/simple"},"wheels":[{"url":"https://files.pythonhosted.org/p/networkx-3.6.1-py3-none-any.whl","hash":"sha256:"+'a'*64}]},{"name":"openai","version":"9","source":{"registry":"https://pypi.org/simple"},"wheels":[]},{"name":"mcp","version":"9","source":{"registry":"https://pypi.org/simple"},"wheels":[]}]}
  s=wheelhouse.select_default_closure(lock);self.assertEqual([p['name'] for p in s],['networkx']);self.assertEqual(wheelhouse.select_locked_wheel(s[0])['sha256'],'a'*64)
 def test_19_wheelhouse_graphify_hash_enforced(self):
  with tempfile.TemporaryDirectory() as d:
   w=Path(d);a={"filename":policy.GRAPHIFY_WHEEL,"name":"graphifyy","sha256":policy.GRAPHIFY_WHEEL_SHA256,"source":"hwm-graphify-supply-chain/v2","url":policy.GRAPHIFY_WHEEL_URL,"version":"0.9.38"};m={"schema":"hwm-graphify-wheelhouse/v1","upstream_commit":policy.UPSTREAM_COMMIT,"uv_lock_blob_sha":policy.UPSTREAM_UV_LOCK_BLOB_SHA,"runtime":{"python":"3.12.10","platform":"linux-x86_64"},"artifacts":[a],"license_files":[],"optional_extras":[],"build_time_resolution":False};raw=json.dumps(m,sort_keys=True,separators=(',',':')).encode();(w/'manifest.json').write_bytes(raw);(w/'.verified-ready').write_text(hashlib.sha256(raw).hexdigest());(w/policy.GRAPHIFY_WHEEL).write_bytes(b'bad')
   with self.assertRaises(wheelhouse.WheelhouseError):wheelhouse.verify_wheelhouse(w)
 def test_20_graph_schemas_unchanged_and_no_publication(self):
  self.assertEqual((policy.SNAPSHOT_SCHEMA_BLOB_SHA,policy.METADATA_SCHEMA_BLOB_SHA,policy.HEALTH_SCHEMA_BLOB_SHA,policy.QUERY_SCHEMA_BLOB_SHA),("5f96d6bf7da37a08b975cbedc1feccdbfe1ace12","dee33775e362d48a6a7fa5cd34b0660aceeea679","b3495ee2ddab379330625ee06e5377fc8d7105d8","5ac42a42e8f51a0dc3c250e472e4c23ae5b6f5c4"));s=(Path(__file__).parents[1]/'graphify_builder/run_github_hosted.sh').read_text();self.assertFalse(any(x in s for x in ('upload-artifact','hwm-context','git push','graphify serve')));self.assertFalse((Path(__file__).parents[1]/'.github/workflows/graphify-disposable-builder.yml').exists());self.assertEqual((policy.TIMEOUT_SNAPSHOT_IDENTITY,policy.TIMEOUT_PUBLICATION_POLICY),(None,'forbidden'))
if __name__=='__main__':unittest.main()
