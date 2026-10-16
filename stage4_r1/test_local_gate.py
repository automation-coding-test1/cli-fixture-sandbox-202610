"""Independent deterministic LOCAL STATIC gate (never called 'runtime verified')."""
import fnmatch,hashlib,json,pathlib,unittest
R=pathlib.Path(__file__).resolve().parent
C=json.loads((R/'fixture/opencode.json').read_text())
P=C['permissions']; Q=C['policies']
def check(items,a,r,default='ask'):
 e=default
 for x in items:
  if fnmatch.fnmatchcase(a,x['action']) and fnmatch.fnmatchcase(r,x['resource']):e=x['effect']
 return e
def permit(a,r):
 return check(P,a,r)=='allow' and check(Q,'tool.use',a+':'+r,'allow')!='deny'
class R1StaticGate(unittest.TestCase):
 def test_minimal_config(self):
  self.assertEqual(C['update'],'disable')
  self.assertEqual(C['mcp'],{'servers':{}})
  self.assertEqual(C['plugins'],[]);self.assertEqual(C['skills'],[])
  self.assertFalse(C['formatter']);self.assertFalse(C['snapshots'])
  self.assertEqual(P[0],dict(action='*',resource='*',effect='deny'))
  self.assertEqual(Q[0],dict(action='tool.use',resource='*',effect='deny'))
  self.assertEqual({a['action'] for a in Q}, {'tool.use','integration.use','provider.use'})
 def test_allow_only_four(self):
  allow={(x['action'],x['resource']) for x in P[1:] if x['effect']=='allow'}
  self.assertEqual(allow,{('read','README.md'),('read','src/selection.py'),('read','tests/test_selection.py'),('edit','src/selection.py')})
  for a,r in allow:self.assertTrue(permit(a,r))
 def test_negative_tools(self):
  tests=[('shell','git push origin main'),('shell','ls'),('webfetch','http://127.0.0.1:4096'),('websearch','*'),('external_directory','/etc/*'),('execute','*'),('read','/etc/passwd'),('read','../../private'),('read','.env'),('edit','tests/test_selection.py'),('edit','opencode.json'),('edit','README.md'),('edit','src/nope.py'),('read','src/selection.py.old'),('glob','*'),('grep','*'),('subagent','general'),('skill','*'),('github_delete_repository','*'),('opencode_list_mcp_resources','any')]
  for a,r in tests:
   with self.subTest(a=a,r=r):self.assertFalse(permit(a,r))
 def test_integration_and_provider_denies(self):
  for a,items in [('integration.use',['mcp:github','plugin:evil','skill:foo']),('provider.use',['openai','ollama','anthropic','r1mock'])]:
   for r in items:self.assertEqual(check(Q,a,r,'allow'),'deny')
 def test_prevent_trailing_grant(self):
  expected={('read','README.md'),('read','src/selection.py'),('read','tests/test_selection.py'),('edit','src/selection.py')}
  allows={(e['resource'].split(':',1)[0],e['resource'].split(':',1)[1]) for e in Q if e['action']=='tool.use' and e['effect']=='allow'}
  self.assertEqual(allows,expected)
  self.assertEqual(set(C),{'permissions','policies','mcp','plugins','formatter','snapshots','skills','update'})
 def test_synthetic_inventory(self):
  actual={x.relative_to(R/'fixture').as_posix() for x in (R/'fixture').rglob('*') if x.is_file()}
  self.assertEqual(actual,{'README.md','opencode.json','src/__init__.py','src/selection.py','tests/__init__.py','tests/test_selection.py'})
  for p in (R/'fixture').rglob('*'):
   self.assertFalse(p.is_symlink())
 def test_wrapper_scope(self):
  t=(R/'r1_runtime_probe.go').read_text()
  self.assertIn('R1_ENVIRONMENT_BLOCKED',t)
  self.assertIn('192.0.2.55:443',t)
  self.assertIn('p.Action',t)
  self.assertNotIn('opencode run ',t)
  self.assertNotIn('OPENCODE_API_KEY',t)
  self.assertIn('R1_JSON_RESULT=',t)
  self.assertNotIn('/tmp/evidence',t)
  self.assertNotIn('ANTHROPIC_API_KEY',t)
 def test_policy_mutation_trailing_shell_grant_detected(self):
  mut=Q+[{'action':'tool.use','resource':'shell:*','effect':'allow'}]
  self.assertEqual(check(mut,'tool.use','shell:git push origin main','allow'),'allow')
  self.assertNotEqual(mut,Q)
 def test_policy_mutation_provider_override_detected(self):
  mut=Q+[{'action':'provider.use','resource':'openai','effect':'allow'}]
  self.assertEqual(check(mut,'provider.use','openai','allow'),'allow')
  self.assertEqual(check(Q,'provider.use','openai','allow'),'deny')
 def test_policy_mutation_external_path_detected(self):
  mut=P+[{'action':'edit','resource':'../../outside','effect':'allow'}]
  self.assertEqual(check(mut,'edit','../../outside'),'allow')
  self.assertNotEqual(mut,P)
 def test_reference_manifest(self):
  data=json.loads((R/'STAGE3_PROVENANCE.json').read_text())
  self.assertEqual(data['stage3_run_id'],38836182752)
  self.assertEqual(data['cli_version'],'2.0.29')
  self.assertEqual(len(data['cli_elf_sha256']),64)
if __name__=='__main__':unittest.main(verbosity=2)
