// Model-free R1 real OpenCode API and kernel-level negative checks.
// Standard-library-only; compiled with CGO_ENABLED=0 and GOPROXY=off on GitHub runner.
// NOT a model capability benchmark; not proof of arbitrary raw API security.
package main
import (
  "bytes"
  "crypto/sha256"
  "encoding/json"
  "errors"
  "fmt"
  "io"
  "net"
  "net/http"
  "os"
  "os/exec"
  "path/filepath"
  "strings"
  "syscall"
  "time"
)
type Check struct { Test string `json:"test"`; Verdict string `json:"verdict"`; Detail string `json:"detail"` }
var checks []Check
func record(name,detail string) { if len(detail)>160 {detail=detail[:160]}; checks=append(checks,Check{name,"PASS",detail});fmt.Printf("%s: PASS\n",name) }
func must(ok bool,why string) { if !ok {panic(why)} }
func api(method,path string, body any) any {
  allowed:=path=="/api/info"||path=="/api/config"||path=="/api/plugin"||path=="/api/mcp"||path=="/api/session"||(strings.HasPrefix(path,"/api/session/") && strings.HasSuffix(path,"/permission"))
  must(allowed,"UNAPPROVED_API_ROUTE")
  var buf io.Reader
  if body!=nil {b,e:=json.Marshal(body);must(e==nil,"JSON_ENCODE_FAILED");buf=bytes.NewReader(b)}
  req,e:=http.NewRequest(method,"http://127.0.0.1:4096"+path,buf);must(e==nil,"HTTP_REQUEST_INVALID")
  req.Header.Set("Content-Type","application/json")
  client:=&http.Client{Timeout:5*time.Second,Transport:&http.Transport{Proxy:nil}}
  resp,e:=client.Do(req);must(e==nil,"OPEN_CODE_API_UNREACHABLE")
  defer resp.Body.Close()
  must(resp.StatusCode==200,fmt.Sprintf("OPEN_CODE_API_HTTP_%d_%s",resp.StatusCode,path))
  data,e:=io.ReadAll(io.LimitReader(resp.Body,1048577));must(e==nil&&len(data)<=1048576,"API_OVERSIZE")
  var decoded any
  must(json.Unmarshal(data,&decoded)==nil,"API_INVALID_JSON")
  return decoded
}
func readOnly(path string) {
  f,e:=os.OpenFile(path,os.O_CREATE|os.O_WRONLY|os.O_APPEND,0600)
  if e==nil {f.Close();panic("IMMUTABLE_WRITABLE_"+path)}
  if !errors.Is(e,syscall.EACCES)&&!errors.Is(e,syscall.EROFS)&&!errors.Is(e,syscall.EPERM) {panic("IMMUTABLE_UNEXPECTED_ERROR_"+path+":"+e.Error())}
}
func checksRun() {
  output,e:=exec.Command("/opt/bin/opencode","--version").CombinedOutput()
  must(e==nil&&strings.Contains(string(output),"2.0.29"),"CLI_VERSION_FAILURE")
  record("real_v2_0_29","version_verified")
  c,e:=os.ReadFile("/workspace/opencode.json");must(e==nil,"CONFIG_READ_FAILED")
  must(bytes.Contains(c,[]byte(`"permissions"`))&&bytes.Contains(c,[]byte(`"policies"`)),"INVALID_CONFIG")
  for _,p:=range []string{"/workspace/opencode.json","/workspace/README.md","/workspace/tests/test_selection.py","/workspace/src/__init__.py","/workspace/src/unapproved.py"}{readOnly(p)}
  record("os_immutable_paths","readonly")
  allowed:="/workspace/src/selection.py"
  before,e:=os.ReadFile(allowed);must(e==nil,"ALLOWLIST_FILE_MISSING")
  f,e:=os.OpenFile(allowed,os.O_APPEND|os.O_WRONLY,0);must(e==nil,"ALLOWLIST_WRITE_DENIED")
  _,e=f.Write([]byte("\n# R1 ephemeral marker\n"));must(e==nil,"ALLOWLIST_WRITE_FAILED");must(f.Close()==nil,"ALLOWLIST_CLOSE_FAILED")
  must(os.WriteFile(allowed,before,0666)==nil,"ALLOWLIST_RESTORE_FAILED")
  after,e:=os.ReadFile(allowed);must(e==nil,"RESTORE_UNREADABLE")
  must(sha256.Sum256(before)==sha256.Sum256(after),"ALLOWLIST_HASH_CHANGED")
  record("os_allowed_file_only","restored")
  con,e:=net.DialTimeout("tcp","192.0.2.55:443",1*time.Second)
  if e==nil {con.Close();panic("NON_LOOPBACK_EGRESS_NOT_BLOCKED")}
  record("os_no_external_egress","connection_failed")
  cmd:=exec.Command("/opt/bin/opencode","serve","--hostname","127.0.0.1","--port","4096")
  cmd.Dir="/workspace";cmd.Env=os.Environ();cmd.Stdout=io.Discard;cmd.Stderr=io.Discard
  must(cmd.Start()==nil,"RUNTIME_SERVER_FAILED_TO_SPAWN")
  defer func(){_ = cmd.Process.Kill();_ = cmd.Wait()}()
  deadline:=time.Now().Add(25*time.Second)
  ready:=false
  for time.Now().Before(deadline) {
    if cmd.ProcessState!=nil&&cmd.ProcessState.Exited(){break}
    ok:=func() bool{c:=&http.Client{Timeout:400*time.Millisecond,Transport:&http.Transport{Proxy:nil}};r,e:=c.Get("http://127.0.0.1:4096/api/info");if e!=nil{return false};defer r.Body.Close();return r.StatusCode==200}()
    if ok {ready=true;break};time.Sleep(250*time.Millisecond)
  }
  must(ready,"SERVER_NOT_READY")
  record("actual_server_start","loopback_only")
  cfg:=api("GET","/api/config",nil)
  cfglist,ok:=cfg.([]any)
  must(ok&&len(cfglist)==1,"EFFECTIVE_CONFIG_SOURCES_UNEXPECTED")
  cfgjson,_:=json.Marshal(cfglist[0])
  must(bytes.Contains(cfgjson,[]byte("src/selection.py"))&&bytes.Contains(cfgjson,[]byte("integration.use"))&&bytes.Contains(cfgjson,[]byte("tool.use")),"EFFECTIVE_CONFIG_UNVERIFIED")
  must(bytes.Contains(cfgjson,[]byte("/workspace/opencode.json")),"EFFECTIVE_CONFIG_PATH_UNVERIFIED")
  record("effective_config","rules_present")
  plug:=api("GET","/api/plugin",nil);plugmap,ok:=plug.(map[string]any);must(ok,"PLUGIN_WRAPPER_UNVERIFIED");pitems,ok:=plugmap["data"].([]any);must(ok,"PLUGIN_INVENTORY_UNVERIFIED")
  for _,a:=range pitems {
    item,ok:=a.(map[string]any);must(ok,"UNEXPECTED_PLUGIN_SHAPE")
    name,_:=item["id"].(string)
    must(name=="policy"||name=="console","UNEXPECTED_PLUGIN_LOADED")
  }
  record("actual_plugin_inventory","no_third_party")
  mcp:=api("GET","/api/mcp",nil);mcpmap,ok:=mcp.(map[string]any);must(ok,"MCP_WRAPPER_UNVERIFIED");m:=mcpmap["data"]
  switch x:=m.(type){case map[string]any:must(len(x)==0,"MCP_NOT_EMPTY");case []any:must(len(x)==0,"MCP_NOT_EMPTY");default:panic("MCP_INVENTORY_UNVERIFIED")}
  record("actual_mcp_inventory","none")
  session:=api("POST","/api/session",map[string]any{"title":"R1 model-free permission checks"})
  sessionmap,ok:=session.(map[string]any);must(ok,"SESSION_WRAPPER_MISMATCH")
  data,ok:=sessionmap["data"].(map[string]any);must(ok,"SESSION_SHAPE_MISMATCH")
  sid,ok:=data["id"].(string);must(ok&&strings.HasPrefix(sid,"ses_"),"SESSION_ID_NOT_VERIFIED")
  type Probe struct{ Action,Resource,Expected string }
  probes:=[]Probe{
    {"read","README.md","allow"},{"read","src/selection.py","allow"},{"read","tests/test_selection.py","allow"},{"edit","src/selection.py","allow"},
    {"shell","git push origin main","deny"},{"shell","touch tests/tampered","deny"},{"execute","*","deny"},
    {"external_directory","/etc/*","deny"},{"read","/etc/passwd","deny"},{"read","../../private","deny"},
    {"read",".env","deny"},{"edit","tests/test_selection.py","deny"},{"edit","README.md","deny"},{"edit","opencode.json","deny"},
    {"edit","src/forbidden.py","deny"},{"webfetch","https://example.com","deny"},{"websearch","x","deny"},
    {"subagent","general","deny"},{"skill","irrelevant","deny"},{"github_delete_repository","*","deny"},
    {"opencode_list_mcp_resources","github","deny"},{"opencode_read_mcp_resource","github:secret","deny"},
  }
  for i,p:=range probes {
    resp:=api("POST",filepath.ToSlash(filepath.Join("/api/session",sid,"permission")),map[string]any{"action":p.Action,"resources":[]string{p.Resource}})
    responsemap,ok:=resp.(map[string]any);must(ok,fmt.Sprintf("PERMISSION_WRAPPER_SHAPE_%d",i))
    d,ok:=responsemap["data"].(map[string]any);must(ok,fmt.Sprintf("PERMISSION_RESPONSE_SHAPE_%d",i))
    effect,_:=d["effect"].(string);must(effect==p.Expected,fmt.Sprintf("PERMISSION_EFFECT_MISMATCH_%d_%s_%s_%s",i,p.Action,effect,p.Expected))
    record(fmt.Sprintf("real_permission_%02d_%s",i,p.Action),effect)
  }
  record("real_permission_gate","22_checks")
}
func main(){
  var reason string
  func(){defer func(){if e:=recover();e!=nil{reason=fmt.Sprint(e)}}();checksRun()}()
  result:=map[string]any{"status":"R1_REAL_RUNTIME_PASS","checks":checks}
  if reason!="" {result["status"]="R1_ENVIRONMENT_BLOCKED";result["reason"]=reason;fmt.Println("R1_HOLD:",reason)}
  output,_:=json.Marshal(result)
  fmt.Println("R1_JSON_RESULT="+string(output))
  if reason!=""{os.Exit(87)}
  fmt.Println("R1_REAL_PERMISSION_API_AND_OS_GATE_PASS")
}
