package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"local/aistudio-signer/transport"
	"local/aistudio-signer/waa"
)

const (
	waaCreateURL="https://waa-pa.clients6.google.com/$rpc/google.internal.waa.v1.Waa/Create"
	waaRequestKey="lmnUSbltwc5ULv48iKLX"
	waaAPIKey="AIzaSyBGb5fGAyC-pRcRU6MUHb__b_vKha71HRE"
	bootstrapLimit=16<<20

	// Startup uses the init context, as the reference catalogue task does.
	// Only a request-time refresh gets its own bounded lookup budget.
	benefitRefreshTimeout = 30 * time.Second
	benefitSuccessTTL     = 5 * time.Minute
	benefitMaxAge         = 30 * time.Minute // measured from the last successful lookup
)

var apiKeyPattern=regexp.MustCompile(`"WIu0Nc":"([^"]+)"`)
var togglesPattern=regexp.MustCompile(`window\["_F_toggles_default_MakerSuite"\]\s*=\s*\[([^\]]*)\]`)
var globalsPattern=regexp.MustCompile(`var (_F_cssRowKey|_F_combinedSignature) = '([^']*)'`)
var loggingMaxAgePattern = regexp.MustCompile(`"NHyHAe":(\d+)`)

func numberValue(v any)(float64,bool){
	switch n:=v.(type){case float64:return n,true;case int:return float64(n),true;case json.Number:f,err:=n.Float64();return f,err==nil}
	return 0,false
}

func profileFromConfig(c map[string]any)(waa.Profile,string,string){
	p:=waa.Profile{Window:map[string]any{},Navigator:map[string]any{},Screen:map[string]any{},Document:map[string]any{},HasFocus:true}
	for key,value:=range c{
		scope,name,ok:=strings.Cut(key,".");if !ok{continue}
		switch scope{case "window":p.Window[name]=value;case "navigator":p.Navigator[name]=value;case "screen":p.Screen[name]=value}
	}
	p.Locale,_=c["navigator.language"].(string)
	p.TimeZone,_=c["timezone"].(string)
	p.Navigator["doNotTrack"]="unspecified"
	p.Navigator["globalPrivacyControl"]=false
	for _,key:=range []string{"availLeft","availTop"}{if _,ok:=p.Screen[key];!ok{p.Screen[key]=0}}
	if _,ok:=p.Window["innerWidth"];!ok{p.Window["innerWidth"]=p.Window["outerWidth"]}
	if _,ok:=p.Window["innerHeight"];!ok{if n,ok:=numberValue(p.Window["outerHeight"]);ok{p.Window["innerHeight"]=n-85}}
	for _,device:=range [][2]string{{"mediaDevices:micros","audioinput"},{"mediaDevices:webcams","videoinput"}}{if n,_:=numberValue(c[device[0]]);n>0{p.MediaInputs=append(p.MediaInputs,device[1])}}
	ua,_:=c["navigator.userAgent"].(string)
	language,_:=c["headers.Accept-Language"].(string)
	return p,ua,language
}

// Resource callbacks accept only HTTPS Google-owned host suffixes. No caller
// supplied endpoint or authorization header is accepted through IPC.
func googleHost(host string)bool{
	host=strings.ToLower(strings.TrimSuffix(host,"."))
	for _,base:=range []string{"google.com","gstatic.com","googleusercontent.com","googleapis.com"}{
		if host==base || strings.HasSuffix(host,"."+base){return true}
	}
	return false
}

func allowedURL(raw string)bool{
	u,err:=url.Parse(raw)
	return err==nil && u.Scheme=="https" && u.User==nil && (u.Port()=="" || u.Port()=="443") && googleHost(u.Hostname())
}

func (e *engine) do(ctx context.Context,method,target string,body []byte,headers http.Header)(*http.Response,error){
	if !allowedURL(target){return nil,failure("INVALID_ENDPOINT","Endpoint is outside the component's allowed origins.")}
	var reader io.Reader
	if body!=nil{reader=bytes.NewReader(body)}
	req,err:=http.NewRequestWithContext(ctx,method,target,reader)
	if err!=nil{return nil,err}
	req.Header=headers.Clone()
	if req.Header==nil{req.Header=make(http.Header)}
	req.Header.Set("User-Agent",e.userAgent)
	req.Header.Set("Accept-Language",e.language)
	if req.Header.Get("Accept-Encoding")==""{req.Header.Set("Accept-Encoding","gzip, deflate, br, zstd")}
	// Do not permit automatic replay of a submitted authenticated POST.
	if method==http.MethodPost{req.GetBody=nil}
	// One ordered account state supplies both authentication and transport.
	// Recompute for every target, including each explicitly followed redirect.
	authenticated := req.Header.Get("Authorization") != ""
	cookie, auth, err := e.session.requestCredentials(req.URL, authenticated)
	if err != nil {
		e.shared.invalidateBenefit()
		return nil, err
	}
	req.Header.Del("Cookie")
	if cookie != "" { req.Header.Set("Cookie", cookie) }
	if authenticated { req.Header.Set("Authorization", auth) }
	response, err := e.client.Do(req)
	if err != nil { return response, err }
	e.session.SetCookies(req.URL, response.Cookies())
	return response, nil
}

func readBounded(response *http.Response,limit int64)([]byte,error){
	defer response.Body.Close()
	body,err:=io.ReadAll(io.LimitReader(response.Body,limit+1))
	if err!=nil{return nil,err}
	if int64(len(body))>limit{return nil,failure("RESPONSE_TOO_LARGE","Initialization response exceeded its size limit.")}
	return body,nil
}

func (e *engine) rpcHeaders(key string)(http.Header,error){
	auth, err := e.session.authorization()
	if err != nil {
		e.shared.invalidateBenefit()
		return nil, err
	}
	h:=http.Header{}
	h.Set("Accept","*/*")
	h.Set("Content-Type","application/json+protobuf")
	h.Set("Origin",studioOrigin)
	h.Set("Referer",studioOrigin+"/")
	h.Set("Authorization",auth)
	h.Set("X-Goog-Api-Key",key)
	h.Set("X-Goog-AuthUser",strconv.Itoa(e.config.AuthUser))
	h.Set("X-User-Agent","grpc-web-javascript/0.1")
	h.Set("Sec-Fetch-Dest","empty")
	h.Set("Sec-Fetch-Mode","cors")
	h.Set("Sec-Fetch-Site","same-site")
	if key!=waaAPIKey{
		if e.visitID!=""{h.Set("X-AIStudio-Visit-Id",e.visitID)}
		// Startup RPCs race logging completion in the reference. They do not
		// read a partially published extension; all business calls use it.
		if e.initialized && e.logHeader!=""{h.Set("X-Goog-Ext-519733851-bin",e.logHeader)}
	}
	return h,nil
}

func (e *engine) loadPage(ctx context.Context)error{
	path:="/prompts/new_chat"
	if e.config.AuthUser>0{path=fmt.Sprintf("/u/%d/prompts/new_chat",e.config.AuthUser)}
	e.pageURL=studioOrigin+path+"?model="+url.QueryEscape(e.config.Model)+"&temporary=true"
	target:=e.pageURL
	started:=time.Now()
	headers:=http.Header{}
	headers.Set("Accept","text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	headers.Set("Upgrade-Insecure-Requests","1")
	headers.Set("Sec-Fetch-Dest","document")
	headers.Set("Sec-Fetch-Mode","navigate")
	headers.Set("Sec-Fetch-Site","none")
	headers.Set("Sec-Fetch-User","?1")
	headers.Set("Priority", "u=0, i")
	for i:=0;i<5;i++{
		traceCtx, snapshot := transport.TraceConnection(ctx)
		response,err:=e.do(traceCtx,http.MethodGet,target,nil,headers);if err!=nil{return err}
		body,err:=readBounded(response,bootstrapLimit);if err!=nil{return err}
		if response.StatusCode>=300 && response.StatusCode<400{
			location,err:=response.Location();if err!=nil{return err}
			if location.Hostname()=="accounts.google.com"{return failure("AUTH_REQUIRED","Account session requires interactive sign-in.")}
			if location.Hostname()!="aistudio.google.com"{return failure("ACCESS_DENIED","AI Studio redirected outside the application.")}
			target=location.String();continue
		}
		if response.StatusCode!=http.StatusOK{return failure("BOOTSTRAP_HTTP","AI Studio page did not return HTTP 200.")}
		match:=apiKeyPattern.FindSubmatch(body)
		if len(match)!=2{return failure("BOOTSTRAP_FORMAT","AI Studio page has no recognizable API configuration.")}
		e.apiKey=string(match[1])
		e.audit.pageBuild(ctx, body)
		e.pageURL=target
		e.profile.PageURL=target
		e.profile.NavigationStart=started
		e.profile.LocalStorage = e.session.storageSnapshot()
		e.profile.Globals=map[string]any{}
		if m:=togglesPattern.FindSubmatch(body);len(m)>1{
			var toggles []any
			for _,part:=range strings.Split(string(m[1]),","){if v,err:=strconv.ParseInt(strings.TrimSpace(part),0,64);err==nil{toggles=append(toggles,v)}}
			e.profile.Globals["_F_toggles_default_MakerSuite"]=toggles
		}
		for _,m:=range globalsPattern.FindAllSubmatch(body,-1){e.profile.Globals[string(m[1])]=string(m[2])}
		for _,policy:=range response.Header.Values("Content-Security-Policy"){
			e.profile.TrustedTypes=e.profile.TrustedTypes || strings.Contains(policy,"require-trusted-types-for 'script'")
		}
		e.pageLoaded = time.Now()
		if m := loggingMaxAgePattern.FindSubmatch(body); len(m) == 2 {
			e.loggingMaxAge, _ = strconv.ParseInt(string(m[1]), 10, 64)
		}
		e.profile.Document=map[string]any{"cookie":e.session.documentCookie(),"lastModified":e.lastModified(e.profile.TimeZone)}
		e.profile.Navigation, e.profile.DOMLoading = navigationTiming(pageLoad{
			url: target, protocol: nextHopProtocol(response), started: started,
			connection: snapshot(), end: e.pageLoaded.Sub(started), decoded: len(body),
		})
		document := parsePageDocument(body, target)
		if err=e.loadDocumentResources(ctx,document);err!=nil{return err}
		documentTiming(e.profile.Navigation, time.Since(started))
		e.loadPageIcons(document)
		var id [16]byte
		if _,err=rand.Read(id[:]);err!=nil{return err}
		id[6]=id[6]&0x0f|0x40;id[8]=id[8]&0x3f|0x80
		uuid:=fmt.Sprintf("%x-%x-%x-%x-%x",id[:4],id[4:6],id[6:8],id[8:10],id[10:])
		e.visitID="v1_"+base64.StdEncoding.EncodeToString([]byte(uuid))
		return nil
	}
	return failure("BOOTSTRAP_REDIRECT","Too many page redirects.")
}

// Logging context is an auxiliary JSPB RPC. Business requests never use JSPB.
func (e *engine) loadLoggingContext(ctx context.Context)error{
	h,err:=e.rpcHeaders(e.apiKey);if err!=nil{return err}
	requestBody := []byte("[]")
	var cached struct { Timestamp int64 `json:"timestamp"`; Result string `json:"result"` }
	if e.loggingMaxAge > 0 && json.Unmarshal([]byte(e.session.pageStorageValue("ais_glcr")), &cached) == nil &&
		cached.Timestamp > 0 && time.Now().UnixMilli()-cached.Timestamp <= e.loggingMaxAge {
		if cached.Result == "true" { requestBody = []byte("[1]") } else if cached.Result == "false" { requestBody = []byte("[0]") }
	}
	response,err:=e.do(ctx,http.MethodPost,makerRPC+"GetLoggingContext",requestBody,h)
	if err!=nil{return err}
	body,err:=readBounded(response,1<<20);if err!=nil{return err}
	if response.StatusCode!=http.StatusOK{return failure("CONTEXT_HTTP","Cannot obtain account logging context.")}
	binary,err:=loggingFields(body);if err!=nil{return failure("CONTEXT_FORMAT","Unsupported logging context format.")}
	e.logHeader=base64.StdEncoding.EncodeToString(binary)
	var fields []json.RawMessage
	_ = json.Unmarshal(body, &fields)
	result := "false"
	if len(fields) > 1 && textValue(fields[1]) == "B" { result = "true" }
	record, _ := json.Marshal(map[string]any{"timestamp":time.Now().UnixMilli(), "result":result})
	e.session.setPageStorage("ais_glcr", string(record))
	return nil
}

func loggingFields(raw []byte)([]byte,error){
	var fields []json.RawMessage
	if json.Unmarshal(raw,&fields)!=nil || fields==nil{return nil,fmt.Errorf("expected array")}
	var out []byte
	for i,raw:=range fields{
		v:=bytes.TrimSpace(raw);if isNull(v){continue}
		field:=uint64(i+1)
		switch v[0]{
		case '"':
			var value string;if err:=json.Unmarshal(v,&value);err!=nil{return nil,err}
			out=appendVarint(out,field<<3|2);out=appendVarint(out,uint64(len(value)));out=append(out,value...)
		case 't','f':
			var value bool;if err:=json.Unmarshal(v,&value);err!=nil{return nil,err}
			out=appendVarint(out,field<<3);if value{out=append(out,1)}else{out=append(out,0)}
		default:
			var value int64;if err:=json.Unmarshal(v,&value);err!=nil{return nil,err}
			out=appendVarint(out,field<<3);out=appendVarint(out,uint64(value))
		}
	}
	return out,nil
}

func appendVarint(out []byte,value uint64)[]byte{
	for value>=128{out=append(out,byte(value)|0x80);value>>=7};return append(out,byte(value))
}

// Temporary transport failures may use a recent confirmed entitlement. Local
// validation and malformed-response errors are not treated as network failures
// merely because url.Error wraps them.
func transientBenefitError(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return true
	}
	var connection *net.OpError
	return errors.As(err, &connection)
}

// One lookup, no retries. The account wrapper publishes results and selects a
// page snapshot; a failed lookup never writes an empty value over a valid tier
// before its failure category is known.
func (e *engine) lookupSubscription(ctx context.Context) (result benefitState, transient bool) {
	result.status = "unavailable"
	if err := ctx.Err(); err != nil {
		return result, transientBenefitError(err)
	}
	started := time.Now()
	budgetSource := "initialization"
	if e.initialized {
		budgetSource = "request_refresh"
	}
	budgetMs := int64(-1)
	if deadline, ok := ctx.Deadline(); ok {
		budgetMs = max(time.Until(deadline).Milliseconds(), 0)
	}
	stage, status := "authentication", 0
	var observedErr error
	defer func() {
		cause := observedErr
		if cause == nil && ctx.Err() != nil {
			cause = ctx.Err()
		}
		e.audit.record(ctx, "benefit", map[string]any{
			"pageId": e.pageID,
			"cached": false, "status": result.status, "selectedTier": result.tier,
			"stage": stage, "httpStatus": status, "transient": transient,
			"budgetSource": budgetSource, "budgetMs": budgetMs,
			"elapsedMs": time.Since(started).Milliseconds(),
			"cacheStored": result.status == "resolved",
			"errorClass": diagnosticError(cause),
		})
		if result.status != "resolved" && !errors.Is(cause, context.Canceled) {
			logLimited(ctx, logWarn, "benefit_unavailable", "权益查询未成功，将按缓存策略处理", map[string]any{
				"stage": stage, "status": status, "code": diagnosticError(cause), "transient": transient,
			})
		}
	}()

	h, err := e.rpcHeaders(e.apiKey)
	if err != nil {
		observedErr = err
		return result, false
	}
	stage = "transport"
	response, err := e.do(ctx, http.MethodPost, benefitURL, []byte("{}"), h)
	if err != nil {
		observedErr = err
		return result, transientBenefitError(err)
	}
	status = response.StatusCode
	if status < 200 || status >= 300 {
		stage = "http_status"
		transient = status == http.StatusTooManyRequests || status >= 500 && status <= 599
		if !transient {
			// Invalidate on the headers, before a slow/error body can make a
			// concurrent waiter mistake an explicit denial for a lookup timeout.
			e.shared.invalidateBenefit()
		}
		_, observedErr = readBounded(response, 1<<20)
		return result, transient
	}
	stage = "read"
	body, err := readBounded(response, 1<<20)
	if err != nil {
		observedErr = err
		return result, transientBenefitError(err)
	}
	stage = "json"
	var value map[string]json.RawMessage
	if err = json.Unmarshal(body, &value); err != nil {
		observedErr = err
		return result, false
	}
	if value == nil {
		stage = "root_shape"
		return result, false
	}
	if !isNull(value["error"]) {
		stage = "upstream_error"
		var rpcError struct {
			Code   int    `json:"code"`
			Status string `json:"status"`
		}
		if json.Unmarshal(value["error"], &rpcError) == nil {
			transient = rpcError.Code == http.StatusTooManyRequests || rpcError.Status == "RESOURCE_EXHAUSTED" ||
				rpcError.Code >= 500 && rpcError.Code <= 599
			if rpcError.Code == 401 || rpcError.Code == 403 ||
				rpcError.Status == "UNAUTHENTICATED" || rpcError.Status == "PERMISSION_DENIED" {
				transient = false
				e.shared.invalidateBenefit()
			}
		}
		return result, transient
	}
	var tier string
	if raw := value["benefitTier"]; !isNull(raw) {
		if err = json.Unmarshal(raw, &tier); err != nil {
			stage, observedErr = "tier_type", err
			return result, false
		}
	}
	if err = ctx.Err(); err != nil {
		stage, observedErr = "cancelled", err
		return result, transientBenefitError(err)
	}
	if tier == "TIER1" || tier == "TIER2" {
		result.tier = tier
	}
	result.status = "resolved"
	result.confirmedAt = time.Now()
	result.expires = result.confirmedAt.Add(benefitSuccessTTL)
	stage = "resolved_no_header"
	if result.tier != "" {
		stage = "resolved_header"
	}
	return result, false
}

func (e *engine) challenge(ctx context.Context,refresh []string)(waa.Challenge,error){
	values:=append([]string{waaRequestKey},refresh...)
	body,_:=json.Marshal(values)
	h,err:=e.rpcHeaders(waaAPIKey);if err!=nil{return waa.Challenge{},err}
	response,err:=e.do(ctx,http.MethodPost,waaCreateURL,body,h);if err!=nil{return waa.Challenge{},err}
	raw,err:=readBounded(response,bootstrapLimit);if err!=nil{return waa.Challenge{},err}
	if response.StatusCode!=http.StatusOK{return waa.Challenge{},failure("WAA_HTTP","WAA initialization was rejected.")}
	return waa.ParseChallenge(raw)
}

func (e *engine) loadInterpreter(ctx context.Context,c waa.Challenge)(string,error){
	// Serialize executable-cache validation/commit across pages, cancellably.
	select {
	case e.shared.interpreterGate <- struct{}{}:
	case <-ctx.Done(): return "", ctx.Err()
	}
	defer func() { <-e.shared.interpreterGate }()
	hash,err:=base64.RawURLEncoding.DecodeString(c.InterpreterHash)
	if err!=nil || len(hash)!=32{return "",failure("WAA_FORMAT","Invalid interpreter hash.")}
	valid:=func(text string)bool{return waa.InterpreterHash([]byte(text))==c.InterpreterHash}
	if c.InterpreterJavaScript!=""{
		if !valid(c.InterpreterJavaScript){return "",failure("WAA_HASH","Interpreter integrity check failed.")}
		return c.InterpreterJavaScript,nil
	}
	path:=filepath.Join(e.cacheDirectory,c.InterpreterHash+".js")
	cached := ""
	if e.interpreterHash == c.InterpreterHash && valid(e.interpreter) {
		cached = e.interpreter
	} else if raw, readErr := os.ReadFile(path); readErr == nil && valid(string(raw)) {
		cached = string(raw)
	}
	entry, fresh := e.pageCache.lookup(c.InterpreterURL, time.Now())
	if cached != "" && (c.InterpreterURL == "" || fresh) { return cached, nil }
	h := subresourceHeaders(c.InterpreterURL, "*/*", "script", "")
	// A validator alone cannot supply a missing/corrupt executable body.
	if cached != "" {
		if entry.LastModified != "" { h.Set("If-Modified-Since", entry.LastModified) }
		if entry.ETag != "" { h.Set("If-None-Match", entry.ETag) }
	}
	response,err:=e.do(ctx,http.MethodGet,c.InterpreterURL,nil,h);if err!=nil{return "",err}
	raw,err:=readBounded(response,bootstrapLimit);if err!=nil{return "",err}
	if response.StatusCode == http.StatusNotModified && cached != "" {
		raw = []byte(cached)
	} else if response.StatusCode != http.StatusOK {
		return "", failure("WAA_HTTP", "Interpreter resource did not return an accepted status.")
	}
	if !valid(string(raw)) { return "",failure("WAA_HASH","Interpreter integrity check failed.") }
	control := response.Header.Get("Cache-Control")
	if control == "" && response.StatusCode == http.StatusNotModified { control = entry.CacheControl }
	if strings.Contains(strings.ToLower(control), "no-store") {
		if cacheErr := os.Remove(path); cacheErr != nil && !os.IsNotExist(cacheErr) {
			logLimited(ctx, logWarn, "interpreter_cache_remove_failed", "解释器缓存移除失败，不作为新鲜缓存复用", map[string]any{"code": diagnosticError(cacheErr)})
		}
	} else if response.StatusCode == http.StatusOK {
		if cacheErr := writePrivateBytes(path, raw); cacheErr != nil {
			logLimited(ctx, logWarn, "interpreter_cache_save_failed", "解释器缓存保存失败，继续使用已校验的内存内容", map[string]any{"code": diagnosticError(cacheErr)})
		}
	}
	if err = e.pageCache.store(c.InterpreterURL, response, time.Now()); err != nil { return "", err }
	return string(raw),nil
}

// Caller holds vmMu. A replacement is committed only after initialization,
// resource settlement and any timezone persistence succeed. Failure keeps the
// old VM and effective profile unless native cleanup itself fails, which is
// account-fatal. Hardware and rhythm are never regenerated.
func (e *engine) replaceVMLocked(ctx context.Context) (err error) {
	if e.shared.broken.Load() {
		return failure("RESTART_REQUIRED", "Account runtime cleanup is incomplete.")
	}
	// Includes failed initialization and candidate cleanup, not just the old
	// active VM. Any unconfirmed native release forbids further page creation.
	defer func() {
		if errors.Is(err, waa.ErrCloseTimeout) {
			e.closeErr = errors.Join(e.closeErr, err)
			e.shared.retire()
		}
	}()
	var refresh []string
	if e.vm!=nil{
		snapshot,err:=e.vm.RefreshSnapshot(ctx)
		if err!=nil{if ctx.Err()!=nil{return ctx.Err()};snapshot="E:UCE"}
		refresh=[]string{e.interpreterHash,snapshot}
	}
	challenge,err:=e.challenge(ctx,refresh);if err!=nil{return err}
	source,err:=e.loadInterpreter(ctx,challenge);if err!=nil{return err}
	profile := e.profile
	if e.egressTimezone != "" {
		profile.TimeZone = e.egressTimezone
	}
	profile.Document = map[string]any{
		"cookie": e.session.documentCookie(), "lastModified": e.lastModified(profile.TimeZone),
	}
	var loaded time.Time
	if end, ok := profile.Navigation["loadEventEnd"].(int); ok {
		loaded = profile.NavigationStart.Add(time.Duration(end) * time.Millisecond)
	}
	vm,err:=waa.NewRuntime(ctx,waa.Options{
		Challenge: challenge, Interpreter: source, Profile: profile,
		Pointer: e.pointer, Rhythm: e.rhythm, Start: loaded,
		ResourceContext: e.lifetime, LoadImage: e.loadImage, LoadFrame: e.loadFrame,
	})
	if err != nil { return err }
	committed := false
	defer func() {
		if !committed {
			err = errors.Join(err, vm.Close())
		}
	}()
	if err = vm.Settle(ctx); err != nil { return err }
	if err = ctx.Err(); err != nil { return err }
	timezoneChanged := profile.TimeZone != e.profile.TimeZone
	if timezoneChanged {
		e.shared.settingsMu.Lock()
		next := *e.shared.fingerprint
		next.Config = maps.Clone(next.Config)
		next.Timezone = profile.TimeZone
		next.Config["timezone"] = profile.TimeZone
		path := filepath.Join(filepath.Dir(e.config.StorageState), runtimeProfileFile)
		// Do not let a late page renewal roll the shared profile back after a
		// newer exit observation. Active streams keep their own pinned profile.
		if latest := e.shared.location.Timezone; latest != "" && latest != profile.TimeZone {
			err = failure("PROFILE_CHANGED", "Account timezone changed during page renewal.")
		} else {
			err = writeAccountProfile(path, next)
		}
		if err == nil { e.shared.fingerprint = &next }
		e.shared.settingsMu.Unlock()
		if err != nil { return err }
		e.fingerprint = &next
	}
	if e.vm != nil {
		if err = e.vm.Close(); err != nil { return err }
	}
	if len(refresh) != 0 {
		logEvent(ctx, logInfo, "vm_renewed", "页面签名运行时已更新", map[string]any{"pageId": e.pageID, "timezoneChanged": timezoneChanged})
	}
	committed = true
	e.profile = profile
	e.vm=vm;e.vmExpires=time.Now().Add(vmLifetime);e.refreshErr=nil
	e.interpreterHash=challenge.InterpreterHash;e.interpreter=source
	if e.audit != nil {
		e.audit.record(ctx, "vm_ready", map[string]any{
			"pageId": e.pageID, "interpreterHash": challenge.InterpreterHash, "renewal": len(refresh) != 0,
			"effectiveTimezone": profile.TimeZone, "timezoneChanged": timezoneChanged,
		})
	}
	return nil
}

func (e *engine) scheduleMaintenanceLocked() {
	// Stop cannot retract a callback already waiting for vmMu. A generation
	// check under that same lock makes superseded callbacks harmless.
	e.refreshSequence++
	sequence := e.refreshSequence
	if e.refreshTimer != nil {
		e.refreshTimer.Stop()
		e.refreshTimer = nil
	}
	if e.closed || e.broken || e.shared.broken.Load() || e.lifetime.Err() != nil { return }
	delay := min(egressInterval, max(time.Until(e.egressChecked.Add(egressInterval)), time.Second))
	if e.refreshErr == nil {
		delay = min(delay, max(time.Until(e.vmExpires), time.Second))
	}
	e.refreshTimer = time.AfterFunc(delay, func() {
		if e.vmMu.LockContext(e.lifetime) != nil {
			return
		}
		defer e.vmMu.Unlock()
		if sequence != e.refreshSequence || e.closed || e.broken || e.shared.broken.Load() || e.lifetime.Err() != nil {
			return
		}
		e.refreshTimer = nil
		defer e.scheduleMaintenanceLocked()
		ctx, cancel := context.WithTimeout(e.lifetime, 2*time.Minute)
		defer cancel()
		if e.refreshEgressLocked(ctx) != nil { return }
		if e.refreshErr == nil && !time.Now().Before(e.vmExpires) {
			e.refreshErr = e.replaceVMLocked(ctx)
			if e.refreshErr != nil && ctx.Err() == nil {
				logLimited(ctx, logWarn, "vm_renewal_failed", "后台运行时更新失败，留待下次请求处理", map[string]any{"pageId": e.pageID, "code": diagnosticError(e.refreshErr)})
			}
			// A failed VM renewal is retried by the next request. Geographic
			// checks continue on their normal cadence without a retry loop.
			return
		}
		if e.vm != nil {
			metricsCtx, stop := context.WithTimeout(ctx, time.Second)
			_, _ = e.vm.TakeMetrics(metricsCtx)
			stop()
		}
	})
}

func (e *engine) lastModified(timezone string) string {
	zone, err := time.LoadLocation(timezone)
	if err != nil {
		zone = time.UTC
	}
	return e.pageLoaded.In(zone).Format("01/02/2006 15:04:05")
}

func nextHopProtocol(response *http.Response) string {
	switch response.ProtoMajor {
	case 2:
		return "h2"
	case 3:
		return "h3"
	default:
		return strings.ToLower(response.Proto)
	}
}

// initializePageContext retains the relative logging/WAA/catalogue startup
// schedule. No readiness result is published until required tasks have joined.
func (e *engine) initializePageContext(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	started := time.Now()
	waaDelay, catalogDelay := contextStartupOffsets()
	tasks := []struct {
		delay time.Duration
		run   func(context.Context) error
	}{
		{0, e.loadLoggingContext},
		{catalogDelay, e.loadModelCatalog},
		{catalogDelay, func(ctx context.Context) error { e.subscription(ctx); return nil }},
		{waaDelay, func(ctx context.Context) error {
			e.vmMu.Lock()
			defer e.vmMu.Unlock()
			return e.replaceVMLocked(ctx)
		}},
	}
	var group sync.WaitGroup
	errs := make([]error, len(tasks))
	for i, task := range tasks {
		group.Add(1)
		go func() {
			defer group.Done()
			err := waitUntil(ctx, started.Add(task.delay))
			if err == nil { err = task.run(ctx) }
			errs[i] = err
			if err != nil { cancel() }
		}()
	}
	group.Wait()
	if parent.Err() != nil {
		return parent.Err()
	}
	// Report the initiating failure, not a sibling cancelled by that failure.
	for _, err := range errs {
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	return errors.Join(errs...)
}
