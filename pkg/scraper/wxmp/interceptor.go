package wxmp

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ltaoo/echo"
	"github.com/rs/zerolog"

	"wx_channel/frontend"
	"wx_channel/pkg/system"
)

var csp_nonce_reg = regexp.MustCompile(`'nonce-([^']+)'`)

// InterceptorConfig contains the application values needed by the
// official-account injection rule.
type InterceptorConfig struct {
	Version  string
	Mode     string
	Settings OfficialAccountConfig
}

// NewInterceptorPlugins builds the Echo injection rules owned by the
// official-account scraper.
func NewInterceptorPlugins(cfg InterceptorConfig, logger *zerolog.Logger) []*echo.Plugin {
	if logger == nil {
		nop_logger := zerolog.Nop()
		logger = &nop_logger
	} else {
		component_logger := logger.With().Str("component", "wxmp_scraper").Logger()
		logger = &component_logger
	}
	settings := &cfg.Settings
	asset_base_url := "/__assets"
	url_build := frontend.NewURLBuild(asset_base_url, nil)
	asset_version := cfg.Version
	if asset_version == "" {
		asset_version = "static"
	}
	version_query := url.Values{"v": []string{asset_version}}
	inline_assets := cfg.Mode == "release" || cfg.Mode == "prod"
	inline_asset_options := frontend.StaticAssetMockOptions{
		PlatformPrefix: InjectAssetsPath + "/",
		PlatformFS:     InjectAssets(),
	}
	// 破茧：文章打开去重状态（key 为规范化文章URL，一周内重复打开直接跳过并记日志）
	var article_states sync.Map
	// 去重状态持久化到 workdir，跨重启保持一周窗口
	opened_articles_path := ""
	if settings.WorkDir != "" {
		opened_articles_path = filepath.Join(settings.WorkDir, "pojian_opened_articles.json")
		load_article_states(&article_states, opened_articles_path)
	}
	plugin := &echo.Plugin{
		Match: "qq.com",
		OnRequest: func(ctx *echo.Context) {
			if ctx.Req.URL.Hostname() != "mp.weixin.qq.com" {
				return
			}
			// 破茧：处理"在浏览器中打开"按钮的 API 请求
			if ctx.Req.URL.Path == "/__wx_mp_api/open_in_browser" {
				handle_open_in_browser(ctx)
				return
			}
			// 破茧：自动打开模式，从后续请求的 Referer 中检测公众号文章URL
			// 微信内置浏览器加载文章HTML不走系统代理，但后续的API请求（如 /mp/jsmonitor）会走代理
			// 我们通过这些请求的 Referer 头来识别正在浏览的文章
			if settings.OpenInSystemBrowser {
				// 文章页面（重新）加载时做标记，用于区分"重新点开"与"页面内持续请求"
				if ctx.Req.Method == "GET" && ctx.Req.URL.Path == "/s" {
					if key := normalize_article_url(ctx.Req.URL); key != "" {
						mark_article_reload(&article_states, key)
					}
				}
				auto_open_article_from_referer(ctx, &article_states, opened_articles_path, logger)
			}
			frontend.MockStaticAsset(ctx.Req.URL.Path, ctx.Req.Header, func(status int, headers map[string]string, body string) {
				ctx.Mock(status, headers, body)
			}, frontend.StaticAssetMockOptions{
				PlatformPrefix: InjectAssetsPath + "/",
				PlatformFS:     InjectAssets(),
				UserScriptPath: settings.GlobalScriptPath,
				Logger:         logger,
			})
		},
		OnResponse: func(ctx *echo.Context) {
			response_content_type := strings.ToLower(ctx.GetResponseHeader("Content-Type"))
			hostname := ctx.Req.URL.Hostname()
			if hostname != "mp.weixin.qq.com" || !strings.Contains(response_content_type, "text/html") {
				return
			}
			response_body, err := ctx.GetResponseBody()
			if err != nil {
				return
			}
			html_content := response_body
			csp := ctx.GetResponseHeader("Content-Security-Policy") + " " + ctx.GetResponseHeader("Content-Security-Policy-Report-Only")
			mp_websocket_url := build_mp_websocket_url(settings)
			rewrite_response_csp(ctx, asset_base_url, mp_websocket_url)
			variables := BuildOfficialAccountVariables(html_content)
			script_attr := ""
			style_attr := ""
			if match := csp_nonce_reg.FindStringSubmatch(csp); len(match) > 1 {
				script_attr = fmt.Sprintf(` nonce="%s" reportloaderror`, match[1])
				style_attr = fmt.Sprintf(` nonce="%s"`, match[1])
			}
			var injected strings.Builder
			append_scripts := func(srcs ...string) {
				if err := frontend.AppendRegisteredScripts(&injected, script_attr, inline_assets, inline_asset_options, srcs...); err != nil {
					logger.Warn().Err(err).Msg("failed to inline registered scripts; using external assets")
				}
			}
			append_stylesheets := func(hrefs ...string) {
				if err := frontend.AppendRegisteredStylesheets(&injected, style_attr, inline_assets, inline_asset_options, hrefs...); err != nil {
					logger.Warn().Err(err).Msg("failed to inline registered stylesheets; using external assets")
				}
			}
			if settings.DebugShowError {
				append_scripts(url_build("/inject/error.js", version_query))
			}
			append_scripts(url_build("/public/timeless/0.33.0/timeless.umd.min.js", version_query))
			append_stylesheets(url_build("/public/timeless/0.33.0/timeless.weui.css", version_query))
			append_scripts(url_build("/public/timeless/0.33.0/timeless.weui.umd.min.js", version_query))
			append_scripts(url_build("/public/timeless/0.33.0/timeless.dom.umd.min.js", version_query))
			append_scripts(url_build("/public/timeless/0.33.0/timeless.web.umd.min.js", version_query))
			append_stylesheets(url_build("/inject/components.css"))
			frontend_config := make(map[string]any, len(variables)+2)
			cfg_byte, _ := json.Marshal(settings)
			_ = json.Unmarshal(cfg_byte, &frontend_config)
			for key, value := range variables {
				frontend_config[key] = value
			}
			api_host := settings.Addr
			if api_host == "" && settings.Hostname != "" {
				api_host = net.JoinHostPort(strings.Trim(settings.Hostname, "[]"), strconv.Itoa(settings.Port))
			}
			api_protocol := strings.TrimSuffix(strings.TrimSpace(settings.Protocol), ":")
			if api_protocol == "" {
				api_protocol = "http"
			}
			frontend_config["version"] = cfg.Version
			frontend_config["assets_base_url"] = asset_base_url
			frontend_config["apiHost"] = api_host
			frontend_config["apiOrigin"] = api_protocol + "://" + api_host
			frontend_config["apiProtocol"] = settings.Protocol
			frontend_config["mpWSURL"] = mp_websocket_url
			frontend_config_byte, _ := json.Marshal(frontend_config)
			frontend.AppendInlineScript(&injected, script_attr, fmt.Sprintf(`window.__d_config = %s;`, frontend_config_byte))
			append_scripts(
				url_build("/inject/eventbus.js", version_query),
				url_build("/public/dl.utils.js", version_query),
				url_build("/public/dl.sdk.js", version_query),
				url_build("/inject/env.js", version_query),
				url_build("/inject/utils.js", version_query),
				url_build("/inject/components.js", version_query),
				url_build("/public/virtual-list-view.js", version_query),
				url_build("/inject/download/model.js", version_query),
				url_build("/inject/download/view.js", version_query),
				asset_url(asset_base_url, "/inject/mp.utils.js", version_query),
				// asset_url(asset_base_url, "/inject/mp.ws.js", version_query),
				asset_url(asset_base_url, "/inject/mp.components.js", version_query),
				asset_url(asset_base_url, "/inject/mp.main.js", version_query),
			)
			if settings.OpenInSystemBrowser || settings.Enabled {
				frontend.AppendInlineScript(&injected, script_attr, open_in_browser_button_script)
			}
			if settings.GlobalScriptURL != "" {
				frontend.AppendScripts(&injected, script_attr, settings.GlobalScriptURL)
			}
			if settings.InjectContentScript != "" {
				frontend.AppendInlineScript(&injected, script_attr, settings.InjectContentScript)
			}
			html_content = strings.Replace(html_content, "</body>", injected.String()+"</body>", 1)
			ctx.SetResponseBody(html_content)
		},
	}
	return []*echo.Plugin{plugin}
}

func rewrite_response_csp(ctx *echo.Context, asset_base_url string, websocket_url string) {
	for _, header := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		policy := ctx.GetResponseHeader(header)
		rewritten := frontend.RewriteCSPForLocalAssets(policy, asset_base_url)
		rewritten = frontend.RewriteCSPForWebSocket(rewritten, websocket_url)
		if rewritten != "" && rewritten != policy {
			ctx.SetResponseHeader(header, rewritten)
		}
	}
}

func build_mp_websocket_url(cfg *OfficialAccountConfig) string {
	if cfg == nil {
		return ""
	}
	protocol := cfg.Protocol
	hostname := cfg.Hostname
	port := cfg.Port
	if cfg.RemoteServerEnabled && strings.TrimSpace(cfg.RemoteServerHostname) != "" {
		protocol = cfg.RemoteServerProtocol
		hostname = cfg.RemoteServerHostname
		port = cfg.RemoteServerPort
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "0.0.0.0" || hostname == "::" || hostname == "[::]" {
		hostname = "127.0.0.1"
	}
	if hostname == "" {
		return ""
	}
	websocket_protocol := "ws"
	switch strings.ToLower(strings.TrimSuffix(strings.TrimSpace(protocol), ":")) {
	case "https", "wss":
		websocket_protocol = "wss"
	}
	host := hostname
	if port > 0 {
		host = net.JoinHostPort(strings.Trim(hostname, "[]"), strconv.Itoa(port))
	}
	return (&url.URL{
		Scheme: websocket_protocol,
		Host:   host,
		Path:   WebsocketPath,
	}).String()
}

// handle_open_in_browser 破茧：响应页面"浏览器打开"按钮的 API 请求
func handle_open_in_browser(ctx *echo.Context) {
	json_headers := map[string]string{"Content-Type": "application/json"}
	var data struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(ctx.Req.Body).Decode(&data); err != nil {
		ctx.Mock(400, json_headers, `{"code":1,"msg":"invalid request body"}`)
		return
	}
	if !strings.HasPrefix(data.URL, "https://mp.weixin.qq.com") {
		ctx.Mock(400, json_headers, `{"code":1,"msg":"invalid url"}`)
		return
	}
	if err := system.OpenURL(data.URL); err != nil {
		ctx.Mock(500, json_headers, fmt.Sprintf(`{"code":1,"msg":"%s"}`, err.Error()))
		return
	}
	ctx.Mock(200, json_headers, `{"code":0,"msg":"ok"}`)
}

// articleOpenDedupWindow 破茧：文章去重窗口，窗口内重复打开直接跳过
const articleOpenDedupWindow = 7 * 24 * time.Hour

// article_open_state 破茧：单篇文章的打开去重状态
type article_open_state struct {
	mu          sync.Mutex
	last_opened time.Time
	reload_seen bool // 文章页面正在（重新）加载的标记，由首个带 Referer 的请求消费
}

// get_article_state 取或创建文章去重状态
func get_article_state(states *sync.Map, key string) *article_open_state {
	if v, ok := states.Load(key); ok {
		return v.(*article_open_state)
	}
	v, _ := states.LoadOrStore(key, &article_open_state{})
	return v.(*article_open_state)
}

// mark_article_reload 标记文章页面正在（重新）加载
func mark_article_reload(states *sync.Map, key string) {
	state := get_article_state(states, key)
	state.mu.Lock()
	state.reload_seen = true
	state.mu.Unlock()
}

// consume_reload_decision 判定本次触发是否应打开系统浏览器。
// 仅在"页面重新加载后的首个请求"或"首次见到该文章"时判定；
// 返回 (应打开, 属于窗口内重复跳过)。
func (s *article_open_state) consume_reload_decision(now time.Time) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	opened_before := !s.last_opened.IsZero()
	eligible := s.reload_seen || !opened_before
	s.reload_seen = false
	if !eligible {
		return false, false
	}
	if opened_before && now.Sub(s.last_opened) < articleOpenDedupWindow {
		return false, true
	}
	s.last_opened = now
	return true, false
}

// auto_open_article_from_referer 破茧：从代理请求的 Referer 识别文章并自动在系统浏览器打开
func auto_open_article_from_referer(ctx *echo.Context, states *sync.Map, persist_path string, logger *zerolog.Logger) {
	referer := ctx.Req.Header.Get("Referer")
	if referer == "" {
		return
	}
	ref_url, err := url.Parse(referer)
	if err != nil {
		return
	}
	if ref_url.Host != "mp.weixin.qq.com" || ref_url.Path != "/s" {
		return
	}
	// 用规范化的URL做去重key（去掉无关参数，保留核心标识）
	article_key := normalize_article_url(ref_url)
	if article_key == "" {
		return
	}
	state := get_article_state(states, article_key)
	should_open, duplicate := state.consume_reload_decision(time.Now())
	if !should_open && !duplicate {
		return // 同一次页面浏览期间的后续请求，静默跳过
	}
	clean_url := build_clean_article_url(ref_url)
	if duplicate {
		fmt.Printf("\n破茧 - 检测到重复打开，已跳过（%d天内已打开过）\n%s\n\n", int(articleOpenDedupWindow.Hours()/24), clean_url)
		if logger != nil {
			logger.Info().Str("article", clean_url).Msg("pojian skip duplicate article open")
		}
		return
	}
	fmt.Printf("\n破茧 - 在系统浏览器中打开公众号文章\n%s\n\n", clean_url)
	if logger != nil {
		logger.Info().Str("article", clean_url).Msg("pojian open article in system browser")
	}
	if persist_path != "" {
		save_article_states(states, persist_path)
	}
	// 不关闭任何页面，只在系统浏览器中打开
	_ = system.OpenURL(clean_url)
}

// load_article_states 破茧：启动时从磁盘恢复去重状态（只恢复窗口内的条目）
func load_article_states(states *sync.Map, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var persisted map[string]string
	if err := json.Unmarshal(data, &persisted); err != nil {
		return
	}
	now := time.Now()
	for key, ts := range persisted {
		opened_at, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			continue
		}
		if now.Sub(opened_at) >= articleOpenDedupWindow {
			continue
		}
		states.Store(key, &article_open_state{last_opened: opened_at})
	}
}

// save_article_states 破茧：打开文章后把去重状态落盘（窗口外条目顺手清理）
func save_article_states(states *sync.Map, path string) {
	snapshot := make(map[string]string)
	now := time.Now()
	states.Range(func(k, v any) bool {
		state, ok := v.(*article_open_state)
		if !ok {
			return true
		}
		state.mu.Lock()
		opened_at := state.last_opened
		state.mu.Unlock()
		if opened_at.IsZero() || now.Sub(opened_at) >= articleOpenDedupWindow {
			return true
		}
		snapshot[k.(string)] = opened_at.Format(time.RFC3339)
		return true
	})
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

// normalize_article_url 从公众号文章URL中提取核心标识参数作为去重key
func normalize_article_url(u *url.URL) string {
	q := u.Query()
	biz := q.Get("__biz")
	mid := q.Get("mid")
	idx := q.Get("idx")
	sn := q.Get("sn")
	if biz == "" && mid == "" && sn == "" {
		// 短链接格式 /s/xxxx，用整个path+query作为key
		return u.Path + "?" + u.RawQuery
	}
	return fmt.Sprintf("biz=%s&mid=%s&idx=%s&sn=%s", biz, mid, idx, sn)
}

// build_clean_article_url 构建干净的文章URL，只保留核心参数，去掉追踪/会话参数
func build_clean_article_url(u *url.URL) string {
	q := u.Query()
	biz := q.Get("__biz")
	mid := q.Get("mid")
	idx := q.Get("idx")
	sn := q.Get("sn")
	if biz == "" || mid == "" || sn == "" {
		return u.String()
	}
	clean := url.Values{}
	clean.Set("__biz", biz)
	clean.Set("mid", mid)
	clean.Set("idx", idx)
	clean.Set("sn", sn)
	return "https://mp.weixin.qq.com/s?" + clean.Encode()
}

// open_in_browser_button_script 破茧：在文章页交互栏插入"浏览器打开"按钮
const open_in_browser_button_script = `(function () {
  if (window.__pojian_open_in_browser_mounted) return;
  window.__pojian_open_in_browser_mounted = true;
  var icon = '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>';
  function toast(msg) {
    var $t = document.createElement("div");
    $t.textContent = msg;
    $t.style.cssText = "position:fixed;left:50%;top:20%;transform:translateX(-50%);background:rgba(0,0,0,0.75);color:#fff;padding:8px 16px;border-radius:6px;font-size:14px;z-index:99999;";
    document.body.appendChild($t);
    setTimeout(function () { $t.remove(); }, 2500);
  }
  function render_button(page_type) {
    var $btn = document.createElement("div");
    $btn.style.cssText = "display:flex;align-items:center;margin-left:16px;font-size:14px;cursor:pointer;";
    var text = '<span class="sns_opr_gap" style="margin-left:1px">浏览器打开</span>';
    if (page_type === 2) {
      $btn.style.cssText = "display:flex;align-items:center;flex-direction:column;margin-left:4px;font-size:14px;cursor:pointer;";
      text = '<span style="width:56px;text-align:center;font-size:12px;">浏览器打开</span>';
    }
    $btn.innerHTML = '<span style="position:relative;top:-6px;width:24px;height:24px;font-size:24px;display:inline-flex;align-items:center;">' + icon + "</span>" + text;
    $btn.onclick = function () {
      fetch("/__wx_mp_api/open_in_browser", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: window.location.href }),
      })
        .then(function (res) { return res.json(); })
        .then(function (data) {
          if (data && data.code === 0) {
            toast("已在系统浏览器中打开");
          } else {
            toast("打开失败：" + ((data && data.msg) || "未知错误"));
          }
        })
        .catch(function (err) { toast("打开失败：" + err.message); });
    };
    return $btn;
  }
  function insert_button() {
    var $wraps = document.querySelectorAll(".interaction_bar");
    if (!$wraps.length) return false;
    var page_type = (window.cgiDataNew && window.cgiDataNew.page_type) || 1;
    var $container = page_type === 2 ? $wraps[0] : $wraps[$wraps.length - 1];
    if (!$container || !$container.lastElementChild) return false;
    $container.insertBefore(render_button(page_type), $container.lastElementChild);
    return true;
  }
  function start() {
    var attempts = 0;
    var timer = setInterval(function () {
      attempts += 1;
      if (insert_button() || attempts >= 15) clearInterval(timer);
    }, 800);
  }
  if (document.readyState === "complete") start();
  else window.addEventListener("load", start);
})();`
