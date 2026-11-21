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
	// 破茧：待关闭的文章（直接打开场景，文档未走代理，等文章页 JS 资源经过代理时打关窗补丁）
	var close_pending sync.Map
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
			// pojian-diag: 记录文章页文档请求是否到达插件
			if strings.HasPrefix(ctx.Req.URL.Path, "/s") {
				fmt.Printf("破茧诊断: 文章页请求到达 method=%s 文章页=%v referer=%s\n",
					ctx.Req.Method, is_article_page_url(ctx.Req.URL), truncate_str(ctx.Req.Header.Get("Referer"), 60))
				if logger != nil {
					logger.Info().
						Str("component", "pojian-diag").
						Str("method", ctx.Req.Method).
						Bool("is_article_page", is_article_page_url(ctx.Req.URL)).
						Str("query", truncate_str(ctx.Req.URL.RawQuery, 200)).
						Str("referer", truncate_str(ctx.Req.Header.Get("Referer"), 120)).
						Msg("article page request seen")
				}
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
				if ctx.Req.Method == "GET" && is_article_page_url(ctx.Req.URL) {
					if settings.CloseWeChatView {
						// 破茧：文章不在微信内置浏览器打开——直接转系统浏览器并返回自动关闭页
						handle_article_page_load(ctx, &article_states, opened_articles_path, logger)
						return
					}
					mark_article_reload(&article_states, normalize_article_url(ctx.Req.URL))
				}
				auto_open_article_from_referer(ctx, &article_states, &close_pending, opened_articles_path, settings.CloseWeChatView, logger)
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
			if ctx.GetMockResponse() != nil {
				return // 我们自己 mock 的响应，无需注入
			}
			response_content_type := strings.ToLower(ctx.GetResponseHeader("Content-Type"))
			hostname := ctx.Req.URL.Hostname()
			// 破茧：直接打开的文章（文档未走代理）——给文章页加载的 JS 资源打自动关窗补丁
			if settings.CloseWeChatView && strings.Contains(response_content_type, "javascript") {
				maybe_patch_article_close_snippet(ctx, &close_pending, logger)
				return
			}
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

// articleRefererGap 破茧：超过该间隔未再见到该文章的 Referer 请求，视为一次新的页面加载
// （微信原生直接打开的文章文档不走代理，无法通过 /s 请求打 reload 标记，用间隔兜底识别）
const articleRefererGap = 2 * time.Minute

// article_open_state 破茧：单篇文章的打开去重状态
type article_open_state struct {
	mu            sync.Mutex
	last_opened   time.Time
	last_seen     time.Time // 最近一次带该文章 Referer 的请求时间
	reload_seen   bool      // 文章页面正在（重新）加载的标记，由首个带 Referer 的请求消费
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
// 触发条件（满足其一）：页面重新加载后的首个请求 / 首次见到该文章 /
// 距上次见到该文章请求超过 articleRefererGap（原生直接打开的兜底）。
// 返回 (应打开, 属于窗口内重复跳过)。
func (s *article_open_state) consume_reload_decision(now time.Time) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	first_sighting := s.last_seen.IsZero()
	stale_seen := !first_sighting && now.Sub(s.last_seen) > articleRefererGap
	s.last_seen = now
	opened_before := !s.last_opened.IsZero()
	eligible := s.reload_seen || !opened_before || first_sighting || stale_seen
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

// decide_page_load 文章页面加载请求（closeWeChatView 模式）触发的判定：
// 页面加载本身就是"点开"信号，无需 reload 标记。
func (s *article_open_state) decide_page_load(now time.Time) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.last_opened.IsZero() && now.Sub(s.last_opened) < articleOpenDedupWindow {
		return false, true
	}
	s.last_opened = now
	return true, false
}

// article_short_link_reg 破茧：公众号短链形式 /s/xxxx（纯字母数字token，区别于 /s/index.html 等页面）
var article_short_link_reg = regexp.MustCompile(`^/s/[A-Za-z0-9_-]{10,}$`)

// is_article_page_url 判断是否为公众号文章/贴图页URL：
// /s 带 __biz 参数（文章、贴图 image_detail 页），或 /s/xxxx 短链形式
func is_article_page_url(u *url.URL) bool {
	if u.Path == "/s" {
		return u.Query().Get("__biz") != ""
	}
	return article_short_link_reg.MatchString(u.Path)
}

// handle_article_page_load 破茧：文章页加载请求直接在系统浏览器打开，
// 并返回一个自动关闭的本地页面，让微信内置浏览器不再展示文章。
func handle_article_page_load(ctx *echo.Context, states *sync.Map, persist_path string, logger *zerolog.Logger) {
	req_url := ctx.Req.URL
	state := get_article_state(states, normalize_article_url(req_url))
	should_open, duplicate := state.decide_page_load(time.Now())
	clean_url := build_clean_article_url(req_url)
	if should_open {
		fmt.Printf("\n破茧 - 在系统浏览器中打开公众号文章\n%s\n\n", clean_url)
		if logger != nil {
			logger.Info().Str("article", clean_url).Msg("pojian open article in system browser")
		}
		if persist_path != "" {
			save_article_states(states, persist_path)
		}
		_ = system.OpenURL(clean_url)
	} else {
		fmt.Printf("\n破茧 - 检测到重复打开，已跳过（%d天内已打开过）\n%s\n\n", int(articleOpenDedupWindow.Hours()/24), clean_url)
		if logger != nil {
			logger.Info().Str("article", clean_url).Msg("pojian skip duplicate article open")
		}
	}
	ctx.Mock(200, map[string]string{
		"Content-Type":  "text/html; charset=utf-8",
		"Cache-Control": "no-store",
	}, build_close_page_html(should_open, duplicate))
	if logger != nil {
		logger.Info().
			Str("component", "pojian-diag").
			Bool("opened", should_open).
			Bool("duplicate", duplicate).
			Msg("article page mocked, close page returned")
	}
}

// truncate_str 截断字符串用于日志
func truncate_str(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// build_close_page_html 破茧：返回给微信内置浏览器的自动关闭页
func build_close_page_html(opened, duplicate bool) string {
	title := "已在系统浏览器打开"
	if !opened && duplicate {
		title = "7天内已打开过，未重复打开"
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<style>
body { margin:0; font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif; background:#f7f7f7; }
.card { position:fixed; left:50%%; top:40%%; transform:translate(-50%%,-50%%); text-align:center; width:80%%; }
.icon { font-size:44px; color:#07c160; }
.title { font-size:17px; color:#333; margin:12px 0 6px; }
.desc { font-size:13px; color:#999; margin-bottom:24px; word-break:break-all; }
button { padding:10px 32px; border:none; border-radius:6px; background:#07c160; color:#fff; font-size:15px; }
</style>
</head>
<body>
<div class="card">
<div class="icon">&#10003;</div>
<div class="title">%s</div>
<button onclick="close_now()">关闭此页</button>
</div>
<script>
function report(data) {
  try {
    fetch(((window.__d_config && window.__d_config.apiOrigin) || "http://127.0.0.1:2022") + "/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(Object.assign({ level: "info", msg: "pojian-close-page-diag", href: String(location.href).slice(0, 120) }, data))
    }).catch(function () {});
  } catch (e) {}
}
function close_now(src) {
  report({ phase: "close-attempt", via: src, bridge: typeof window.WeixinJSBridge !== "undefined", opener: !!window.opener });
  try { if (window.WeixinJSBridge) { WeixinJSBridge.call("closeWindow"); } } catch (e) {}
  try { if (window.WeixinJSBridge) { WeixinJSBridge.invoke("closeWindow", {}, function () {}); } } catch (e) {}
  try { window.close(); } catch (e) {}
}
function go_back(src) {
  report({ phase: "history-back", via: src });
  try { history.back(); } catch (e) {}
}
report({ phase: "load", bridge: typeof window.WeixinJSBridge !== "undefined", opener: !!window.opener, readyState: document.readyState, historyLen: history.length });
document.addEventListener("WeixinJSBridgeReady", function () { report({ phase: "bridge-ready" }); }, false);
close_now("immediate");
setTimeout(function () { go_back("t600"); }, 600);
setTimeout(function () { close_now("t2000"); }, 2000);
setTimeout(function () { go_back("t2600"); }, 2600);
</script>
</body>
</html>`, title)
}
// auto_open_article_from_referer 破茧：从代理请求的 Referer 识别文章并自动在系统浏览器打开
// （兜底路径：当文章 HTML 请求未走代理时仍可通过 Referer 检测）
func auto_open_article_from_referer(ctx *echo.Context, states *sync.Map, close_pending *sync.Map, persist_path string, close_wechat_view bool, logger *zerolog.Logger) {
	referer := ctx.Req.Header.Get("Referer")
	if referer == "" {
		return
	}
	ref_url, err := url.Parse(referer)
	if err != nil {
		return
	}
	if ref_url.Host != "mp.weixin.qq.com" || !is_article_page_url(ref_url) {
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
	// 直接打开场景：文档未走代理无法 mock，等文章页 JS 经过代理时打关窗补丁（覆盖缓存命不中的场合）
	if close_pending != nil {
		pending_reason := "opened"
		if duplicate {
			pending_reason = "duplicate"
		}
		close_pending.Store(article_key, pending_reason)
	}
	if duplicate {
		fmt.Printf("\n破茧 - 检测到重复打开，已跳过（%d天内已打开过）\n%s\n\n", int(articleOpenDedupWindow.Hours()/24), clean_url)
		if logger != nil {
			logger.Info().Str("component", "pojian-diag").Str("via", "referer-fallback").Str("article", clean_url).Msg("pojian skip duplicate article open")
		}
		// 文档未经代理、网页手段关不掉，定向关闭前台的微信内置浏览器窗口（此刻它仍是前台）
		if close_wechat_view {
			close_foreground_wechat_view(logger)
		}
		return
	}
	fmt.Printf("\n破茧 - 在系统浏览器中打开公众号文章\n%s\n\n", clean_url)
	if logger != nil {
		logger.Info().Str("component", "pojian-diag").Str("via", "referer-fallback").Str("article", clean_url).Msg("pojian open article in system browser")
	}
	if persist_path != "" {
		save_article_states(states, persist_path)
	}
	// 先关微信窗口（此时前台还是微信文章页），再开系统浏览器（避免焦点被抢后关错窗口）
	if close_wechat_view {
		close_foreground_wechat_view(logger)
	}
	_ = system.OpenURL(clean_url)
}

// close_foreground_wechat_view 破茧：关闭当前前台的微信内置浏览器窗口（仅当属于 WeChatAppEx 进程）
func close_foreground_wechat_view(logger *zerolog.Logger) {
	if !system.CloseForegroundWeChatView() {
		if logger != nil {
			logger.Info().Str("component", "pojian-diag").Msg("os close skipped: foreground window is not WeChatAppEx")
		}
		return
	}
	fmt.Println("破茧 - 已请求关闭微信内文章窗口")
	if logger != nil {
		logger.Info().Str("component", "pojian-diag").Msg("pojian closed foreground wechat view window")
	}
}

// maybe_patch_article_close_snippet 破茧：直接打开的文章页，其 JS 资源经过代理时
// 追加自动关窗脚本（一次性消费 close_pending 标记），实现文章不在微信中展示。
func maybe_patch_article_close_snippet(ctx *echo.Context, close_pending *sync.Map, logger *zerolog.Logger) {
	referer := ctx.Req.Header.Get("Referer")
	if referer == "" {
		return
	}
	ref_url, err := url.Parse(referer)
	if err != nil {
		return
	}
	is_article := ref_url.Host == "mp.weixin.qq.com" && is_article_page_url(ref_url)
	if !is_article {
		return
	}
	article_key := normalize_article_url(ref_url)
	if logger != nil {
		logger.Info().
			Str("component", "pojian-diag").
			Str("host", ctx.Req.URL.Hostname()).
			Str("path", ctx.Req.URL.Path).
			Str("article", truncate_str(build_clean_article_url(ref_url), 120)).
			Msg("article page subresource js seen")
	}
	reason, ok := close_pending.Load(article_key)
	if !ok {
		return
	}
	close_pending.Delete(article_key)
	response_body, err := ctx.GetResponseBody()
	if err != nil {
		return
	}
	// 剥缓存头，确保微信侧不缓存打了补丁的 JS
	ctx.SetResponseHeader("Cache-Control", "no-store")
	ctx.DelResponseHeader("ETag")
	ctx.DelResponseHeader("Last-Modified")
	snippet := article_close_snippet_opened
	if fmt.Sprint(reason) == "duplicate" {
		snippet = article_close_snippet_duplicate
	}
	ctx.SetResponseBody(response_body + snippet)
	if logger != nil {
		logger.Info().
			Str("component", "pojian-diag").
			Str("reason", fmt.Sprint(reason)).
			Msg("article page subresource js patched with close snippet")
	}
}

// article_close_snippet_opened 破茧：追加到文章页 JS 的自动关窗脚本（首次打开场景）
const article_close_snippet_opened = `
;(function () {
  if (window.__pojian_close_snippet) return;
  window.__pojian_close_snippet = 1;
  var box = document.createElement("div");
  box.style.cssText = "position:fixed;left:50%;top:20%;transform:translateX(-50%);z-index:2147483647;background:#fff;color:#333;padding:14px 20px;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,.2);font-size:14px;text-align:center;font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;";
  box.innerHTML = '<div style="color:#07c160;font-size:20px;margin-bottom:4px;">&#10003;</div><div>已在系统浏览器打开</div><button id="pojian-close-btn" style="margin-top:10px;padding:8px 24px;border:none;border-radius:6px;background:#07c160;color:#fff;font-size:14px;">关闭此页</button>';
  function close_now() {
    try { if (window.WeixinJSBridge) { WeixinJSBridge.call("closeWindow"); } } catch (e) {}
    try { if (window.WeixinJSBridge) { WeixinJSBridge.invoke("closeWindow", {}, function () {}); } } catch (e) {}
    try { window.close(); } catch (e) {}
  }
  box.querySelector("#pojian-close-btn").onclick = close_now;
  function mount() {
    if (document.body) { document.body.appendChild(box); } else { setTimeout(mount, 100); }
  }
  mount();
  close_now();
  setTimeout(function () { try { history.back(); } catch (e) {} }, 600);
  setTimeout(close_now, 2000);
})();
`

// article_close_snippet_duplicate 破茧：追加到文章页 JS 的自动关窗脚本（重复打开场景）
const article_close_snippet_duplicate = `
;(function () {
  if (window.__pojian_close_snippet) return;
  window.__pojian_close_snippet = 1;
  var box = document.createElement("div");
  box.style.cssText = "position:fixed;left:50%;top:20%;transform:translateX(-50%);z-index:2147483647;background:#fff;color:#333;padding:14px 20px;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,.2);font-size:14px;text-align:center;font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;";
  box.innerHTML = '<div style="color:#07c160;font-size:20px;margin-bottom:4px;">&#10003;</div><div>7天内已打开过，未重复打开</div><button id="pojian-close-btn" style="margin-top:10px;padding:8px 24px;border:none;border-radius:6px;background:#07c160;color:#fff;font-size:14px;">关闭此页</button>';
  function close_now() {
    try { if (window.WeixinJSBridge) { WeixinJSBridge.call("closeWindow"); } } catch (e) {}
    try { if (window.WeixinJSBridge) { WeixinJSBridge.invoke("closeWindow", {}, function () {}); } } catch (e) {}
    try { window.close(); } catch (e) {}
  }
  box.querySelector("#pojian-close-btn").onclick = close_now;
  function mount() {
    if (document.body) { document.body.appendChild(box); } else { setTimeout(mount, 100); }
  }
  mount();
  close_now();
  setTimeout(function () { try { history.back(); } catch (e) {} }, 600);
  setTimeout(close_now, 2000);
})();
`

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
	if biz != "" && mid != "" && sn != "" {
		return fmt.Sprintf("biz=%s&mid=%s&idx=%s&sn=%s", biz, mid, idx, sn)
	}
	// 短链 /s/xxxx、贴图 image_detail 等形式，用整个path+query作为key
	return u.Path + "?" + u.RawQuery
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
