package officialaccount

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"wx_channel/internal/interceptor"
	"wx_channel/internal/interceptor/proxy"
	"wx_channel/pkg/system"
)

var cspNonceReg = regexp.MustCompile(`'nonce-([^']+)'`)

func CreateOfficialAccountInterceptorPlugin(cfg *OfficialAccountConfig, files *interceptor.ChannelInjectedFiles) *proxy.Plugin {
	// 已打开的文章URL去重，防止同一篇文章被反复打开
	var openedURLs sync.Map

	return &proxy.Plugin{
		Match: "qq.com",
		OnRequest: func(ctx proxy.Context) {
			hostname := ctx.Req().URL.Hostname()
			pathname := ctx.Req().URL.Path

			// 处理"在浏览器中打开"按钮的 API 请求
			if hostname == "mp.weixin.qq.com" && pathname == "/__wx_mp_api/open_in_browser" {
				var data struct {
					URL string `json:"url"`
				}
				if err := json.NewDecoder(ctx.Req().Body).Decode(&data); err != nil {
					ctx.Mock(400, map[string]string{
						"Content-Type": "application/json",
					}, `{"code":1,"msg":"invalid request body"}`)
					return
				}
				if !strings.HasPrefix(data.URL, "https://mp.weixin.qq.com") {
					ctx.Mock(400, map[string]string{
						"Content-Type": "application/json",
					}, `{"code":1,"msg":"invalid url"}`)
					return
				}
				if err := system.OpenURL(data.URL); err != nil {
					ctx.Mock(500, map[string]string{
						"Content-Type": "application/json",
					}, fmt.Sprintf(`{"code":1,"msg":"%s"}`, err.Error()))
					return
				}
				ctx.Mock(200, map[string]string{
					"Content-Type": "application/json",
				}, `{"code":0,"msg":"ok"}`)
				return
			}

			// 自动打开模式：从后续请求的 Referer 中检测公众号文章URL
			// 微信内置浏览器加载文章HTML不走系统代理，但后续的API请求（如 /mp/jsmonitor）会走代理
			// 我们通过这些请求的 Referer 头来识别正在浏览的文章
			if cfg.OpenInSystemBrowser && hostname == "mp.weixin.qq.com" {
				referer := ctx.Req().Header.Get("Referer")
				if referer == "" {
					return
				}
				refURL, err := url.Parse(referer)
				if err != nil {
					return
				}
				if refURL.Host != "mp.weixin.qq.com" || refURL.Path != "/s" {
					return
				}
				// 用规范化的URL做去重key（去掉无关参数，保留核心标识）
				articleKey := normalizeArticleURL(refURL)
				if articleKey == "" {
					return
				}
				if _, loaded := openedURLs.LoadOrStore(articleKey, true); loaded {
					return // 已经打开过
				}
				cleanURL := buildCleanArticleURL(refURL)
				fmt.Printf("\n破茧 - 在系统浏览器中打开公众号文章\n%s\n\n", cleanURL)
				// 先关闭微信内置浏览器页面，再打开系统浏览器
				go system.SendCloseWindow()
				system.OpenURL(cleanURL)
			}
		},
		OnResponse: func(ctx proxy.Context) {
			resp_content_type := strings.ToLower(ctx.GetResponseHeader("Content-Type"))
			hostname := ctx.Req().URL.Hostname()
			if hostname == "mp.weixin.qq.com" && strings.Contains(resp_content_type, "text/html") {
				// 以下 JS 注入功能需要 mp.disabled 为 false
				if cfg.Disabled {
					return
				}
				resp_body, err := ctx.GetResponseBody()
				if err != nil {
					return
				}
				html := string(resp_body)
				csp := ctx.GetResponseHeader("Content-Security-Policy-Report-Only")
				script_attr := ""
				if match := cspNonceReg.FindStringSubmatch(csp); len(match) > 1 {
					script_attr = fmt.Sprintf(` nonce="%s" reportloaderror`, match[1])
				}
				inserted_scripts := ""
				cfg_byte, _ := json.Marshal(cfg)
				script_config := fmt.Sprintf(`<script%s>var __wx_channels_config__ = %s</script>`, script_attr, string(cfg_byte))
				inserted_scripts += script_config
				inserted_scripts += fmt.Sprintf(`<script%s>%s</script>`, script_attr, files.JSMitt)
				inserted_scripts += fmt.Sprintf(`<script%s>%s</script>`, script_attr, files.JSEventBus)
				inserted_scripts += fmt.Sprintf(`<script%s>%s</script>`, script_attr, files.JSUtils)
				inserted_scripts += fmt.Sprintf(`<style>%s</style>`, files.CSSWeui)
				inserted_scripts += fmt.Sprintf(`<script%s>%s</script>`, script_attr, files.JSWeui)
				inserted_scripts += fmt.Sprintf(`<script%s>%s</script>`, script_attr, files.JSFloatingUICore)
				inserted_scripts += fmt.Sprintf(`<script%s>%s</script>`, script_attr, files.JSFloatingUIDOM)
				inserted_scripts += fmt.Sprintf(`<script%s>%s</script>`, script_attr, files.JSWui)
				inserted_scripts += fmt.Sprintf(`<script%s>%s</script>`, script_attr, files.JSComponents)
				inserted_scripts += fmt.Sprintf(`<script%s>%s</script>`, script_attr, files.JSWechatOfficialAccount)
				if cfg.DebugShowError {
					script_error := fmt.Sprintf(`<script%s>%s</script>`, script_attr, files.JSError)
					inserted_scripts += script_error
				}
				if cfg.PagespyEnabled {
					script_pagespy := fmt.Sprintf(`<script%s>%s</script>`, script_attr, files.JSPageSpy)
					script_pagespy2 := fmt.Sprintf(`<script%s>%s</script>`, script_attr, files.JSDebug)
					inserted_scripts += script_pagespy + script_pagespy2
				}
				html = strings.Replace(html, "</body>", inserted_scripts+"</body>", 1)
				ctx.SetResponseBody(html)
				return
			}
		},
	}
}

// normalizeArticleURL 从公众号文章URL中提取核心标识参数作为去重key
func normalizeArticleURL(u *url.URL) string {
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

// buildCleanArticleURL 构建干净的文章URL，只保留核心参数，去掉追踪/会话参数
func buildCleanArticleURL(u *url.URL) string {
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
