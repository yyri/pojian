package wxmp

import (
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNormalizeArticleURL(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{
			"https://mp.weixin.qq.com/s?__biz=MzA3&mid=2247&idx=1&sn=abc&chksm=xyz&scene=27",
			"biz=MzA3&mid=2247&idx=1&sn=abc",
		},
		{
			"https://mp.weixin.qq.com/s/AbCdEf?foo=1",
			"/s/AbCdEf?foo=1",
		},
		{
			"https://mp.weixin.qq.com/s?__biz=MzU1Njc2NzM5Mg%3D%3D&idx=1&mid=2247485120&sn=9992a4354324e05ba44043bdbe49d69c&poc_token=HD_z_GqjPdvSJnj7jCtS2vmM7Xv4cX16BS0kOpAa",
			"biz=MzU1Njc2NzM5Mg==&mid=2247485120&idx=1&sn=9992a4354324e05ba44043bdbe49d69c",
		},
		{
			"https://mp.weixin.qq.com/s?__biz=MzU1Njc2NzM5Mg%3D%3D&idx=1&mid=2247485120&sn=9992a4354324e05ba44043bdbe49d69c&poc_token=HJTy_Gqj7040nFBDxG2GzAMiiVGqnqZoyk8lj_SA",
			"biz=MzU1Njc2NzM5Mg==&mid=2247485120&idx=1&sn=9992a4354324e05ba44043bdbe49d69c",
		},
	}
	for _, c := range cases {
		u, err := url.Parse(c.raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := normalize_article_url(u); got != c.want {
			t.Errorf("normalize_article_url(%s) = %s, want %s", c.raw, got, c.want)
		}
	}
}

func TestBuildCleanArticleURL(t *testing.T) {
	u, err := url.Parse("https://mp.weixin.qq.com/s?__biz=MzA3&mid=2247&idx=1&sn=abc&chksm=xyz&scene=27&key=token")
	if err != nil {
		t.Fatal(err)
	}
	got := build_clean_article_url(u)
	want := "https://mp.weixin.qq.com/s?__biz=MzA3&idx=1&mid=2247&sn=abc"
	if got != want {
		t.Errorf("build_clean_article_url = %s, want %s", got, want)
	}

	short, _ := url.Parse("https://mp.weixin.qq.com/s/AbCdEf")
	if got := build_clean_article_url(short); got != short.String() {
		t.Errorf("short link should stay unchanged, got %s", got)
	}
}

func TestConsumeReloadDecision(t *testing.T) {
	now := time.Now()

	// 首次见到文章：应打开
	first := &article_open_state{}
	if open, dup := first.consume_reload_decision(now); !open || dup {
		t.Errorf("first sighting should open, got open=%v dup=%v", open, dup)
	}

	// 同一次页面浏览的后续请求（无重载标记）：静默跳过
	if open, dup := first.consume_reload_decision(now.Add(time.Second)); open || dup {
		t.Errorf("ongoing traffic should be silent, got open=%v dup=%v", open, dup)
	}

	// 窗口内重新点开：跳过并标记重复
	first.reload_seen = true
	if open, dup := first.consume_reload_decision(now.Add(30 * time.Minute)); open || !dup {
		t.Errorf("re-click within window should be duplicate, got open=%v dup=%v", open, dup)
	}

	// 窗口外重新点开：再次打开
	first.reload_seen = true
	if open, dup := first.consume_reload_decision(now.Add(articleOpenDedupWindow + time.Hour)); !open || dup {
		t.Errorf("re-click after window should open again, got open=%v dup=%v", open, dup)
	}

	// 窗口边界：恰好等于窗口时长时视为已过期，重新打开
	boundary := &article_open_state{last_opened: now.Add(-articleOpenDedupWindow), reload_seen: true}
	if open, dup := boundary.consume_reload_decision(now); !open || dup {
		t.Errorf("exactly at window edge should open again, got open=%v dup=%v", open, dup)
	}

	// 窗口边界内一秒：跳过
	edge := &article_open_state{last_opened: now.Add(-articleOpenDedupWindow + time.Second), reload_seen: true}
	if open, dup := edge.consume_reload_decision(now); open || !dup {
		t.Errorf("one second inside window should be duplicate, got open=%v dup=%v", open, dup)
	}
}

func TestDecidePageLoad(t *testing.T) {
	now := time.Now()
	s := &article_open_state{}

	// 首次加载：打开
	if open, dup := s.decide_page_load(now); !open || dup {
		t.Errorf("first page load should open, got open=%v dup=%v", open, dup)
	}
	// 窗口内再次加载：跳过并标记重复
	if open, dup := s.decide_page_load(now.Add(time.Hour)); open || !dup {
		t.Errorf("re-load within window should be duplicate, got open=%v dup=%v", open, dup)
	}
	// 窗口外再次加载：重新打开
	if open, dup := s.decide_page_load(now.Add(articleOpenDedupWindow + time.Hour)); !open || dup {
		t.Errorf("re-load after window should open, got open=%v dup=%v", open, dup)
	}
}

func TestIsFullArticleURL(t *testing.T) {
	full, _ := url.Parse("https://mp.weixin.qq.com/s?__biz=MzA3&mid=2247&idx=1&sn=abc&chksm=xyz")
	if !is_full_article_url(full) {
		t.Error("full article url should match")
	}
	partial, _ := url.Parse("https://mp.weixin.qq.com/s?chksm=xyz&scene=27")
	if is_full_article_url(partial) {
		t.Error("url without biz/mid/sn should not match")
	}
	short, _ := url.Parse("https://mp.weixin.qq.com/s/AbCdEf")
	if is_full_article_url(short) {
		t.Error("short link should not match")
	}
}

func TestBuildClosePageHTML(t *testing.T) {
	opened := build_close_page_html(true, false)
	if !strings.Contains(opened, "已在系统浏览器打开") {
		t.Error("opened page should show opened title")
	}
	dup := build_close_page_html(false, true)
	if !strings.Contains(dup, "未重复打开") {
		t.Error("duplicate page should show duplicate title")
	}
	if !strings.Contains(opened, "close_now") {
		t.Error("page should contain auto close script")
	}
}

func TestArticleStatesPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/pojian_opened_articles.json"

	var states sync.Map
	states.Store("k1", &article_open_state{last_opened: time.Now().Add(-time.Hour)})
	states.Store("k2", &article_open_state{last_opened: time.Now().Add(-articleOpenDedupWindow * 2)}) // 窗口外，应被清理
	save_article_states(&states, path)

	var restored sync.Map
	load_article_states(&restored, path)
	if _, ok := restored.Load("k1"); !ok {
		t.Error("k1 within window should be restored")
	}
	if _, ok := restored.Load("k2"); ok {
		t.Error("k2 outside window should be pruned")
	}
}