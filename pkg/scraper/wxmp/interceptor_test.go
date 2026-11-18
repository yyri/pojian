package wxmp

import (
	"net/url"
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