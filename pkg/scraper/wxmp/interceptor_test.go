package wxmp

import (
	"net/url"
	"testing"
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