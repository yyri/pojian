# 破茧 (PoJian)

**破茧而出，跳出封闭生态。**

WX 内置浏览器不允许用户使用系统浏览器打开公众号文章，破茧通过本地 HTTPS 代理拦截 WX 浏览器流量，自动将公众号文章在系统默认浏览器中打开，并关闭 WX 内置浏览器页面。

---

**Break free from WX's walled garden.**

WX's built-in browser prevents users from opening Official Account articles in their system browser. PoJian runs a local HTTPS proxy to intercept WX browser traffic, automatically opens articles in your default system browser, and closes the WX browser page.

## 功能 / Features

- 自动检测 WX 公众号文章页面，用系统默认浏览器打开
- 自动关闭 WX 内置浏览器页面 (Windows)
- 智能 URL 去重，同一篇文章不会重复打开
- 构建干净的文章 URL，去除追踪参数
- 支持 Windows / macOS / Linux

---

- Automatically detects WX Official Account articles and opens them in the system default browser
- Automatically closes the WX built-in browser page (Windows)
- Smart URL deduplication - same article won't be opened twice
- Builds clean article URLs by stripping tracking parameters
- Supports Windows / macOS / Linux

## 使用方法 / Usage

### 1. 下载并运行 / Download & Run

以**管理员身份**运行终端（程序需要安装 HTTPS 证书和设置系统代理）：

Run terminal as **Administrator** (the program needs to install HTTPS certificates and set system proxy):

```bash
pojian.exe
```

### 2. 配置 / Configuration

程序首次运行会在当前目录生成 `config.yaml`，核心配置项：

A `config.yaml` will be generated on first run. Key configuration:

```yaml
mp:
  openInSystemBrowser: true   # 自动用系统浏览器打开公众号文章 / Auto-open articles in system browser
```

### 3. 使用 / Use

启动程序后，在 WX PC 端打开任意公众号文章，系统浏览器会自动打开该文章，WX 内置浏览器页面会自动关闭。

After starting the program, open any Official Account article in WX PC. The article will automatically open in your system browser, and the WX browser page will close automatically.

## 工作原理 / How It Works

1. 程序启动后设置系统 HTTPS 代理，拦截 WX 内置浏览器的网络流量
2. WX 打开公众号文章后，页面内的 API 请求会经过代理
3. 程序从这些请求的 `Referer` 头中提取正在浏览的文章 URL
4. 首次检测到新文章时，调用系统默认浏览器打开干净的文章链接
5. 发送 Ctrl+W 关闭 WX 内置浏览器页面 (Windows)

---

1. The program sets up a system HTTPS proxy to intercept WX browser traffic
2. After WX opens an article, subsequent API requests pass through the proxy
3. The program extracts the article URL from the `Referer` header of these requests
4. On first detection of a new article, it opens a clean URL in the system default browser
5. Sends Ctrl+W to close the WX built-in browser page (Windows)

## 编译 / Build

```bash
# Windows
go build -ldflags="-s -w"

# macOS
CGO_ENABLED=1 GOOS=darwin go build -trimpath -ldflags="-s -w" -o pojian

# Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o pojian
```

## 致谢 / Acknowledgments

本项目基于 [wx_channels_download](https://github.com/ltaoo/wx_channels_download) 项目开发，感谢原作者 [@ltaoo](https://github.com/ltaoo) 提供的 HTTPS 代理拦截和 JS 注入框架。

破茧的功能代码由 [Qoder](https://qoder.com) AI 编程助手编写。

This project is built upon [wx_channels_download](https://github.com/ltaoo/wx_channels_download). Thanks to [@ltaoo](https://github.com/ltaoo) for the HTTPS proxy interception and JS injection framework.

The feature code of PoJian was written by [Qoder](https://qoder.com), an AI coding assistant.

## 免责声明 / Disclaimer

```
本项目为开源项目，仅用于技术交流学习和研究目的。
请遵守法律法规，请勿用作任何非法用途，否则造成一切后果自负。
若您下载并使用即视为您知晓并同意。

This is an open-source project for technical learning and research purposes only.
Please comply with applicable laws and regulations. Do not use for any illegal purposes.
By downloading and using this software, you acknowledge and agree to these terms.
```
