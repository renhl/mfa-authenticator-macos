# MFA 验证器（macOS）

![应用图标](Resources/Icon.png)

使用 Swift / AppKit 编写的本地 TOTP 验证器，可同时显示多个账号的动态码，并提供可复制的桌面小面板。

## 功能

- 多账号列表、独立倒计时和复制按钮。
- 手动输入 Base32 密钥，或粘贴完整 `otpauth://totp` 链接。
- 从图片导入单个 TOTP 二维码，检测重复账号。
- SHA-1 / SHA-256 / SHA-512、6 / 8 位、5–300 秒周期；纯密钥默认 SHA-1、6 位、30 秒。
- 桌面面板可拖动、分别复制；关闭管理窗口后面板仍运行，退出后再打开可恢复面板。
- 账号与密钥保存在当前用户的 macOS 钥匙串，应用本身不联网。

桌面面板由应用进程提供，不是 WidgetKit 原生小组件。完全退出应用会同时关闭面板。

## 下载安装

从本仓库的 Releases 下载 `MFA-Authenticator-macOS.zip`，解压后将 `MFA 验证器.app` 放入“应用程序”。发布包为 Apple Silicon 版本，需要 macOS 13 或更新系统。

应用使用本地临时签名，未经过 Apple 公证。首次运行或更新后，macOS 可能要求确认钥匙串访问权限；请在系统提示中处理。

仓库和安装包不包含预置账号、个人 MFA 密钥、二维码或钥匙串导出。首次使用需要添加自己的账号。

## 从源码构建

需要 macOS、Xcode Command Line Tools（含 Swift 编译器）和 Python 3，无第三方库依赖。

```bash
python3 scripts/build.py
```

输出：

- `build/MFA 验证器.app`
- `build/MFA-Authenticator-macOS.zip`

构建脚本使用本机处理器架构。Intel Mac 可在本机从源码构建。

## 验证

```bash
python3 scripts/test.py
```

包含 RFC 6238 的 18 组测试向量，以及位数、周期边界、URI 参数、无效输入、重复账号、数据序列化和添加表单布局回归检查。布局检查需要已解锁的 macOS 图形会话。

## 使用

- **添加账号**：点击按钮或按 `Command+N`；完整链接可自动提取名称与参数。
- **桌面面板**：点击按钮或按 `Command+D`。
- **管理账号**：从面板返回管理窗口，或点击 Dock 图标。
- **退出**：`Command+Q`。

旧版本的内部 bundle identifier 与钥匙串 service identifier 保留为 `com.local.qsh-mfa`，便于兼容已保存的多账号列表；应用显示名称为“MFA 验证器”。

删除应用不会删除钥匙串中的账号。需要手动清除时，在“钥匙串访问”中查找 `com.local.qsh-mfa`。

## 图标

图标源代码在 `scripts/MakeIcon.swift`；它用 AppKit 绘制钥匙孔与计时圆环。已生成的 PNG 与 ICNS 位于 `Resources/`。
