import AppKit
import CryptoKit
import Security
import Vision

func decodeBase32(_ value: String) -> Data? {
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    var buffer = 0, bits = 0, bytes = [UInt8]()
    let text = value.uppercased().filter { !$0.isWhitespace && $0 != "=" }
    guard !text.isEmpty else { return nil }
    for char in text {
        guard let n = alphabet.firstIndex(of: char) else { return nil }
        buffer = (buffer << 5) | n
        bits += 5
        if bits >= 8 {
            bits -= 8
            bytes.append(UInt8((buffer >> bits) & 255))
            buffer &= (1 << bits) - 1
        }
    }
    guard bits < 5, buffer == 0 else { return nil }
    return Data(bytes)
}

struct MFAError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
    init(_ message: String) { self.message = message }
}

struct Token: Codable {
    var id = UUID().uuidString
    var name: String
    var key: Data
    var period = 30
    var digits = 6
    var algorithm = "SHA1"

    func code(at time: TimeInterval = Date().timeIntervalSince1970) -> String {
        var counter = UInt64(time / Double(period)).bigEndian
        let message = withUnsafeBytes(of: &counter) { Data($0) }
        let secret = SymmetricKey(data: key)
        let hash: [UInt8]
        switch algorithm {
        case "SHA256": hash = Array(HMAC<SHA256>.authenticationCode(for: message, using: secret))
        case "SHA512": hash = Array(HMAC<SHA512>.authenticationCode(for: message, using: secret))
        default: hash = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: secret))
        }
        let offset = Int(hash.last! & 15)
        let number = (UInt32(hash[offset] & 127) << 24) | (UInt32(hash[offset + 1]) << 16)
            | (UInt32(hash[offset + 2]) << 8) | UInt32(hash[offset + 3])
        return String(format: "%0*u", digits, number % (digits == 8 ? 100_000_000 : 1_000_000))
    }

    func matches(_ other: Token) -> Bool {
        key == other.key && period == other.period && digits == other.digits && algorithm == other.algorithm
    }
}

func parseToken(name: String, input: String) throws -> Token {
    var label = name.trimmingCharacters(in: .whitespacesAndNewlines)
    let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
    var secret = text, period = 30, digits = 6, algorithm = "SHA1"
    if text.lowercased().hasPrefix("otpauth:") {
        guard let url = URLComponents(string: text), url.scheme?.lowercased() == "otpauth", url.host == "totp" else {
            throw MFAError("仅支持 otpauth://totp 时间型验证码链接。")
        }
        var params = [String: String]()
        for item in url.queryItems ?? [] {
            guard params[item.name] == nil, let value = item.value else { throw MFAError("链接参数重复或缺少值。") }
            params[item.name] = value
        }
        secret = params["secret"] ?? ""
        if let value = params["period"] {
            guard let n = Int(value) else { throw MFAError("刷新周期必须是整数。") }
            period = n
        }
        if let value = params["digits"] {
            guard let n = Int(value) else { throw MFAError("验证码位数无效。") }
            digits = n
        }
        algorithm = (params["algorithm"] ?? "SHA1").uppercased()
        if label.isEmpty {
            label = String(url.path.dropFirst())
            if let issuer = params["issuer"], !issuer.isEmpty, !label.hasPrefix(issuer + ":") {
                label = issuer + (label.isEmpty ? "" : ":" + label)
            }
        }
    }
    guard !label.isEmpty else { throw MFAError("请填写账号名称。") }
    guard let key = decodeBase32(secret), !key.isEmpty else {
        throw MFAError("密钥必须为 Base32 字符。请只粘贴密钥，或粘贴完整 otpauth 链接。")
    }
    guard (5...300).contains(period) else { throw MFAError("刷新周期需在 5–300 秒之间。") }
    guard [6, 8].contains(digits) else { throw MFAError("仅支持 6 位或 8 位验证码。") }
    guard ["SHA1", "SHA256", "SHA512"].contains(algorithm) else { throw MFAError("不支持该摘要算法。") }
    return Token(name: label, key: key, period: period, digits: digits, algorithm: algorithm)
}

func keychainQuery(_ account: String) -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword,
     kSecAttrService as String: "com.local.qsh-mfa", kSecAttrAccount as String: account]
}

func readKeychain(_ account: String) throws -> Data? {
    var query = keychainQuery(account)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess, let data = result as? Data else {
        throw MFAError("无法读取钥匙串（\(status)）。请解锁钥匙串并允许本应用访问。")
    }
    return data
}

func saveTokens(_ tokens: [Token]) throws {
    let data = try JSONEncoder().encode(tokens)
    let query = keychainQuery("tokens-v2")
    let update = [kSecValueData as String: data]
    var status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
    if status == errSecItemNotFound {
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrLabel as String] = "MFA 验证器 · 账号列表"
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        status = SecItemAdd(add as CFDictionary, nil)
    }
    guard status == errSecSuccess, try readKeychain("tokens-v2") == data else {
        throw MFAError("保存钥匙串失败（\(status)），账号未添加。")
    }
}

func loadTokens() throws -> [Token] {
    if let data = try readKeychain("tokens-v2") { return try JSONDecoder().decode([Token].self, from: data) }
    return []
}

func readQR(_ url: URL) throws -> [String] {
    let request = VNDetectBarcodesRequest()
    request.usesCPUOnly = true
    request.symbologies = [.qr]
    try VNImageRequestHandler(url: url).perform([request])
    let values = (request.results ?? []).compactMap(\.payloadStringValue)
    guard !values.isEmpty else { throw MFAError("图片中未识别到二维码。") }
    return values
}

if CommandLine.arguments.contains("--self-test") {
    do {
        let times: [Double] = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
        let expected = [
            "SHA1": ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"],
            "SHA256": ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"],
            "SHA512": ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"]]
        for (algorithm, count) in [("SHA1", 20), ("SHA256", 32), ("SHA512", 64)] {
            let sequence = Array("1234567890".utf8)
            let key = Data((0..<count).map { sequence[$0 % 10] })
            let token = Token(name: "RFC 6238", key: key, digits: 8, algorithm: algorithm)
            for (i, time) in times.enumerated() { precondition(token.code(at: time) == expected[algorithm]![i]) }
        }
        let token = try parseToken(name: "", input: "otpauth://totp/Test:user?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test")
        precondition(token.name == "Test:user" && token.code(at: 59) == "287082")
        precondition(token.code(at: 29) != token.code(at: 30))
        let custom = try parseToken(name: "Custom", input: "otpauth://totp/A?secret=MY======&period=60&digits=8&algorithm=SHA256")
        precondition(custom.period == 60 && custom.digits == 8 && custom.algorithm == "SHA256")
        let renamed = try parseToken(name: "Renamed", input: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        precondition(token.matches(renamed))
        precondition(decodeBase32("SECRET&period=30") == nil)
        for invalid in ["otpauth://hotp/A?secret=MY", "otpauth://totp/A?secret=MY&digits=7",
            "otpauth://totp/A?secret=MY&period=0", "otpauth://totp/A?secret=MY&algorithm=MD5",
            "otpauth://totp/A?secret=MY&secret=MY", "otpauth://totp/A", "INVALID!"] {
            do { _ = try parseToken(name: "Test", input: invalid); fatalError("Accepted invalid input") }
            catch { }
        }
        let roundTrip = try JSONDecoder().decode([Token].self, from: JSONEncoder().encode([token, custom]))
        precondition(roundTrip.count == 2 && roundTrip[0].id == token.id && roundTrip[1].matches(custom))
        print("PASS: 18 RFC 6238 vectors; six digits; rollover; URI parameters; invalid inputs; duplicates; persistence encoding")
    } catch { fputs("\(error)\n", stderr); exit(1) }
    exit(0)
}

if CommandLine.arguments.contains("--import-json") || CommandLine.arguments.contains("--list") {
    do {
        var tokens = try loadTokens()
        if CommandLine.arguments.contains("--import-json") {
            struct Entry: Decodable { let name: String; let input: String }
            let entries = try JSONDecoder().decode([Entry].self, from: FileHandle.standardInput.readDataToEndOfFile())
            for entry in entries {
                let token = try parseToken(name: entry.name, input: entry.input)
                if tokens.contains(where: { $0.matches(token) }) { print("Already added: \(token.name)") }
                else { tokens.append(token) }
            }
            try saveTokens(tokens)
        }
        for token in tokens { print("\(token.name) | \(token.algorithm) | \(token.digits) digits | \(token.period)s") }
        print("Total: \(tokens.count)")
    } catch { fputs("\(error.localizedDescription)\n", stderr); exit(1) }
    exit(0)
}

final class TokenRow: NSBox {
    let token: Token
    let code = NSTextField(labelWithString: "")
    let countdown = NSTextField(labelWithString: "")
    let progress = NSProgressIndicator()
    let copyButton = NSButton(title: "复制", target: nil, action: nil)
    var copiedUntil = Date.distantPast

    init(_ token: Token, compact: Bool = false) {
        self.token = token
        super.init(frame: .zero)
        boxType = .custom
        borderColor = .separatorColor
        cornerRadius = 10
        contentViewMargins = NSSize(width: 16, height: 12)
        let displayName = compact ? token.name.replacingOccurrences(of: " · ", with: "\n")
            .replacingOccurrences(of: ":", with: "\n") : token.name
        let name = NSTextField(labelWithString: displayName)
        name.font = .systemFont(ofSize: compact ? 12 : 15, weight: .semibold)
        name.lineBreakMode = compact ? .byWordWrapping : .byTruncatingTail
        name.maximumNumberOfLines = compact ? 2 : 1
        name.toolTip = token.name
        name.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let details = NSTextField(labelWithString: "\(token.algorithm) · \(token.digits) 位 · \(token.period) 秒")
        details.font = .systemFont(ofSize: 11)
        details.textColor = .secondaryLabelColor
        countdown.font = .monospacedDigitSystemFont(ofSize: 11, weight: .regular)
        countdown.textColor = .secondaryLabelColor
        progress.isIndeterminate = false
        progress.maxValue = Double(token.period)
        progress.style = .bar
        let left = NSStackView(views: compact ? [name, progress, countdown] : [name, details, progress, countdown])
        left.orientation = .vertical
        left.alignment = .leading
        left.spacing = 7
        progress.widthAnchor.constraint(equalTo: left.widthAnchor).isActive = true
        code.font = .monospacedDigitSystemFont(ofSize: compact ? 25 : 32, weight: .medium)
        code.isSelectable = true
        code.alignment = .right
        code.setAccessibilityLabel(token.name + " 动态验证码")
        copyButton.target = self
        copyButton.action = #selector(copyCode)
        copyButton.bezelStyle = .rounded
        copyButton.setAccessibilityLabel("复制 " + token.name + " 验证码")
        let right = NSStackView(views: [code, copyButton])
        right.orientation = .vertical
        right.alignment = .trailing
        right.spacing = 6
        let row = NSStackView(views: [left, right])
        row.spacing = compact ? 12 : 24
        row.alignment = .centerY
        row.translatesAutoresizingMaskIntoConstraints = false
        contentView!.addSubview(row)
        NSLayoutConstraint.activate([
            row.leadingAnchor.constraint(equalTo: contentView!.leadingAnchor),
            row.trailingAnchor.constraint(equalTo: contentView!.trailingAnchor),
            row.topAnchor.constraint(equalTo: contentView!.topAnchor),
            row.bottomAnchor.constraint(equalTo: contentView!.bottomAnchor),
            heightAnchor.constraint(equalToConstant: compact ? 100 : 126),
            right.widthAnchor.constraint(equalToConstant: compact ? 132 : 180)
        ])
        update()
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    func update() {
        let now = Date().timeIntervalSince1970
        code.stringValue = token.code(at: now)
        let remaining = Double(token.period) - now.truncatingRemainder(dividingBy: Double(token.period))
        progress.doubleValue = remaining
        countdown.stringValue = "\(Int(ceil(remaining))) 秒后刷新"
        copyButton.title = Date() < copiedUntil ? "已复制" : "复制"
    }
    @objc func copyCode() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(token.code(), forType: .string)
        copiedUntil = Date().addingTimeInterval(2)
        update()
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var timer: Timer?
    var tokens = [Token]()
    var rows = [TokenRow]()
    var desktopRows = [TokenRow]()
    var desktopPanel: NSPanel?
    var isTerminating = false
    let list = NSStackView()
    let summary = NSTextField(labelWithString: "")

    func showError(_ error: Error) {
        let alert = NSAlert()
        alert.messageText = "无法完成操作"
        alert.informativeText = error.localizedDescription
        alert.runModal()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        do { tokens = try loadTokens() } catch { showError(error); NSApp.terminate(nil); return }
        let menu = NSMenu(), item = NSMenuItem(), appMenu = NSMenu()
        menu.addItem(item)
        appMenu.addItem(withTitle: "退出 MFA 验证器", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appMenu.insertItem(withTitle: "显示桌面面板", action: #selector(showDesktopPanel), keyEquivalent: "d", at: 0)
        item.submenu = appMenu
        NSApp.mainMenu = menu
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 660, height: 570),
            styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "MFA 验证器"
        window.minSize = NSSize(width: 600, height: 400)
        window.isReleasedWhenClosed = false
        let title = NSTextField(labelWithString: "动态验证码")
        title.font = .systemFont(ofSize: 23, weight: .semibold)
        title.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let add = NSButton(title: "添加账号", target: self, action: #selector(addToken))
        add.bezelStyle = .rounded
        add.keyEquivalent = "n"
        add.keyEquivalentModifierMask = .command
        let qr = NSButton(title: "导入二维码图片", target: self, action: #selector(importQR))
        qr.bezelStyle = .rounded
        let desktop = NSButton(title: "桌面面板", target: self, action: #selector(showDesktopPanel))
        desktop.bezelStyle = .rounded
        let header = NSStackView(views: [title, desktop, qr, add])
        header.spacing = 10
        summary.textColor = .secondaryLabelColor
        summary.font = .systemFont(ofSize: 12)
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        list.orientation = .vertical
        list.alignment = .leading
        list.spacing = 12
        list.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = list
        NSLayoutConstraint.activate([
            list.leadingAnchor.constraint(equalTo: scroll.contentView.leadingAnchor),
            list.trailingAnchor.constraint(equalTo: scroll.contentView.trailingAnchor),
            list.topAnchor.constraint(equalTo: scroll.contentView.topAnchor),
            list.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor)
        ])
        let footer = NSTextField(labelWithString: "密钥保存在本机钥匙串 · 验证码在本地生成")
        footer.font = .systemFont(ofSize: 11)
        footer.textColor = .secondaryLabelColor
        let root = NSStackView(views: [header, summary, scroll, footer])
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 16
        root.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 24),
            root.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -24),
            root.topAnchor.constraint(equalTo: window.contentView!.topAnchor, constant: 24),
            root.bottomAnchor.constraint(equalTo: window.contentView!.bottomAnchor, constant: -20),
            header.widthAnchor.constraint(equalTo: root.widthAnchor),
            scroll.widthAnchor.constraint(equalTo: root.widthAnchor)
        ])
        rebuild()
        timer = Timer(timeInterval: 0.25, repeats: true) { [weak self] _ in
            self?.rows.forEach { $0.update() }
            self?.desktopRows.forEach { $0.update() }
        }
        RunLoop.main.add(timer!, forMode: .common)
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        if UserDefaults.standard.bool(forKey: "desktopPanelEnabled") { showDesktopPanel() }
    }

    func rebuild() {
        for view in list.arrangedSubviews { list.removeArrangedSubview(view); view.removeFromSuperview() }
        rows = tokens.map { TokenRow($0) }
        for row in rows {
            list.addArrangedSubview(row)
            row.widthAnchor.constraint(equalTo: list.widthAnchor).isActive = true
        }
        summary.stringValue = tokens.isEmpty ? "还没有账号，点击“添加账号”开始" : "\(tokens.count) 个账号 · 各账号按自身周期自动刷新"
        if desktopPanel?.isVisible == true { showDesktopPanel() }
    }

    @objc func showMainWindow() {
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc func showDesktopPanel() {
        let panel: NSPanel
        if let existing = desktopPanel { panel = existing }
        else {
            panel = NSPanel(contentRect: NSRect(x: 40, y: 180, width: 440, height: 400),
                styleMask: [.titled, .closable, .nonactivatingPanel], backing: .buffered, defer: false)
            panel.title = "MFA · 桌面面板"
            panel.isReleasedWhenClosed = false
            panel.hidesOnDeactivate = false
            panel.isFloatingPanel = false
            panel.isMovableByWindowBackground = true
            panel.level = NSWindow.Level(rawValue: Int(CGWindowLevelForKey(.desktopIconWindow)) + 1)
            panel.setFrameAutosaveName("MFADesktopPanel")
            NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: panel, queue: .main) { [weak self] _ in
                if self?.isTerminating == false { UserDefaults.standard.set(false, forKey: "desktopPanelEnabled") }
            }
            desktopPanel = panel
        }
        let title = NSTextField(labelWithString: "动态验证码")
        title.font = .systemFont(ofSize: 15, weight: .semibold)
        title.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let manage = NSButton(title: "管理账号", target: self, action: #selector(showMainWindow))
        manage.bezelStyle = .rounded
        let header = NSStackView(views: [title, manage])
        desktopRows = tokens.map { TokenRow($0, compact: true) }
        let stack = NSStackView(views: [header] + desktopRows)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        let content = NSView()
        content.addSubview(stack)
        panel.contentView = content
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 12),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -12),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -12),
            header.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])
        for row in desktopRows { row.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true }
        panel.setContentSize(NSSize(width: 440, height: 58 + tokens.count * 110))
        panel.orderFrontRegardless()
        UserDefaults.standard.set(true, forKey: "desktopPanelEnabled")
    }

    func add(_ token: Token) throws {
        guard !tokens.contains(where: { $0.matches(token) }) else { throw MFAError("此密钥与参数已存在于列表，无需重复添加。") }
        let updated = tokens + [token]
        try saveTokens(updated)
        tokens = updated
        rebuild()
    }

    @objc func addToken() {
        let alert = NSAlert()
        alert.messageText = "添加 MFA 账号"
        alert.informativeText = "填写名称和 Base32 密钥，或粘贴完整 otpauth://totp 链接。\n纯密钥默认使用 SHA-1、6 位、30 秒。"
        alert.addButton(withTitle: "添加")
        alert.addButton(withTitle: "取消")
        let name = NSTextField(), secret = NSTextField()
        name.placeholderString = "账号名称（完整链接可自动提取）"
        secret.placeholderString = "Base32 密钥或完整 otpauth 链接"
        name.setAccessibilityLabel("账号名称")
        secret.setAccessibilityLabel("密钥或 otpauth 链接")
        let fields = NSStackView(views: [name, secret])
        fields.orientation = .vertical
        fields.alignment = .leading
        fields.spacing = 14
        fields.frame = NSRect(x: 0, y: 0, width: 420, height: 76)
        fields.widthAnchor.constraint(equalToConstant: 420).isActive = true
        name.widthAnchor.constraint(equalTo: fields.widthAnchor).isActive = true
        secret.widthAnchor.constraint(equalTo: fields.widthAnchor).isActive = true
        alert.accessoryView = fields
        alert.window.initialFirstResponder = name
        while alert.runModal() == .alertFirstButtonReturn {
            do { try add(parseToken(name: name.stringValue, input: secret.stringValue)); return }
            catch { showError(error) }
        }
    }

    @objc func importQR() {
        let panel = NSOpenPanel()
        panel.title = "选择 MFA 二维码图片"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let payloads = try readQR(url)
            guard payloads.count == 1 else { throw MFAError("图片包含多个二维码，请分别裁剪后导入。") }
            try add(parseToken(name: "", input: payloads[0]))
        } catch { showError(error) }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        isTerminating = true
        return .terminateNow
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showMainWindow()
        return false
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
