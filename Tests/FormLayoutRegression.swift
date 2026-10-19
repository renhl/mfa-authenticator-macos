import AppKit
let app = NSApplication.shared
let alert = NSAlert()
alert.addButton(withTitle: "添加")
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

alert.layout()
alert.window.contentView!.layoutSubtreeIfNeeded()
print("name:", name.frame, "bezeled:", name.isBezeled, "editable:", name.isEditable)
print("secret:", secret.frame, "bezeled:", secret.isBezeled, "editable:", secret.isEditable)
let valid = [name, secret].allSatisfy { $0.frame.width >= 300 && $0.frame.height >= 22 && $0.isBezeled && $0.isEditable }
if !valid { fputs("FAIL: add-account text inputs must be visible and editable\n", stderr); exit(1) }
print("PASS: visible, editable inputs")
