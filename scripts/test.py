#!/usr/bin/env python3
"""Run RFC/parser tests and the macOS add-form layout regression."""
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
build = root / "build"
exe = build / "MFA 验证器.app/Contents/MacOS/MFAAuthenticator"
if not exe.exists():
    raise SystemExit("Run python3 scripts/build.py first")
subprocess.run([str(exe), "--self-test"], check=True)
# Extract the actual form implementation to keep the regression tied to app code.
source = (root / "Sources/main.swift").read_text()
start = source.index("        let name = NSTextField(), secret = NSTextField()")
end = source.index("        while alert.runModal()", start)
fixture = (root / "Tests/FormLayoutRegression.swift").read_text()
first = fixture.index("        let name = NSTextField(), secret = NSTextField()")
last = fixture.index("\nalert.layout()", first)
regression = build / "FormLayoutRegression.swift"
regression.write_text(fixture[:first] + source[start:end] + fixture[last:])
test = build / "form-layout-test"
subprocess.run(["xcrun", "swiftc", str(regression), "-module-cache-path",
                str(build / "swift-cache"), "-framework", "AppKit", "-o", str(test)], check=True)
subprocess.run([str(test)], check=True)
