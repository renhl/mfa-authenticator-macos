#!/usr/bin/env python3
"""Build an ad-hoc signed macOS app without third-party dependencies."""
from pathlib import Path
import platform
import shutil
import subprocess

root = Path(__file__).resolve().parents[1]
build = root / "build"
app = build / "MFA 验证器.app"
contents = app / "Contents"
(contents / "MacOS").mkdir(parents=True, exist_ok=True)
(contents / "Resources").mkdir(exist_ok=True)
shutil.copyfile(root / "Resources/Info.plist", contents / "Info.plist")
shutil.copyfile(root / "Resources/AppIcon.icns", contents / "Resources/AppIcon.icns")
subprocess.run([
    "xcrun", "swiftc", str(root / "Sources/main.swift"),
    "-target", f"{platform.machine()}-apple-macosx13.0",
    "-module-cache-path", str(build / "swift-cache"),
    "-framework", "AppKit", "-framework", "CryptoKit",
    "-framework", "Security", "-framework", "Vision",
    "-o", str(contents / "MacOS/MFAAuthenticator"),
], check=True)
subprocess.run(["codesign", "--force", "--sign", "-", str(app)], check=True)
subprocess.run(["codesign", "--verify", "--strict", str(app)], check=True)
subprocess.run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent",
                str(app), str(build / "MFA-Authenticator-macOS.zip")], check=True)
print(app)
