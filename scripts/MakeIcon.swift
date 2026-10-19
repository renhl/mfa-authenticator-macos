import AppKit
import ImageIO
import UniformTypeIdentifiers

let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
func drawIcon(_ size: Int, to url: URL) throws {
    let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
    let context = NSGraphicsContext.current!.cgContext
    context.scaleBy(x: CGFloat(size) / 1024, y: CGFloat(size) / 1024)
    let plate = NSBezierPath(roundedRect: NSRect(x: 72, y: 72, width: 880, height: 880), xRadius: 196, yRadius: 196)
    NSColor(calibratedRed: 0.09, green: 0.15, blue: 0.25, alpha: 1).setFill()
    plate.fill()
    let ring = NSBezierPath()
    ring.appendArc(withCenter: NSPoint(x: 512, y: 520), radius: 268, startAngle: 118, endAngle: 422, clockwise: false)
    ring.lineWidth = 59
    ring.lineCapStyle = .round
    NSColor(calibratedRed: 0.39, green: 0.88, blue: 0.79, alpha: 1).setStroke()
    ring.stroke()
    NSColor.white.setFill()
    NSBezierPath(ovalIn: NSRect(x: 420, y: 491, width: 184, height: 184)).fill()
    let stem = NSBezierPath()
    stem.move(to: NSPoint(x: 473, y: 536))
    stem.line(to: NSPoint(x: 451, y: 365))
    stem.curve(to: NSPoint(x: 573, y: 365), controlPoint1: NSPoint(x: 478, y: 347), controlPoint2: NSPoint(x: 546, y: 347))
    stem.line(to: NSPoint(x: 551, y: 536))
    stem.close()
    stem.fill()
    NSGraphicsContext.restoreGraphicsState()
    guard let png = bitmap.representation(using: .png, properties: [:]) else { throw NSError(domain: "Icon", code: 1) }
    try png.write(to: url)
}
for size in [16, 32, 128, 256, 512] {
    try drawIcon(size, to: directory.appendingPathComponent("icon_\(size)x\(size).png"))
    try drawIcon(size * 2, to: directory.appendingPathComponent("icon_\(size)x\(size)@2x.png"))
}
try drawIcon(1024, to: directory.deletingLastPathComponent().appendingPathComponent("MFA Icon.png"))
