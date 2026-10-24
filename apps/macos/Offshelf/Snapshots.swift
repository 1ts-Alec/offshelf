#if DEBUG
import AppKit
import SwiftUI

/// Dev aid: with OFFSHELF_SNAPSHOTS=<dir>, renders every screen to PNGs once
/// the shelf is open, then quits. Lets the UI be checked without anyone
/// clicking through it.
@MainActor
enum Snapshots {
    static var dir: URL? {
        ProcessInfo.processInfo.environment["OFFSHELF_SNAPSHOTS"].map { URL(fileURLWithPath: $0) }
    }

    static func run(_ model: AppModel) {
        guard let dir else { return }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) {
            let shots: [(String, AnyView, CGSize)] = [
                ("popover", AnyView(PopoverView()), CGSize(width: 340, height: 420)),
                ("files", AnyView(MainWindow(section: .files)), CGSize(width: 1100, height: 640)),
                ("files-movies", AnyView(MainWindow(section: .files, folder: "Movies")), CGSize(width: 1100, height: 640)),
                ("activity", AnyView(MainWindow(section: .activity)), CGSize(width: 1100, height: 640)),
                ("hosts", AnyView(MainWindow(section: .hosts)), CGSize(width: 1100, height: 760)),
                ("settings", AnyView(MainWindow(section: .settings)), CGSize(width: 1100, height: 900)),
                ("unlock", AnyView(UnlockView()), CGSize(width: 520, height: 300)),
            ] + (1...5).map { ("onboarding-\($0)", AnyView(OnboardingView(step: $0)), CGSize(width: 960, height: 640)) }
            var windows: [NSWindow] = []
            for (name, view, size) in shots {
                let host = NSHostingView(rootView: view.environmentObject(model).frame(width: size.width, height: size.height))
                host.frame = NSRect(origin: .zero, size: size)
                let w = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
                w.contentView = host
                w.setFrameOrigin(NSPoint(x: -10000, y: -10000))
                w.orderFrontRegardless()
                windows.append(w)
                _ = name
            }
            // Let tasks load listings, then capture.
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                for (i, (name, _, _)) in shots.enumerated() {
                    guard let v = windows[i].contentView,
                          let rep = v.bitmapImageRepForCachingDisplay(in: v.bounds) else { continue }
                    v.cacheDisplay(in: v.bounds, to: rep)
                    try? rep.representation(using: .png, properties: [:])?.write(to: dir.appendingPathComponent("\(name).png"))
                }
                model.quit()
            }
        }
    }
}
#endif
