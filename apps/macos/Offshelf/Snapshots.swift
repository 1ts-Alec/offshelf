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

    /// With OFFSHELF_SELFTEST=<file>: pins the first top-level folder, waits
    /// for it to land, offloads it, and writes what happened to the file.
    static func selfTest(_ model: AppModel) {
        guard let out = ProcessInfo.processInfo.environment["OFFSHELF_SELFTEST"], let e = model.engine else { return }
        Task.detached {
            var log: [String] = []
            func note(_ s: String) { log.append(s) }
            do {
                guard let folder = try e.list(path: "").first(where: { $0.isDir }) else { note("no folder"); throw OffshelfError.NotFound(path: "") }
                note("folder \(folder.path): size \(folder.size), local \(folder.localBytes)")
                let start = Date()
                try e.pin(path: folder.path)
                var cur = folder
                while Date().timeIntervalSince(start) < 180 {
                    cur = try e.list(path: "").first { $0.path == folder.path }!
                    if cur.localBytes >= cur.size { break }
                    try await Task.sleep(for: .seconds(1))
                }
                note(String(format: "pinned: local %llu of %llu, pinned=%@, %.0f s", cur.localBytes, cur.size, cur.pinned ? "yes" : "no", Date().timeIntervalSince(start)))
                let freed = try e.offload(path: folder.path)
                cur = try e.list(path: "").first { $0.path == folder.path }!
                note("offloaded: freed \(freed), local now \(cur.localBytes), pinned=\(cur.pinned)")
                note("events: " + e.events().prefix(3).map(\.title).joined(separator: " | "))
            } catch {
                note("error: \(describe(error))")
            }
            try? log.joined(separator: "\n").write(toFile: out, atomically: true, encoding: .utf8)
            await MainActor.run { model.quit() }
        }
    }

    static func run(_ model: AppModel) {
        selfTest(model)
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
                // Popover has no window chrome; the rest mirror the app's
                // hidden-title-bar windows, controls included.
                let chrome: NSWindow.StyleMask = name == "popover"
                    ? [.borderless]
                    : [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView]
                let w = NSWindow(contentRect: host.frame, styleMask: chrome, backing: .buffered, defer: false)
                w.titlebarAppearsTransparent = true
                w.titleVisibility = .hidden
                w.contentView = host
                w.setFrameOrigin(NSPoint(x: -10000, y: -10000))
                w.orderFrontRegardless()
                windows.append(w)
                _ = name
            }
            // Let tasks load listings, then capture.
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                for (i, (name, _, _)) in shots.enumerated() {
                    guard let v = windows[i].contentView?.superview ?? windows[i].contentView,
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
