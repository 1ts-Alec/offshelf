import AppKit
import Foundation
import ServiceManagement
import SwiftUI

/// App state shared by the menu bar, the main window and onboarding.
@MainActor
final class AppModel: ObservableObject {
    enum Phase: Equatable {
        case onboarding
        case locked
        case starting
        case running
        case failed(String)
    }

    @Published var phase: Phase = .starting
    @Published var status: Status?
    @Published var usage: ShelfUsage?
    @Published var events: [ActivityEvent] = []
    @Published var hosts: [HostRule] = []
    @Published var settings: EngineSettings?
    @Published var device: Paired?
    /// Bumped whenever the tree may have changed, so open listings reload.
    @Published var revision: UInt64 = 0

    private(set) var engine: OffshelfEngine?
    let wifi = WiFi()
    private var timer: Timer?
    private var tick = 0

    var homeDir: String { Paths.device.path }
    var dataDir: String { Paths.data.path }

    init() {
        try? FileManager.default.createDirectory(at: Paths.device, withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(at: Paths.data, withIntermediateDirectories: true)
        device = pairedDevice(homeDir: homeDir)
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.reconnect() }
        }
    }

    /// Decides where to start: onboarding, the unlock prompt, or straight
    /// to the mount with the Keychain key.
    func launch() {
        guard isPaired(homeDir: homeDir) else {
            phase = .onboarding
            return
        }
        device = pairedDevice(homeDir: homeDir)
        #if DEBUG
        // Unattended dev runs against a test shelf.
        if let p = ProcessInfo.processInfo.environment["OFFSHELF_DEV_PASSPHRASE"] {
            open(.passphrase(passphrase: p))
            return
        }
        #endif
        if let key = Keychain.load() {
            open(.masterKey(key: key)) { [weak self] err in
                if err != nil {
                    // A stale key (passphrase reset elsewhere): ask again.
                    Keychain.delete()
                    self?.phase = .locked
                }
            }
        } else {
            phase = .locked
        }
    }

    /// Unlocks, keeps the key in the Keychain, and mounts.
    func open(_ unlock: UnlockWith, done: ((Error?) -> Void)? = nil) {
        phase = .starting
        let home = homeDir, data = dataDir, mount = Paths.mount.path
        Task.detached {
            do {
                let e = try OffshelfEngine.open(homeDir: home, dataDir: data, unlock: unlock)
                if ProcessInfo.processInfo.environment["OFFSHELF_DEV_PASSPHRASE"] == nil {
                    Keychain.save(Data(e.masterKey()))
                }
                try e.start(mountpoint: mount)
                await MainActor.run {
                    self.engine = e
                    self.phase = .running
                    self.startPolling()
                    done?(nil)
                    #if DEBUG
                    Snapshots.run(self)
                    #endif
                }
            } catch {
                await MainActor.run {
                    if done == nil {
                        self.phase = .failed(describe(error))
                    }
                    done?(error)
                }
            }
        }
    }

    private func startPolling() {
        wifi.onChange = { [weak self] ssid in
            guard let e = self?.engine else { return }
            Task.detached { e.setNetwork(ssid: ssid) }
        }
        wifi.start()
        hosts = engine?.hosts() ?? []
        settings = engine?.settings()
        refresh()
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    func refresh() {
        guard let e = engine else { return }
        tick += 1
        let slow = tick % 15 == 1
        Task.detached {
            let s = e.status()
            let ev = e.events()
            let u = slow ? (try? e.usage()) : nil
            await MainActor.run {
                if s.revision != self.status?.revision { self.revision = s.revision }
                self.status = s
                self.events = ev
                if let u { self.usage = u }
            }
        }
    }

    func reconnect() {
        guard let e = engine else { return }
        Task.detached { e.reconnect() }
    }

    // MARK: actions

    func run(_ work: @escaping @Sendable (OffshelfEngine) throws -> Void) {
        guard let e = engine else { return }
        Task.detached {
            do { try work(e) } catch {
                await MainActor.run { _ = NSAlert(error: error as NSError).runModal() }
            }
            await MainActor.run { self.revision &+= 1; self.refresh() }
        }
    }

    func pin(_ path: String) { run { try $0.pin(path: path) } }
    func unpin(_ path: String) { run { try $0.unpin(path: path) } }
    func offload(_ path: String) { run { _ = try $0.offload(path: path) } }

    func saveHosts(_ h: [HostRule]) {
        hosts = h
        guard let e = engine else { return }
        Task.detached { e.setHosts(hosts: h) }
    }

    func saveSettings(_ s: EngineSettings) {
        settings = s
        engine?.setSettings(settings: s)
    }

    func showInFinder(_ path: String) {
        let url = path.isEmpty ? Paths.mount : Paths.mount.appendingPathComponent(path)
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    func quit() {
        timer?.invalidate()
        try? engine?.unmount()
        NSApp.terminate(nil)
    }

    func signOut() {
        try? engine?.unmount()
        engine = nil
        timer?.invalidate()
        Keychain.delete()
        try? unpair(homeDir: homeDir)
        device = nil
        status = nil
        phase = .onboarding
    }

    var openAtLogin: Bool {
        get { SMAppService.mainApp.status == .enabled }
        set {
            try? newValue ? SMAppService.mainApp.register() : SMAppService.mainApp.unregister()
            objectWillChange.send()
        }
    }

    // MARK: derived

    var isHome: Bool {
        guard let s = status else { return true }
        return !s.hostName.lowercased().contains("away") && !s.hostUrl.hasPrefix("https")
    }

    var placeLabel: String {
        guard let s = status else { return "Starting" }
        if !s.online { return "Offline" }
        return (s.hostName.isEmpty ? "Home" : s.hostName) + " · Live"
    }
}
