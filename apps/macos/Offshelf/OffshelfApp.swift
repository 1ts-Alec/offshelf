import AppKit
import SwiftUI

@main
struct OffshelfApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.openWindow) private var openWindow

    var body: some Scene {
        MenuBarExtra {
            PopoverView()
                .environmentObject(model)
        } label: {
            Image("MenuBarIcon")
                .onAppear { start() }
        }
        .menuBarExtraStyle(.window)

        Window("Offshelf", id: "main") {
            MainWindow()
                .environmentObject(model)
                .frame(minWidth: 820, minHeight: 520)
        }
        .defaultSize(width: 980, height: 620)
        .windowResizability(.contentMinSize)

        Window("Welcome to Offshelf", id: "onboarding") {
            OnboardingView()
                .environmentObject(model)
                .frame(width: 960, height: 640)
        }
        .windowResizability(.contentSize)
        .windowStyle(.hiddenTitleBar)

        Window("Unlock Offshelf", id: "unlock") {
            UnlockView()
                .environmentObject(model)
                .frame(width: 520, height: 300)
        }
        .windowResizability(.contentSize)
    }

    private func start() {
        guard model.phase == .starting, model.engine == nil else { return }
        model.launch()
        DispatchQueue.main.async {
            switch model.phase {
            case .onboarding: show("onboarding")
            case .locked: show("unlock")
            default: break
            }
        }
    }

    private func show(_ id: String) {
        openWindow(id: id)
        NSApp.activate(ignoringOtherApps: true)
    }
}

/// Opens one of the app's windows and brings the app forward (it has no
/// Dock icon, so windows would otherwise open behind).
struct WindowOpener {
    let openWindow: OpenWindowAction

    func callAsFunction(_ id: String) {
        openWindow(id: id)
        NSApp.activate(ignoringOtherApps: true)
    }
}
