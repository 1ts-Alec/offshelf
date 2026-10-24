import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var s = EngineSettings(cacheCap: 50_000_000_000, autoOffload: true, thresholdPct: 15, offloadBiggestFirst: false)
    @State private var offloadable: UInt64 = 0
    @State private var changingPassphrase = false
    @State private var confirmUnpair = false
    @State private var confirmOffloadAll = false

    var body: some View {
        VStack(spacing: 0) {
            HStack { Text("Settings").font(.system(size: 14, weight: .semibold)); Spacer() }
                .padding(.horizontal, 18).frame(height: 52)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    group("Space on this Mac") {
                        toggleRow("Free up space automatically", "Offload when free space drops below the threshold", $s.autoOffload)
                        row("Threshold", thresholdDetail) {
                            Picker("", selection: $s.thresholdPct) {
                                ForEach([5, 10, 15, 20, 25, 30] as [UInt8], id: \.self) { Text("\($0)%").tag($0) }
                            }
                            .labelsHidden().frame(width: 90)
                        }
                        row("Offload first", "Pinned folders are never offloaded") {
                            Picker("", selection: $s.offloadBiggestFirst) {
                                Text("Oldest opened").tag(false)
                                Text("Biggest").tag(true)
                            }
                            .pickerStyle(.segmented).labelsHidden().frame(width: 200)
                        }
                        row("Streaming cache", "Recently streamed bytes kept for fast reopen · \(Format.bytes(model.status?.cacheBytes ?? 0)) used") {
                            Picker("", selection: $s.cacheCap) {
                                Text("20 GB").tag(UInt64(20_000_000_000))
                                Text("50 GB").tag(UInt64(50_000_000_000))
                                Text("100 GB").tag(UInt64(100_000_000_000))
                            }
                            .pickerStyle(.segmented).labelsHidden().frame(width: 200)
                        }
                        row("Offload everything not pinned", "Frees about \(Format.bytes(offloadable)) right now") {
                            Button("Offload now…") { confirmOffloadAll = true }.buttonStyle(SecondaryButton())
                        }
                    }
                    group("Finder") {
                        row("Offshelf in Finder", "Mounted at \(model.status?.mountedAt ?? Paths.mount.path)") {
                            Button("Show in Finder") { model.showInFinder("") }.buttonStyle(SecondaryButton())
                        }
                    }
                    group("Encryption") {
                        row("Passphrase", "Stored in your Keychain on this Mac") {
                            Button("Change…") { changingPassphrase = true }.buttonStyle(SecondaryButton())
                        }
                    }
                    group("This Mac") {
                        row("Device name", model.device?.deviceName ?? "") { EmptyView() }
                        row("Paired with \(URL(string: model.device?.serverUrl ?? "")?.host ?? "your shelf")",
                            "Key ends in \(String((model.device?.deviceId ?? "").suffix(4)).uppercased())") {
                            Button("Unpair…") { confirmUnpair = true }.buttonStyle(SecondaryButton())
                        }
                    }
                    group("General") {
                        toggleRow("Open at login", "", Binding(get: { model.openAtLogin }, set: { model.openAtLogin = $0 }))
                        row("Version", "Offshelf \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "")") { EmptyView() }
                    }
                }
                .padding(18)
            }
        }
        .onAppear {
            if let cur = model.settings { s = cur }
            refreshOffloadable()
        }
        .onChange(of: s.autoOffload) { _, _ in model.saveSettings(s) }
        .onChange(of: s.thresholdPct) { _, _ in model.saveSettings(s) }
        .onChange(of: s.offloadBiggestFirst) { _, _ in model.saveSettings(s) }
        .onChange(of: s.cacheCap) { _, _ in model.saveSettings(s) }
        .sheet(isPresented: $changingPassphrase) { PassphraseSheet() }
        .alert("Unpair this Mac?", isPresented: $confirmUnpair) {
            Button("Cancel", role: .cancel) {}
            Button("Unpair", role: .destructive) { model.signOut() }
        } message: {
            Text("Offshelf unmounts and forgets this shelf here. Files on the shelf stay put, and unsent changes stay in the app's folder.")
        }
        .alert("Offload everything not pinned?", isPresented: $confirmOffloadAll) {
            Button("Cancel", role: .cancel) {}
            Button("Offload") {
                model.run { _ = $0.offloadAll() }
                offloadable = 0
            }
        } message: {
            Text("Frees about \(Format.bytes(offloadable)). Everything stays in Finder and streams on open.")
        }
    }

    private var thresholdDetail: String {
        guard let st = model.status, st.macTotal > 0 else { return "" }
        let pct = Int(Double(st.macFree) / Double(st.macTotal) * 100)
        return "Currently \(pct)% free (\(Format.bytes(st.macFree)))"
    }

    private func refreshOffloadable() {
        guard let e = model.engine else { return }
        Task.detached {
            let n = e.offloadableBytes()
            await MainActor.run { offloadable = n }
        }
    }

    private func group(_ title: String, @ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(title).font(.system(size: 11, weight: .semibold)).foregroundStyle(Fog.secondary).padding(.bottom, 8)
            VStack(spacing: 0) { content() }
                .padding(.horizontal, 16)
                .background(Fog.surface)
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(Fog.border))
                .clipShape(RoundedRectangle(cornerRadius: 12))
        }
    }

    private func row(_ title: String, _ detail: String, @ViewBuilder _ trailing: () -> some View) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13))
                if !detail.isEmpty {
                    Text(detail).font(.system(size: 12)).foregroundStyle(Fog.secondary).lineLimit(2)
                }
            }
            Spacer()
            trailing()
        }
        .padding(.vertical, 12)
        .overlay(alignment: .bottom) { Rectangle().fill(Fog.border).frame(height: 1).opacity(0.6) }
    }

    private func toggleRow(_ title: String, _ detail: String, _ on: Binding<Bool>) -> some View {
        row(title, detail) { Toggle("", isOn: on).toggleStyle(.switch).labelsHidden().tint(Fog.accent) }
    }
}

struct PassphraseSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var a = ""
    @State private var b = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Change passphrase").font(.display(20))
            Text("Your files stay as they are; only the lock on your key changes.")
                .font(.system(size: 13)).foregroundStyle(Fog.secondary)
            SecureField("New passphrase", text: $a).fogField()
            SecureField("Type it again", text: $b).fogField()
            if let error { Text(error).font(.system(size: 12)).foregroundStyle(Fog.warnInk) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.buttonStyle(SecondaryButton()).keyboardShortcut(.cancelAction)
                Button(busy ? "Changing…" : "Change") {
                    guard a.count >= 8 else { error = "Use at least 8 characters."; return }
                    guard a == b else { error = "The two don't match."; return }
                    guard let e = model.engine else { return }
                    busy = true
                    let p = a
                    Task.detached {
                        do {
                            try e.changePassphrase(newPassphrase: p)
                            await MainActor.run { dismiss() }
                        } catch {
                            await MainActor.run { self.error = describe(error); busy = false }
                        }
                    }
                }
                .buttonStyle(PrimaryButton()).keyboardShortcut(.defaultAction).disabled(busy)
            }
        }
        .padding(24).frame(width: 400).background(Fog.surface)
    }
}

struct UnlockView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismissWindow) private var dismissWindow
    @State private var secret = ""
    @State private var recovery = false
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Unlock your shelf").font(.display(26))
            Text(recovery ? "Enter your 24 recovery words." : "Enter your passphrase. It stays in this Mac's Keychain after this.")
                .font(.system(size: 13)).foregroundStyle(Fog.secondary)
            HStack(spacing: 10) {
                SecureField(recovery ? "Recovery words" : "Passphrase", text: $secret)
                    .fogField()
                    .onSubmit(unlock)
                Button(busy ? "Unlocking…" : "Unlock", action: unlock)
                    .buttonStyle(PrimaryButton()).disabled(busy || secret.isEmpty)
            }
            if let error { Text(error).font(.system(size: 12)).foregroundStyle(Fog.warnInk) }
            Button(recovery ? "Use passphrase instead" : "Use recovery words instead") {
                recovery.toggle(); secret = ""; error = nil
            }
            .buttonStyle(.plain).font(.system(size: 12)).foregroundStyle(Fog.accent)
            Spacer()
        }
        .padding(.horizontal, 32).padding(.top, 44).padding(.bottom, 24)
        .background(Fog.surface)
        .foregroundStyle(Fog.ink)
        .ignoresSafeArea()
    }

    private func unlock() {
        guard !secret.isEmpty else { return }
        busy = true
        error = nil
        let u: UnlockWith = recovery ? .recoveryWords(words: secret) : .passphrase(passphrase: secret)
        model.open(u) { err in
            busy = false
            if let err {
                error = describe(err)
                model.phase = .locked
            } else {
                dismissWindow(id: "unlock")
            }
        }
    }
}
