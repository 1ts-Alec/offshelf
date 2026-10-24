import SwiftUI

/// The menu bar popover: where the shelf is, how full things are, and
/// what's moving.
struct PopoverView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Offshelf").font(.display(15))
                Spacer()
                Text(model.status?.online == false ? "Offline" : "Live")
                    .font(.system(size: 12))
                    .foregroundStyle(model.status?.online == false ? Fog.secondary : Fog.accent)
            }
            switch model.phase {
            case .running:
                running
            case .locked:
                notice("Locked", "Enter your passphrase to open your shelf.", button: "Unlock…") { open("unlock") }
            case .onboarding:
                notice("Not set up", "Pair this Mac with your shelf.", button: "Set up…") { open("onboarding") }
            case .starting:
                HStack(spacing: 8) { ProgressView().controlSize(.small); Text("Opening your shelf…") }
                    .font(.system(size: 13)).foregroundStyle(Fog.secondary)
            case .failed(let m):
                notice("Couldn't open your shelf", m, button: "Try again") { model.launch() }
            }
            Divider()
            HStack {
                Button("Quit Offshelf") { model.quit() }
                    .buttonStyle(.plain).font(.system(size: 12)).foregroundStyle(Fog.secondary)
                Spacer()
            }
        }
        .padding(16)
        .frame(width: 340)
        .background(Fog.surface)
    }

    @ViewBuilder private var running: some View {
        let s = model.status
        if let s, !s.online {
            VStack(alignment: .leading, spacing: 4) {
                Text("Can't reach your shelf").font(.system(size: 13, weight: .semibold))
                Text("Retrying in the background").font(.system(size: 12)).foregroundStyle(Fog.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 14).padding(.vertical, 12)
            .background(Fog.mist).clipShape(RoundedRectangle(cornerRadius: 10))
            VStack(alignment: .leading, spacing: 4) {
                Text("Pinned and cached files still open normally.")
                Text("Folder listings may be out of date. Last verified \(Format.time(ms: s.lastVerifiedMs)).")
                if s.uploadingFiles > 0 {
                    Text("\(Format.count(s.uploadingFiles, "change")) saved here, they'll upload when you're back.")
                }
            }
            .font(.system(size: 12)).foregroundStyle(Fog.secondary)
        } else {
            HStack(spacing: 12) {
                Image(systemName: model.isHome ? "house" : "globe")
                    .font(.system(size: 17)).foregroundStyle(Fog.accent).frame(width: 20)
                VStack(alignment: .leading, spacing: 2) {
                    Text(s?.hostName.isEmpty == false ? s!.hostName : "Home").font(.system(size: 13, weight: .semibold))
                    Text(hostLine).font(.system(size: 12)).foregroundStyle(Fog.secondary)
                }
                Spacer()
            }
            .padding(.horizontal, 14).padding(.vertical, 12)
            .background(Fog.mist).clipShape(RoundedRectangle(cornerRadius: 10))
        }
        VStack(alignment: .leading, spacing: 6) {
            if let u = model.usage, let total = u.diskTotal, let free = u.diskFree, total > 0 {
                row("Shelf", "\(Format.bytes(total - free)) of \(Format.bytes(total))")
                UsageBar(fraction: Double(total - free) / Double(total))
            }
            if let s, s.macTotal > 0 {
                row("This Mac", "\(Format.bytes(s.macFree)) free").padding(.top, 6)
                UsageBar(fraction: Double(s.macTotal - s.macFree) / Double(s.macTotal), color: Fog.macBar)
            }
        }
        .font(.system(size: 12))
        if let s, !s.streaming.isEmpty || s.uploadingFiles > 0 {
            VStack(alignment: .leading, spacing: 2) {
                if !s.streaming.isEmpty {
                    Text("Streaming \(Format.count(UInt64(s.streaming.count), "file")) · \(Format.rate(s.streamRate))")
                }
                if s.uploadingFiles > 0 {
                    Text("Uploading \(Format.count(s.uploadingFiles, "file")) · \(Format.bytes(s.uploadingBytes)) left")
                }
            }
            .font(.system(size: 12)).foregroundStyle(Fog.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 12)
            .overlay(alignment: .top) { Divider() }
        }
        HStack(spacing: 8) {
            Button("Open Offshelf") { open("main") }.buttonStyle(PrimaryButton()).frame(maxWidth: .infinity)
            if s?.online == false {
                Button("Try again") { model.reconnect() }.buttonStyle(SecondaryButton())
            } else {
                Button("Show in Finder") { model.showInFinder("") }.buttonStyle(SecondaryButton())
            }
        }
    }

    private var hostLine: String {
        guard let s = model.status else { return "" }
        let host = URL(string: s.hostUrl)?.host ?? s.hostUrl
        if let ms = s.latencyMs { return "\(host) · \(ms) ms" }
        return host
    }

    private func row(_ a: String, _ b: String) -> some View {
        HStack { Text(a); Spacer(); Text(b).foregroundStyle(Fog.secondary) }
    }

    private func notice(_ title: String, _ detail: String, button: String, action: @escaping () -> Void) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.system(size: 13, weight: .semibold))
            Text(detail).font(.system(size: 12)).foregroundStyle(Fog.secondary)
            Button(button, action: action).buttonStyle(PrimaryButton())
        }
    }

    private func open(_ id: String) {
        WindowOpener(openWindow: openWindow)(id)
    }
}
