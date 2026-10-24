import SwiftUI

enum Section: Hashable {
    case files
    case activity
    case hosts
    case settings
    case pinned(String)
}

/// The main window: sidebar with Files, Activity, Hosts, Settings and the
/// pinned folders, plus shelf and Mac usage at the bottom.
struct MainWindow: View {
    @EnvironmentObject var model: AppModel
    @State private var section: Section
    @State private var folder: String
    @State private var pins: [Entry] = []

    init(section: Section = .files, folder: String = "") {
        _section = State(initialValue: section)
        _folder = State(initialValue: folder)
    }

    var body: some View {
        Group {
            if model.phase == .running {
                HStack(spacing: 0) {
                    sidebar
                    Divider()
                    detail.frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            } else {
                VStack(spacing: 12) {
                    Text("Offshelf isn't open yet").font(.display(22))
                    Text("Use the menu bar icon to set up or unlock your shelf.")
                        .foregroundStyle(Fog.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .background(Fog.surface)
        .foregroundStyle(Fog.ink)
        // Run under the hidden title bar: the window controls sit on the
        // sidebar, with no separate strip above the content.
        .ignoresSafeArea()
        .task(id: model.revision) { loadPins() }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 2) {
            item(.files, "Files", "folder")
            item(.activity, "Activity", "waveform.path.ecg", badge: model.status?.uploadingFiles ?? 0)
            item(.hosts, "Hosts", "server.rack")
            item(.settings, "Settings", "gearshape")
            if !pins.isEmpty {
                Text("Pinned")
                    .font(.system(size: 11, weight: .semibold)).foregroundStyle(Fog.secondary)
                    .padding(.horizontal, 10).padding(.top, 18).padding(.bottom, 4)
                ForEach(pins, id: \.path) { p in
                    item(.pinned(p.path), p.name, "pin")
                }
            }
            Spacer()
            usage
        }
        .padding(.horizontal, 10)
        .padding(.top, 44)
        .padding(.bottom, 14)
        .frame(width: 210)
        .background(Fog.sidebar)
    }

    private func item(_ s: Section, _ title: String, _ icon: String, badge: UInt64 = 0) -> some View {
        let on = section == s
        return Button {
            if case .pinned(let p) = s {
                folder = p
                section = .files
            } else {
                if s == .files && section == .files { folder = "" }
                section = s
            }
        } label: {
            HStack(spacing: 8) {
                Image(systemName: icon).foregroundStyle(on ? Fog.accent : Fog.secondary).frame(width: 16)
                Text(title).lineLimit(1)
                Spacer()
                if badge > 0 {
                    Text("\(badge)").font(.system(size: 11)).foregroundStyle(Fog.secondary)
                }
            }
            .font(.system(size: 13, weight: on ? .semibold : .regular))
            .padding(.horizontal, 10)
            .frame(height: 28)
            .background(on ? Fog.mist : .clear)
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var usage: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let u = model.usage, let total = u.diskTotal, let free = u.diskFree, total > 0 {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Shelf · \(Format.bytes(total - free)) of \(Format.bytes(total))")
                    UsageBar(fraction: Double(total - free) / Double(total), height: 4)
                }
            }
            if let s = model.status {
                Text("This Mac · \(Format.bytes(s.macFree)) free")
            }
        }
        .font(.system(size: 11)).foregroundStyle(Fog.secondary)
        .padding(10)
    }

    @ViewBuilder private var detail: some View {
        switch section {
        case .files, .pinned: FilesView(folder: $folder)
        case .activity: ActivityView()
        case .hosts: HostsView()
        case .settings: SettingsView()
        }
    }

    private func loadPins() {
        guard let e = model.engine else { return }
        Task.detached {
            // Pinned folders sit anywhere; walk the top two levels for them.
            var found: [Entry] = []
            let top = (try? e.list(path: "")) ?? []
            for t in top {
                if t.pinned { found.append(t); continue }
                if t.isDir, let kids = try? e.list(path: t.path) {
                    found += kids.filter { $0.pinned }
                }
            }
            let result = found
            await MainActor.run { pins = result }
        }
    }
}
