import AppKit
import SwiftUI

/// Where a file lives, as shown in the status column and the detail pane.
enum Place {
    case shelf, partly, local, pinned, streaming, uploading

    init(_ e: Entry, streaming: Set<String>) {
        if e.uploading { self = .uploading }
        else if e.pinned { self = .pinned }
        else if !e.isDir && streaming.contains(e.name) { self = .streaming }
        else if e.size > 0 && e.localBytes >= e.size { self = .local }
        else if e.localBytes > 0 { self = .partly }
        else { self = .shelf }
    }

    var label: String {
        switch self {
        case .shelf: return "On the shelf"
        case .partly: return "Partly on this Mac"
        case .local: return "On this Mac"
        case .pinned: return "Pinned"
        case .streaming: return "Streaming"
        case .uploading: return "Uploading"
        }
    }

    func detail(_ e: Entry) -> String {
        switch self {
        case .shelf: return "Streams on open"
        case .partly: return "Partly on this Mac · \(Format.bytes(e.localBytes))"
        case .local: return "On this Mac · can offload"
        case .pinned: return "Pinned · always on this Mac"
        case .streaming: return "Streaming · \(Format.bytes(e.localBytes)) fetched"
        case .uploading: return "Uploading"
        }
    }

    var icon: String {
        switch self {
        case .shelf: return "cloud"
        case .partly: return "circle.lefthalf.filled"
        case .local: return "checkmark.circle.fill"
        case .pinned: return "pin"
        case .streaming: return "waveform.path"
        case .uploading: return "arrow.up.circle"
        }
    }
}

struct FilesView: View {
    @EnvironmentObject var model: AppModel
    @Binding var folder: String
    @State private var entries: [Entry] = []
    @State private var selected: String?
    @State private var query = ""
    @State private var results: [String] = []
    @State private var confirm: Confirm?

    enum Confirm: Identifiable {
        case offload(Entry), pin(Entry)
        var id: String {
            switch self {
            case .offload(let e): return "o" + e.path
            case .pin(let e): return "p" + e.path
            }
        }
    }

    private var streamingNames: Set<String> { Set(model.status?.streaming.map(\.name) ?? []) }
    private var current: Entry? { entries.first { $0.path == selected } ?? entries.first }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if !query.isEmpty {
                searchResults
            } else if entries.isEmpty {
                empty
            } else {
                HStack(spacing: 0) {
                    table
                    Divider()
                    if let c = current { detailPane(c).frame(width: 260) }
                }
            }
            Divider()
            footer
        }
        .task(id: "\(folder)#\(model.revision)") { load() }
        .dropDestination(for: URL.self) { urls, _ in
            let files = urls.filter(\.isFileURL)
            guard !files.isEmpty else { return false }
            model.upload(files, to: folder)
            return true
        }
        .sheet(item: $confirm) { c in
            switch c {
            case .offload(let e): OffloadSheet(entry: e) { model.offload(e.path) }
            case .pin(let e): PinSheet(entry: e, free: model.status?.macFree ?? 0) { model.pin(e.path) }
            }
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            breadcrumbs
            Text(Format.count(UInt64(entries.count), "item")).font(.system(size: 12)).foregroundStyle(Fog.secondary)
            Spacer()
            Pill(text: model.placeLabel, live: model.status?.online ?? false)
            TextField("Search shelf", text: $query)
                .textFieldStyle(.plain).font(.system(size: 12))
                .padding(.horizontal, 10).frame(width: 180, height: 28)
                .background(Fog.ground)
                .overlay(RoundedRectangle(cornerRadius: 7).stroke(Fog.border))
                .clipShape(RoundedRectangle(cornerRadius: 7))
                .onChange(of: query) { _, q in search(q) }
        }
        .padding(.horizontal, 18).frame(height: 52)
    }

    private var breadcrumbs: some View {
        let parts = folder.split(separator: "/").map(String.init)
        return HStack(spacing: 4) {
            Button("Shelf") { folder = "" }
                .buttonStyle(.plain)
                .font(.system(size: 14, weight: parts.isEmpty ? .semibold : .regular))
                .foregroundStyle(parts.isEmpty ? Fog.ink : Fog.secondary)
            ForEach(Array(parts.enumerated()), id: \.offset) { i, p in
                Image(systemName: "chevron.right").font(.system(size: 10)).foregroundStyle(Fog.secondary)
                Button(p) { folder = parts[0...i].joined(separator: "/") }
                    .buttonStyle(.plain)
                    .font(.system(size: 14, weight: i == parts.count - 1 ? .semibold : .regular))
                    .foregroundStyle(i == parts.count - 1 ? Fog.ink : Fog.secondary)
            }
        }
    }

    private var table: some View {
        ScrollView {
            VStack(spacing: 2) {
                row(name: Text("Name"), size: "Size", modified: "Modified", icon: nil, selected: false)
                    .font(.system(size: 11)).foregroundStyle(Fog.secondary).frame(height: 28)
                ForEach(entries, id: \.path) { e in
                    let place = Place(e, streaming: streamingNames)
                    row(
                        name: Text(Image(systemName: e.isDir ? "folder" : "doc")).foregroundStyle(Fog.secondary) + Text("  ") + Text(e.name),
                        size: e.isDir && e.size == 0 ? "—" : Format.bytes(e.size),
                        modified: Format.date(ms: e.mtimeMs),
                        icon: place,
                        selected: e.path == current?.path
                    )
                    .font(.system(size: 13))
                    .frame(height: 36)
                    .contentShape(Rectangle())
                    .onTapGesture(count: 2) { if e.isDir { folder = e.path } else { model.showInFinder(e.path) } }
                    .onTapGesture { selected = e.path }
                    .contextMenu { menu(e) }
                }
            }
            .padding(8)
        }
    }

    private func row(name: Text, size: String, modified: String, icon: Place?, selected: Bool) -> some View {
        HStack(spacing: 12) {
            name.lineLimit(1).truncationMode(.middle).frame(maxWidth: .infinity, alignment: .leading)
            Text(size).foregroundStyle(Fog.secondary).frame(width: 90, alignment: .leading)
            Text(modified).foregroundStyle(Fog.secondary).frame(width: 110, alignment: .leading)
            Group {
                if let icon {
                    Image(systemName: icon.icon)
                        .foregroundStyle(icon == .shelf ? Fog.secondary : Fog.accent)
                        .help(icon.label)
                        .accessibilityLabel(icon.label)
                } else { Color.clear }
            }
            .frame(width: 28)
        }
        .padding(.horizontal, 14)
        .frame(maxHeight: .infinity)
        .background(selected ? Fog.mist : .clear)
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    @ViewBuilder private func menu(_ e: Entry) -> some View {
        if e.pinned {
            Button("Unpin") { model.unpin(e.path) }
        } else {
            Button("Pin to this Mac") { confirm = .pin(e) }
        }
        Button("Offload from this Mac") { confirm = .offload(e) }.disabled(e.localBytes == 0)
        Divider()
        Button("Show in Finder") { model.showInFinder(e.path) }
    }

    private func detailPane(_ e: Entry) -> some View {
        let place = Place(e, streaming: streamingNames)
        return VStack(alignment: .leading, spacing: 14) {
            Image(systemName: e.isDir ? "folder" : "doc")
                .font(.system(size: 30)).foregroundStyle(Fog.accent)
                .frame(width: 56, height: 56).background(Fog.ground).clipShape(RoundedRectangle(cornerRadius: 12))
            VStack(alignment: .leading, spacing: 4) {
                Text(e.name).font(.system(size: 14, weight: .semibold)).lineLimit(3)
                Text(place.detail(e)).font(.system(size: 12)).foregroundStyle(Fog.secondary)
            }
            VStack(spacing: 8) {
                fact("Size", Format.bytes(e.size))
                fact("On this Mac", Format.bytes(e.localBytes))
                fact("Modified", Format.date(ms: e.mtimeMs))
                if e.isDir { fact("Items", "\(e.itemCount)") }
            }
            .font(.system(size: 12))
            VStack(spacing: 8) {
                if e.pinned {
                    Button { model.unpin(e.path) } label: { wide("Unpin") }.buttonStyle(SecondaryButton())
                } else {
                    Button { confirm = .pin(e) } label: { wide("Pin to this Mac") }.buttonStyle(PrimaryButton())
                }
                Button { confirm = .offload(e) } label: { wide("Offload from this Mac") }
                    .buttonStyle(SecondaryButton()).disabled(e.localBytes == 0)
                Button { model.showInFinder(e.path) } label: { wide("Show in Finder") }.buttonStyle(SecondaryButton())
            }
            Spacer()
        }
        .padding(18)
        .background(Fog.surface)
    }

    private func wide(_ title: String) -> some View {
        Text(title).frame(maxWidth: .infinity)
    }

    private func fact(_ a: String, _ b: String) -> some View {
        HStack { Text(a).foregroundStyle(Fog.secondary); Spacer(); Text(b) }
    }

    private var empty: some View {
        VStack(spacing: 10) {
            Spacer()
            Text(folder.isEmpty ? "Nothing on the shelf yet" : "This folder is empty").font(.display(20))
            Text("Drag a folder here, or choose which folders Offshelf should hold.")
                .font(.system(size: 13)).foregroundStyle(Fog.secondary)
            HStack {
                Button("Choose folders…", action: chooseFolders).buttonStyle(PrimaryButton())
                Button("Show in Finder") { model.showInFinder(folder) }.buttonStyle(SecondaryButton())
            }
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var searchResults: some View {
        Group {
            if results.isEmpty {
                VStack(spacing: 8) {
                    Spacer()
                    Text("No names match").font(.display(20))
                    Text("Searches names only.").font(.system(size: 13)).foregroundStyle(Fog.secondary)
                    Button("Clear search") { query = "" }.buttonStyle(SecondaryButton())
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                List(results, id: \.self) { p in
                    Button {
                        let parent = p.split(separator: "/").dropLast().joined(separator: "/")
                        query = ""
                        folder = parent
                        selected = p
                    } label: {
                        Text(p).font(.system(size: 13)).frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .buttonStyle(.plain)
                }
                .scrollContentBackground(.hidden)
            }
        }
    }

    private var footer: some View {
        HStack(spacing: 14) {
            if let s = model.status {
                if let f = s.streaming.first {
                    Label("Streaming \(f.name) · \(Format.rate(s.streamRate)) · \(Format.bytes(f.fetched)) read of \(Format.bytes(f.size))", systemImage: "waveform.path")
                        .lineLimit(1)
                }
                if s.uploadingFiles > 0 {
                    Text("Uploading \(s.uploadingFiles) · \(Format.bytes(s.uploadingBytes)) left")
                }
                Spacer()
                Text(s.online ? "Tree is live · revision \(s.revision.formatted())" : "Offline · last verified \(Format.time(ms: s.lastVerifiedMs))")
            }
        }
        .font(.system(size: 12)).foregroundStyle(Fog.secondary)
        .padding(.horizontal, 18).frame(height: 40)
    }

    private func chooseFolders() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Upload"
        guard panel.runModal() == .OK else { return }
        model.upload(panel.urls, to: folder)
    }

    private func load() {
        guard let e = model.engine else { return }
        let f = folder
        Task.detached {
            let list = (try? e.list(path: f)) ?? []
            await MainActor.run {
                if f == folder { entries = list }
            }
        }
    }

    private func search(_ q: String) {
        guard let e = model.engine, !q.isEmpty else { results = []; return }
        Task.detached {
            let r = e.search(query: q, limit: 200)
            await MainActor.run { if q == query { results = r } }
        }
    }
}

struct OffloadSheet: View {
    let entry: Entry
    let confirm: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Offload “\(entry.name)”?").font(.display(20))
            Text("Frees \(Format.bytes(entry.localBytes)). Stays in Finder.")
                .font(.system(size: 13)).foregroundStyle(Fog.secondary)
            if entry.pinned {
                Text("This also unpins it.").font(.system(size: 12)).foregroundStyle(Fog.secondary)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.buttonStyle(SecondaryButton()).keyboardShortcut(.cancelAction)
                Button("Offload") { confirm(); dismiss() }.buttonStyle(PrimaryButton()).keyboardShortcut(.defaultAction)
            }
        }
        .padding(24).frame(width: 380).background(Fog.surface)
    }
}

struct PinSheet: View {
    let entry: Entry
    let free: UInt64
    let confirm: () -> Void
    @Environment(\.dismiss) private var dismiss

    private var needed: UInt64 { entry.size > entry.localBytes ? entry.size - entry.localBytes : 0 }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if needed > free {
                Text("Not enough space to pin").font(.display(20))
                Text("Needs \(Format.bytes(needed)), \(Format.bytes(free)) free.")
                    .font(.system(size: 13)).foregroundStyle(Fog.secondary)
                HStack { Spacer(); Button("OK") { dismiss() }.buttonStyle(PrimaryButton()).keyboardShortcut(.defaultAction) }
            } else {
                Text("Pin “\(entry.name)”?").font(.display(20))
                Text("Always on this Mac, even offline.").font(.system(size: 13)).foregroundStyle(Fog.secondary)
                VStack(spacing: 6) {
                    HStack { Text("Download"); Spacer(); Text(Format.bytes(needed)) }
                    HStack { Text("This Mac after"); Spacer(); Text("\(Format.bytes(free - needed)) free") }
                }
                .font(.system(size: 12)).foregroundStyle(Fog.secondary)
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }.buttonStyle(SecondaryButton()).keyboardShortcut(.cancelAction)
                    Button("Pin") { confirm(); dismiss() }.buttonStyle(PrimaryButton()).keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(24).frame(width: 380).background(Fog.surface)
    }
}
