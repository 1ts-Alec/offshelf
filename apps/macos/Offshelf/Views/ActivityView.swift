import SwiftUI

struct ActivityView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Activity").font(.system(size: 14, weight: .semibold))
                Spacer()
                Pill(text: model.placeLabel, live: model.status?.online ?? false)
            }
            .padding(.horizontal, 18).frame(height: 52)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    now
                    earlier
                }
                .padding(18)
            }
        }
    }

    @ViewBuilder private var now: some View {
        let s = model.status
        let streaming = s?.streaming ?? []
        if !streaming.isEmpty || (s?.uploadingFiles ?? 0) > 0 {
            heading("Now")
            ForEach(streaming, id: \.name) { f in
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: "waveform.path").foregroundStyle(Fog.accent)
                        Text(f.name).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                        Spacer()
                        Text(Format.rate(s?.streamRate ?? 0)).font(.system(size: 12)).foregroundStyle(Fog.secondary)
                    }
                    UsageBar(fraction: f.size == 0 ? 0 : Double(f.fetched) / Double(f.size), height: 4)
                    Text("\(Format.bytes(f.fetched)) fetched of \(Format.bytes(f.size)) · only what's read moves")
                        .font(.system(size: 12)).foregroundStyle(Fog.secondary)
                }
                .card()
            }
            if let s, s.uploadingFiles > 0 {
                HStack {
                    Image(systemName: "arrow.up.circle").foregroundStyle(Fog.accent)
                    Text("Uploading \(Format.count(s.uploadingFiles, "file"))").font(.system(size: 13, weight: .semibold))
                    Spacer()
                    Text("\(Format.bytes(s.uploadingBytes)) left").font(.system(size: 12)).foregroundStyle(Fog.secondary)
                }
                .card()
            }
        }
    }

    @ViewBuilder private var earlier: some View {
        if model.events.isEmpty {
            Text("Nothing yet. Uploads, pins, offloads and network switches show up here.")
                .font(.system(size: 13)).foregroundStyle(Fog.secondary)
        } else {
            heading("Recent")
            VStack(spacing: 0) {
                ForEach(Array(model.events.enumerated()), id: \.offset) { i, e in
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: icon(e.kind))
                            .foregroundStyle(e.kind == .error || e.kind == .conflict ? Fog.warnInk : Fog.accent)
                            .frame(width: 18)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(e.title).font(.system(size: 13, weight: .semibold))
                            Text(e.detail).font(.system(size: 12)).foregroundStyle(Fog.secondary).lineLimit(2)
                        }
                        Spacer()
                        Text(Format.time(ms: e.timeMs)).font(.system(size: 12)).foregroundStyle(Fog.secondary)
                    }
                    .padding(.vertical, 10)
                    if i < model.events.count - 1 { Divider() }
                }
            }
            .padding(.horizontal, 16)
            .background(Fog.surface)
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Fog.border))
        }
    }

    private func heading(_ t: String) -> some View {
        Text(t).font(.system(size: 11, weight: .semibold)).foregroundStyle(Fog.secondary)
    }

    private func icon(_ k: EventKindFfi) -> String {
        switch k {
        case .uploaded: return "arrow.up.circle"
        case .pinned: return "pin"
        case .offloaded: return "arrow.down.right.and.arrow.up.left"
        case .switched: return "arrow.triangle.swap"
        case .synced: return "checkmark.circle"
        case .conflict: return "exclamationmark.2"
        case .offline: return "wifi.slash"
        case .online: return "wifi"
        case .error: return "exclamationmark.triangle"
        }
    }
}
