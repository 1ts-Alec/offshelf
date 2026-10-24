import SwiftUI

/// The addresses of your shelf and when to use each: first match wins, then
/// falls back down the list.
struct HostsView: View {
    @EnvironmentObject var model: AppModel
    @State private var editing: Int?
    @State private var draft = HostRule(name: "", url: "", ssids: [])
    @State private var newSsid = ""
    @State private var test: String?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Hosts").font(.system(size: 14, weight: .semibold))
                Spacer()
                Button("Add host") {
                    var h = model.hosts
                    h.append(HostRule(name: "Away", url: "https://", ssids: []))
                    model.saveHosts(h)
                    select(h.count - 1)
                }
                .buttonStyle(SecondaryButton())
            }
            .padding(.horizontal, 18).frame(height: 52)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("First match wins, then falls back down the list.")
                        .font(.system(size: 12)).foregroundStyle(Fog.secondary)
                    VStack(spacing: 8) {
                        ForEach(Array(model.hosts.enumerated()), id: \.offset) { i, h in
                            hostRow(i, h)
                        }
                    }
                    rightNow
                    if editing != nil { editor }
                }
                .padding(18)
            }
        }
    }

    private func hostRow(_ i: Int, _ h: HostRule) -> some View {
        let inUse = model.status?.hostUrl == h.url && model.status?.online == true
        return HStack(spacing: 12) {
            Image(systemName: h.ssids.isEmpty ? "globe" : "house")
                .foregroundStyle(Fog.accent).frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(h.name).font(.system(size: 13, weight: .semibold))
                Text("\(h.url) · \(rule(h))").font(.system(size: 12)).foregroundStyle(Fog.secondary).lineLimit(1)
            }
            Spacer()
            if inUse {
                Pill(text: "In use" + (model.status?.latencyMs.map { " · \($0) ms" } ?? ""))
            } else {
                Text(matches(h) ? "Standby" : "Not matched").font(.system(size: 12)).foregroundStyle(Fog.secondary)
            }
            VStack(spacing: 0) {
                Button { move(i, -1) } label: { Image(systemName: "chevron.up") }.disabled(i == 0)
                Button { move(i, 1) } label: { Image(systemName: "chevron.down") }.disabled(i == model.hosts.count - 1)
            }
            .buttonStyle(.plain).font(.system(size: 10)).foregroundStyle(Fog.secondary)
        }
        .padding(14)
        .background(editing == i ? Fog.mist : Fog.surface)
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Fog.border))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .contentShape(Rectangle())
        .onTapGesture { select(i) }
    }

    private var rightNow: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Right now").font(.system(size: 13, weight: .semibold))
            let wifi = model.status?.ssid ?? (model.wifi.authorized ? "not on Wi-Fi" : "unknown")
            Text("Wi-Fi: \(wifi) · Location: \(model.wifi.authorized ? "allowed" : "not allowed")")
            Text("Health checks every 15 s · tree revision \((model.status?.revision ?? 0).formatted()), \(model.status?.online == true ? "live" : "offline")")
        }
        .font(.system(size: 12)).foregroundStyle(Fog.secondary)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14).background(Fog.ground).clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var editor: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(draft.name.isEmpty ? "Host" : draft.name).font(.display(18))
            labeled("Name") { TextField("Home", text: $draft.name).fogField() }
            labeled("Address") { TextField("http://192.168.1.40:8740", text: $draft.url).fogField() }
            labeled("Use when") {
                VStack(alignment: .leading, spacing: 8) {
                    if draft.ssids.isEmpty {
                        Text("Anywhere (no Wi-Fi rule)").font(.system(size: 12)).foregroundStyle(Fog.secondary)
                    }
                    ForEach(draft.ssids, id: \.self) { s in
                        HStack {
                            Text("Wi-Fi is \(s)").font(.system(size: 13))
                            Button { draft.ssids.removeAll { $0 == s } } label: { Image(systemName: "xmark") }
                                .buttonStyle(.plain).foregroundStyle(Fog.secondary)
                        }
                        .padding(.horizontal, 10).padding(.vertical, 5)
                        .background(Fog.mist).clipShape(Capsule())
                    }
                    HStack {
                        TextField("Add a Wi-Fi network", text: $newSsid).fogField()
                            .onSubmit(addSsid)
                        if let current = model.status?.ssid, !draft.ssids.contains(current) {
                            Button("Use “\(current)”") { newSsid = current; addSsid() }.buttonStyle(SecondaryButton())
                        }
                    }
                }
            }
            HStack {
                Button("Test now") {
                    let url = draft.url
                    test = "Testing…"
                    Task.detached {
                        let r = probeServer(url: url)
                        await MainActor.run { test = r.map { "\($0.latencyMs) ms" } ?? "No answer" }
                    }
                }
                .buttonStyle(SecondaryButton())
                if let test { Text(test).font(.system(size: 12)).foregroundStyle(Fog.secondary) }
                Spacer()
                if model.hosts.count > 1 {
                    Button("Remove") {
                        guard let i = editing else { return }
                        var h = model.hosts
                        h.remove(at: i)
                        model.saveHosts(h)
                        editing = nil
                    }
                    .buttonStyle(SecondaryButton())
                }
                Button("Save") {
                    guard let i = editing else { return }
                    var h = model.hosts
                    h[i] = draft
                    model.saveHosts(h)
                }
                .buttonStyle(PrimaryButton())
            }
        }
        .card(padding: 18)
    }

    private func labeled(_ label: String, @ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.system(size: 12)).foregroundStyle(Fog.secondary)
            content()
        }
    }

    private func addSsid() {
        let s = newSsid.trimmingCharacters(in: .whitespaces)
        if !s.isEmpty && !draft.ssids.contains(s) { draft.ssids.append(s) }
        newSsid = ""
    }

    private func select(_ i: Int) {
        editing = i
        draft = model.hosts[i]
        test = nil
    }

    private func move(_ i: Int, _ d: Int) {
        var h = model.hosts
        h.swapAt(i, i + d)
        model.saveHosts(h)
        if editing == i { editing = i + d }
    }

    private func matches(_ h: HostRule) -> Bool {
        h.ssids.isEmpty || h.ssids.contains(model.status?.ssid ?? "\u{0}")
    }

    private func rule(_ h: HostRule) -> String {
        h.ssids.isEmpty ? "anywhere else" : "when Wi-Fi is " + h.ssids.joined(separator: " or ")
    }
}
