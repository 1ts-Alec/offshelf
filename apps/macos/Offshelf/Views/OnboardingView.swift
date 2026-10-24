import AppKit
import SwiftUI

/// Five steps: welcome, find the server, pair, passphrase, choose folders.
struct OnboardingView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismissWindow) private var dismissWindow
    @Environment(\.openWindow) private var openWindow

    @State private var step: Int
    // Find
    @State private var found: [ServerInfo] = []
    @State private var searching = false
    @State private var address = ""
    @State private var chosen: String?
    // Pair
    @State private var code = ""
    @State private var deviceName = Host.current().localizedName ?? "Mac"
    // Passphrase
    @State private var newShelf = true
    @State private var pass1 = ""
    @State private var pass2 = ""
    @State private var words: String?
    @State private var saved = false
    // Folders
    @State private var folders: [Folder] = []

    @State private var busy = false
    @State private var error: String?

    struct Folder: Identifiable {
        let url: URL
        var size: UInt64?
        var pin = false
        var id: URL { url }
    }

    init(step: Int = 1) {
        _step = State(initialValue: step)
    }

    private let steps = ["Welcome", "Find your shelf", "Pair this Mac", "Passphrase", "Choose folders"]

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            VStack(alignment: .leading, spacing: 20) {
                content
                Spacer(minLength: 0)
                if let error {
                    Text(error).font(.system(size: 12)).foregroundStyle(Fog.warnInk)
                }
                footer
            }
            .padding(.horizontal, 64).padding(.top, step == 1 ? 72 : 56).padding(.bottom, 40)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Fog.surface)
        .foregroundStyle(Fog.ink)
        .ignoresSafeArea()
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 28, height: 28)
                Text("Offshelf").font(.system(size: 14, weight: .semibold))
            }
            .padding(.top, 48).padding(.bottom, 28)
            ForEach(Array(steps.enumerated()), id: \.offset) { i, title in
                let n = i + 1
                HStack(spacing: 10) {
                    ZStack {
                        Circle().fill(n <= step ? Fog.accent : .clear)
                        Circle().stroke(n <= step ? Fog.accent : Fog.secondary.opacity(0.6), lineWidth: 1.5)
                        Text(n < step ? "✓" : "\(n)").font(.system(size: 11))
                            .foregroundStyle(n <= step ? Fog.onAccent : Fog.ink)
                    }
                    .frame(width: 20, height: 20)
                    Text(title).font(.system(size: 13, weight: n == step ? .semibold : .regular))
                }
                .frame(height: 28)
            }
            Spacer()
            Text(step == 4 ? "Second Mac? Just enter your passphrase." : "About two minutes.")
                .font(.system(size: 12)).foregroundStyle(Fog.secondary)
        }
        .padding(.horizontal, 28).padding(.bottom, 28)
        .frame(width: 280, alignment: .leading)
        .frame(maxHeight: .infinity, alignment: .top)
        .background(Fog.mist)
    }

    @ViewBuilder private var content: some View {
        switch step {
        case 1: welcome
        case 2: find
        case 3: pairStep
        case 4: passphrase
        default: choose
        }
    }

    // MARK: 1 Welcome

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 24) {
            Text("Keep everything.\nCarry less.").font(.display(46)).lineSpacing(2)
            Text("Files live on your server and stay in Finder.")
                .font(.system(size: 15)).foregroundStyle(Fog.secondary)
            VStack(alignment: .leading, spacing: 16) {
                point("folder", "Still in Finder", "Same folders, same names. Apps open them like local files.")
                point("waveform.path", "Only what you open travels", "Scrub a 20 GB video and only the part you watch moves.")
                point("lock", "Locked before it leaves", "Everything is encrypted on this Mac. Your server only ever sees noise.")
            }
            .padding(.top, 8)
        }
    }

    private func point(_ icon: String, _ title: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: icon).foregroundStyle(Fog.accent)
                .frame(width: 32, height: 32).background(Fog.ground).clipShape(RoundedRectangle(cornerRadius: 9))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 14, weight: .semibold))
                Text(text).font(.system(size: 13)).foregroundStyle(Fog.secondary)
            }
        }
    }

    // MARK: 2 Find

    private var find: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Find your shelf").font(.display(36))
            Text("Looking for Offshelf servers on this network. Pick yours.")
                .font(.system(size: 14)).foregroundStyle(Fog.secondary)
            VStack(spacing: 10) {
                ForEach(found, id: \.url) { s in
                    Button { chosen = s.url; address = "" } label: {
                        HStack(spacing: 14) {
                            Image(systemName: chosen == s.url ? "largecircle.fill.circle" : "circle")
                                .foregroundStyle(Fog.accent)
                            Image(systemName: "server.rack").foregroundStyle(Fog.accent)
                                .frame(width: 36, height: 36).background(Fog.ground).clipShape(RoundedRectangle(cornerRadius: 10))
                            VStack(alignment: .leading, spacing: 2) {
                                Text(URL(string: s.url)?.host ?? s.url).font(.system(size: 13, weight: .semibold))
                                Text("\(s.url) · \(s.latencyMs) ms").font(.system(size: 12)).foregroundStyle(Fog.secondary)
                            }
                            Spacer()
                            Text("Ready to pair").font(.system(size: 12)).foregroundStyle(Fog.accent)
                                .padding(.horizontal, 8).padding(.vertical, 3).background(Fog.mist).clipShape(Capsule())
                        }
                        .padding(.horizontal, 16).padding(.vertical, 14)
                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(chosen == s.url ? Fog.accent : Fog.border))
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
                if searching {
                    HStack(spacing: 8) { ProgressView().controlSize(.small); Text("Still looking…") }
                        .font(.system(size: 12)).foregroundStyle(Fog.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else if found.isEmpty {
                    Text("None found on this network. Enter its address below.")
                        .font(.system(size: 12)).foregroundStyle(Fog.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            VStack(alignment: .leading, spacing: 6) {
                Text("Or enter an address").font(.system(size: 12)).foregroundStyle(Fog.secondary)
                TextField("192.168.1.40:8740", text: $address).fogField()
                    .onChange(of: address) { _, a in if !a.isEmpty { chosen = nil } }
            }
        }
        .task { await discover() }
    }

    /// The common names a fresh Pi answers to, tried on the default port.
    private func discover() async {
        guard found.isEmpty else { return }
        searching = true
        let names = ["offshelf-pi.local", "offshelf.local", "raspberrypi.local", "pi.local"]
        let hits = await withTaskGroup(of: ServerInfo?.self) { g in
            for n in names {
                g.addTask { probeServer(url: "http://\(n):8740") }
            }
            var out: [ServerInfo] = []
            for await r in g { if let r { out.append(r) } }
            return out
        }
        found = hits.sorted { $0.latencyMs < $1.latencyMs }
        if chosen == nil { chosen = found.first?.url }
        searching = false
    }

    private var serverURL: String {
        let a = address.trimmingCharacters(in: .whitespaces)
        if !a.isEmpty { return a.contains("://") ? a : "http://" + a }
        return chosen ?? ""
    }

    // MARK: 3 Pair

    private var pairStep: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Pair this Mac").font(.display(36))
            Text("Enter a code from your server.").font(.system(size: 14)).foregroundStyle(Fog.secondary)
            HStack(spacing: 12) {
                hint("On the Pi", "oshelfd pair", mono: true)
                hint("Or from a paired device", "oshelf pair-code", mono: true)
            }
            VStack(alignment: .leading, spacing: 8) {
                Text("Pairing code").font(.system(size: 12)).foregroundStyle(Fog.secondary)
                TextField("XXXX-XXXX", text: $code)
                    .textFieldStyle(.plain)
                    .font(.system(size: 26, design: .monospaced))
                    .padding(.horizontal, 16).frame(width: 260, height: 58)
                    .background(Fog.ground)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Fog.border))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .onChange(of: code) { _, c in
                        let clean = c.uppercased().filter { $0.isLetter || $0.isNumber }.prefix(8)
                        let f = clean.count > 4 ? clean.prefix(4) + "-" + clean.dropFirst(4) : Substring(clean)
                        if f != c { code = String(f) }
                    }
            }
            VStack(alignment: .leading, spacing: 6) {
                Text("Name this Mac").font(.system(size: 12)).foregroundStyle(Fog.secondary)
                TextField("", text: $deviceName).fogField().frame(maxWidth: 360)
            }
        }
    }

    private func hint(_ title: String, _ value: String, mono: Bool) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.system(size: 12, weight: .semibold)).foregroundStyle(Fog.secondary)
            Text(value).font(.system(size: 13, design: mono ? .monospaced : .default)).textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 16).padding(.vertical, 14)
        .background(Fog.ground).clipShape(RoundedRectangle(cornerRadius: 12))
    }

    // MARK: 4 Passphrase

    @ViewBuilder private var passphrase: some View {
        if newShelf {
            VStack(alignment: .leading, spacing: 18) {
                Text("Lock your shelf").font(.display(36))
                Text("Encrypts everything. Never leaves your devices.")
                    .font(.system(size: 14)).foregroundStyle(Fog.secondary)
                if let words {
                    recoveryCard(words)
                    Toggle("I've saved my recovery key somewhere safe", isOn: $saved)
                        .toggleStyle(.checkbox).font(.system(size: 13)).tint(Fog.accent)
                } else {
                    HStack(spacing: 12) {
                        field("Passphrase") { SecureField("", text: $pass1).fogField() }
                        field("Type it again") { SecureField("", text: $pass2).fogField() }
                    }
                    HStack(spacing: 10) {
                        HStack(spacing: 4) {
                            ForEach(0..<4) { i in
                                Capsule().fill(i < strength ? Fog.accent : Fog.border).frame(width: 36, height: 4)
                            }
                        }
                        Text("\(["Too short", "Weak", "Fair", "Good", "Strong"][strength]) · stored in your Mac's Keychain")
                            .font(.system(size: 12)).foregroundStyle(Fog.secondary)
                    }
                }
            }
        } else {
            VStack(alignment: .leading, spacing: 18) {
                Text("Unlock your shelf").font(.display(36))
                Text("This shelf already exists. Enter its passphrase.")
                    .font(.system(size: 14)).foregroundStyle(Fog.secondary)
                field("Passphrase") { SecureField("", text: $pass1).fogField().onSubmit(next) }
                    .frame(maxWidth: 360)
            }
        }
    }

    private func recoveryCard(_ words: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Your recovery key").font(.system(size: 13, weight: .semibold)).foregroundStyle(Fog.warnInk)
                Spacer()
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(words, forType: .string)
                }
                .buttonStyle(SecondaryButton())
                Button("Print") { printWords(words) }.buttonStyle(SecondaryButton())
            }
            let list = words.split(separator: " ")
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), alignment: .leading), count: 4), spacing: 6) {
                ForEach(Array(list.enumerated()), id: \.offset) { i, w in
                    Text("\(i + 1). \(w)").font(.system(size: 13, design: .monospaced)).textSelection(.enabled)
                }
            }
            Text("The only way back in. Shown once.").font(.system(size: 12)).foregroundStyle(Fog.warnInk)
        }
        .padding(.horizontal, 18).padding(.vertical, 16)
        .background(Fog.warnFill)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Fog.warnBorder))
        .clipShape(RoundedRectangle(cornerRadius: 14))
    }

    private func printWords(_ words: String) {
        let text = NSTextView(frame: NSRect(x: 0, y: 0, width: 468, height: 600))
        let numbered = words.split(separator: " ").enumerated().map { "\($0.offset + 1). \($0.element)" }
        text.string = "Offshelf recovery key\n\n" + numbered.joined(separator: "\n")
        text.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        NSPrintOperation(view: text).run()
    }

    private var strength: Int {
        let p = pass1
        if p.count < 8 { return 0 }
        var score = 1
        if p.count >= 12 { score += 1 }
        if p.count >= 16 || p.contains(" ") || p.contains("-") { score += 1 }
        if Set(p).count >= 10 { score += 1 }
        return min(score, 4)
    }

    private func field(_ label: String, @ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.system(size: 12)).foregroundStyle(Fog.secondary)
            content()
        }
    }

    // MARK: 5 Choose folders

    private var choose: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("What goes on the shelf?").font(.display(36))
            Text("They upload in the background and show up in Offshelf in Finder. Your originals stay where they are.")
                .font(.system(size: 14)).foregroundStyle(Fog.secondary)
            VStack(spacing: 0) {
                HStack {
                    Text("Folder"); Spacer()
                    Text("Size").frame(width: 80, alignment: .leading)
                    Text("On this Mac").frame(width: 150, alignment: .leading)
                    Color.clear.frame(width: 20)
                }
                .font(.system(size: 11)).foregroundStyle(Fog.secondary).padding(.horizontal, 14).frame(height: 28)
                ForEach($folders) { $f in
                    HStack {
                        Text(f.url.path.replacingOccurrences(of: NSHomeDirectory(), with: "~")).font(.system(size: 13)).lineLimit(1)
                        Spacer()
                        Text(f.size.map(Format.bytes) ?? "…").font(.system(size: 12)).foregroundStyle(Fog.secondary)
                            .frame(width: 80, alignment: .leading)
                        Picker("", selection: $f.pin) {
                            Text("Stream on open").tag(false)
                            Text("Pin").tag(true)
                        }
                        .labelsHidden().pickerStyle(.segmented).frame(width: 150)
                        Button { folders.removeAll { $0.url == f.url } } label: { Image(systemName: "xmark") }
                            .buttonStyle(.plain).foregroundStyle(Fog.secondary).frame(width: 20)
                    }
                    .padding(.horizontal, 14).frame(height: 40)
                    Divider()
                }
                Button("Add a folder…", action: addFolder)
                    .buttonStyle(.plain).font(.system(size: 13)).foregroundStyle(Fog.accent)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 14).frame(height: 40)
            }
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Fog.border))
            if let s = model.settings {
                Toggle(isOn: Binding(get: { s.autoOffload }, set: { var n = s; n.autoOffload = $0; model.saveSettings(n) })) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Free up space automatically").font(.system(size: 13))
                        Text("Below \(s.thresholdPct)% free, oldest first. Skips pinned.").font(.system(size: 12)).foregroundStyle(Fog.secondary)
                    }
                }
                .toggleStyle(.switch).tint(Fog.accent)
            }
            if !folders.isEmpty {
                let total = folders.compactMap(\.size).reduce(0, +)
                Text("About \(Format.bytes(total)) will upload.").font(.system(size: 12)).foregroundStyle(Fog.secondary)
            }
        }
    }

    private func addFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = true
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser
        guard panel.runModal() == .OK else { return }
        for url in panel.urls where !folders.contains(where: { $0.url == url }) {
            folders.append(Folder(url: url))
            measure(url)
        }
    }

    private func measure(_ url: URL) {
        Task.detached {
            let total = Self.folderSize(url)
            await MainActor.run {
                if let i = folders.firstIndex(where: { $0.url == url }) { folders[i].size = total }
            }
        }
    }

    nonisolated private static func folderSize(_ url: URL) -> UInt64 {
        var total: UInt64 = 0
        let keys: [URLResourceKey] = [.totalFileAllocatedSizeKey, .isRegularFileKey]
        guard let en = FileManager.default.enumerator(at: url, includingPropertiesForKeys: keys) else { return 0 }
        while let f = en.nextObject() as? URL {
            let v = try? f.resourceValues(forKeys: Set(keys))
            if v?.isRegularFile == true { total += UInt64(v?.totalFileAllocatedSize ?? 0) }
        }
        return total
    }

    // MARK: footer and flow

    private var footer: some View {
        HStack(spacing: 10) {
            if step == 2 {
                Text("No server yet? See the Offshelf README to set up your Pi.")
                    .font(.system(size: 12)).foregroundStyle(Fog.secondary)
            } else if step == 3 {
                Text("This Mac gets its own key. You can revoke it any time.")
                    .font(.system(size: 12)).foregroundStyle(Fog.secondary)
            }
            Spacer()
            if step > 1 && step < 4 {
                Button("Back") { error = nil; step -= 1 }.buttonStyle(SecondaryButton())
            }
            if step == 5 {
                Button("Skip") { finish(upload: false) }.buttonStyle(SecondaryButton())
            }
            Button(action: next) {
                HStack(spacing: 6) {
                    if busy { ProgressView().controlSize(.small) }
                    Text(nextTitle)
                }
            }
            .buttonStyle(PrimaryButton())
            .keyboardShortcut(.defaultAction)
            .disabled(busy || !canContinue)
        }
    }

    private var nextTitle: String {
        switch step {
        case 1: return "Get started"
        case 3: return "Pair"
        case 4: return newShelf ? (words == nil ? "Create" : "Continue") : "Unlock"
        case 5: return "Start uploading"
        default: return "Continue"
        }
    }

    private var canContinue: Bool {
        switch step {
        case 2: return !serverURL.isEmpty
        case 3: return code.filter { $0 != "-" }.count == 8 && !deviceName.isEmpty
        case 4:
            if !newShelf { return !pass1.isEmpty }
            return words == nil ? (strength > 0 && pass1 == pass2) : saved
        case 5: return !folders.isEmpty
        default: return true
        }
    }

    private func next() {
        error = nil
        switch step {
        case 1:
            step = 2
        case 2:
            busy = true
            let url = serverURL
            Task.detached {
                let ok = probeServer(url: url) != nil
                await MainActor.run {
                    busy = false
                    if ok { step = 3 } else { error = "Nothing answered at \(url)." }
                }
            }
        case 3:
            busy = true
            let (home, url, c, name) = (model.homeDir, serverURL, code, deviceName)
            Task.detached {
                do {
                    _ = try pair(homeDir: home, url: url, code: c, deviceName: name)
                    let exists = try hasVault(homeDir: home)
                    await MainActor.run {
                        model.device = pairedDevice(homeDir: home)
                        newShelf = !exists
                        busy = false
                        step = 4
                    }
                } catch {
                    await MainActor.run { busy = false; self.error = describe(error) }
                }
            }
        case 4:
            if newShelf && words == nil {
                busy = true
                let (home, p) = (model.homeDir, pass1)
                Task.detached {
                    do {
                        let w = try createVault(homeDir: home, passphrase: p)
                        await MainActor.run { words = w; busy = false }
                    } catch {
                        await MainActor.run { busy = false; self.error = describe(error) }
                    }
                }
            } else {
                busy = true
                model.open(.passphrase(passphrase: pass1)) { err in
                    busy = false
                    if let err {
                        error = describe(err)
                    } else {
                        pass1 = ""; pass2 = ""; words = nil
                        step = 5
                        for d in [FileManager.SearchPathDirectory.moviesDirectory, .picturesDirectory] {
                            if let u = FileManager.default.urls(for: d, in: .userDomainMask).first {
                                folders.append(Folder(url: u))
                                measure(u)
                            }
                        }
                    }
                }
            }
        default:
            finish(upload: true)
        }
    }

    private func finish(upload: Bool) {
        if upload, let e = model.engine {
            let chosen = folders
            Task.detached {
                for f in chosen {
                    e.uploadLocal(localPath: f.url.path, to: "")
                }
            }
            for f in chosen where f.pin {
                // The folder lands on the shelf as uploads finish; pin it then.
                pinWhenPresent(f.url.lastPathComponent)
            }
        }
        dismissWindow(id: "onboarding")
        WindowOpener(openWindow: openWindow)("main")
    }

    private func pinWhenPresent(_ name: String, tries: Int = 120) {
        guard tries > 0, let e = model.engine else { return }
        Task.detached {
            if (try? e.pin(path: name)) != nil { return }
            try? await Task.sleep(for: .seconds(5))
            await MainActor.run { pinWhenPresent(name, tries: tries - 1) }
        }
    }
}
