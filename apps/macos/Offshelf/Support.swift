import CoreLocation
import CoreWLAN
import Foundation
import Security

/// Where the app keeps its state.
enum Paths {
    static let support: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("Offshelf", isDirectory: true)
    }()

    /// Pairing: device id, signing key, pinned server key.
    static let device = support.appendingPathComponent("device", isDirectory: true)
    /// Chunk cache, unsent writes, engine settings.
    static let data = support.appendingPathComponent("data", isDirectory: true)
    /// The mount. Finder shows it by this folder's name.
    static let mount = support.appendingPathComponent("Volume/Offshelf", isDirectory: true)
}

/// The master key, kept in the login Keychain so launches skip the passphrase.
enum Keychain {
    private static let service = "dev.offshelf.Offshelf"
    private static let account = "master-key"

    static func load() -> Data? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ]
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    static func save(_ key: Data) {
        delete()
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrLabel as String: "Offshelf master key",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: key,
        ]
        SecItemAdd(q as CFDictionary, nil)
    }

    static func delete() {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(q as CFDictionary)
    }
}

/// The current Wi-Fi network name. macOS only reveals it to apps allowed to
/// use Location, so this asks for that once.
final class WiFi: NSObject, CLLocationManagerDelegate {
    private let location = CLLocationManager()
    var onChange: ((String?) -> Void)?
    private var last: String??
    private var timer: Timer?

    var authorized: Bool {
        location.authorizationStatus == .authorizedAlways
    }

    func start() {
        location.delegate = self
        if location.authorizationStatus == .notDetermined {
            location.requestWhenInUseAuthorization()
        }
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in self?.poll() }
    }

    var ssid: String? {
        CWWiFiClient.shared().interface()?.ssid()
    }

    func poll() {
        let now = ssid
        if last == nil || last! != now {
            last = .some(now)
            onChange?(now)
        }
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        last = nil
        poll()
    }
}

enum Format {
    private static let byteFormatter: ByteCountFormatter = {
        let f = ByteCountFormatter()
        f.countStyle = .file
        f.allowsNonnumericFormatting = false
        return f
    }()

    static func bytes(_ n: UInt64) -> String {
        byteFormatter.string(fromByteCount: Int64(clamping: n))
    }

    static func rate(_ n: UInt64) -> String { bytes(n) + "/s" }

    static func date(ms: Int64) -> String {
        let d = Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        let cal = Calendar.current
        if cal.isDateInToday(d) {
            return "Today " + d.formatted(date: .omitted, time: .shortened)
        }
        if cal.isDateInYesterday(d) {
            return "Yesterday"
        }
        return d.formatted(.dateTime.day().month(.abbreviated))
    }

    static func time(ms: Int64) -> String {
        Date(timeIntervalSince1970: TimeInterval(ms) / 1000).formatted(date: .omitted, time: .shortened)
    }

    static func count(_ n: UInt64, _ one: String, _ many: String? = nil) -> String {
        "\(n.formatted()) \(n == 1 ? one : (many ?? one + "s"))"
    }
}

extension OffshelfError {
    var message: String {
        switch self {
        case .Failed(let m): return m
        case .WrongPassphrase: return "That passphrase doesn't open this shelf."
        case .NotFound(let p): return "\(p) isn't on the shelf anymore."
        }
    }
}

func describe(_ error: Error) -> String {
    (error as? OffshelfError)?.message ?? error.localizedDescription
}
