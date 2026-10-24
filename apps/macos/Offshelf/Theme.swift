import AppKit
import SwiftUI

/// The Fog palette from the mockups, with dark variants.
enum Fog {
    static let ground = dynamic(light: 0xF2F4F5, dark: 0x16191B)
    static let surface = dynamic(light: 0xFFFFFF, dark: 0x1E2225)
    static let sidebar = dynamic(light: 0xE9EDEF, dark: 0x191C1F)
    static let mist = dynamic(light: 0xDFE7EB, dark: 0x2A363D)
    static let accent = dynamic(light: 0x34505F, dark: 0x8FB0C2)
    static let accentPressed = dynamic(light: 0x253C48, dark: 0xA9C4D2)
    static let ink = dynamic(light: 0x1B2226, dark: 0xE8ECEE)
    static let secondary = dynamic(light: 0x4F5A60, dark: 0xA3AEB4)
    static let border = dynamic(light: 0xDCE1E4, dark: 0x2E3439)
    static let track = dynamic(light: 0xE9EDEF, dark: 0x2A2F33)
    static let macBar = dynamic(light: 0x8C9AA2, dark: 0x7D8B93)
    static let warnFill = dynamic(light: 0xFBF4E6, dark: 0x2E2617)
    static let warnBorder = dynamic(light: 0xE8D9B8, dark: 0x54452A)
    static let warnInk = dynamic(light: 0x6B4610, dark: 0xE2C38E)
    static let onAccent = dynamic(light: 0xFFFFFF, dark: 0x111618)

    private static func dynamic(light: UInt32, dark: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            return NSColor(hex: isDark ? dark : light)
        })
    }
}

extension NSColor {
    convenience init(hex: UInt32) {
        self.init(
            srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255,
            alpha: 1
        )
    }
}

extension Font {
    /// Manrope for headlines, as in the style guide; SF for everything else.
    static func display(_ size: CGFloat) -> Font {
        .custom("Manrope", size: size).weight(.bold)
    }
}

struct PrimaryButton: ButtonStyle {
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13))
            .padding(.horizontal, 18)
            .frame(minWidth: 96, minHeight: 34)
            .background(configuration.isPressed ? Fog.accentPressed : Fog.accent)
            .foregroundStyle(Fog.onAccent)
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .opacity(enabled ? 1 : 0.45)
            .contentShape(Rectangle())
    }
}

struct SecondaryButton: ButtonStyle {
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13))
            .padding(.horizontal, 14)
            .frame(minHeight: 34)
            .background(Fog.surface)
            .foregroundStyle(Fog.ink)
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Fog.border))
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .opacity(configuration.isPressed ? 0.7 : enabled ? 1 : 0.45)
            .contentShape(Rectangle())
    }
}

/// A rounded text field on the ground color, as in the onboarding mockups.
struct FogField: ViewModifier {
    func body(content: Content) -> some View {
        content
            .textFieldStyle(.plain)
            .font(.system(size: 13))
            .padding(.horizontal, 12)
            .frame(height: 36)
            .background(Fog.ground)
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Fog.border))
            .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

extension View {
    func fogField() -> some View { modifier(FogField()) }

    func card(padding: CGFloat = 16) -> some View {
        self.padding(padding)
            .background(Fog.surface)
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Fog.border))
            .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

/// A thin usage bar.
struct UsageBar: View {
    var fraction: Double
    var color: Color = Fog.accent
    var height: CGFloat = 6

    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(Fog.track)
                Capsule().fill(color).frame(width: max(0, min(1, fraction)) * g.size.width)
            }
        }
        .frame(height: height)
    }
}

/// The small rounded pill ("Home · Live").
struct Pill: View {
    var text: String
    var live: Bool = true

    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(live ? Fog.accent : Fog.secondary).frame(width: 6, height: 6)
            Text(text)
        }
        .font(.system(size: 12))
        .foregroundStyle(live ? Fog.accent : Fog.secondary)
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
        .background(Fog.mist)
        .clipShape(Capsule())
    }
}
