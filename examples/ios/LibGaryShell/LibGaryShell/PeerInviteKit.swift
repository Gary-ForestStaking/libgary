import Foundation

/// Local invite links (`libgaryshell://join`) carry the normalized PIN plus an opaque host room id
/// (Bonjour instance UUID). Same LAN still required; the link disambiguates hosts sharing a PIN.
enum PeerInviteKit {
    static let scheme = "libgaryshell"
    static let authority = "join"

    struct ParsedInvite: Equatable {
        let pinNormalized: String
        /// Lowercase UUID string from `lgry-host-<uuid>` when present.
        let roomUUID: String?
    }

    static func makeInviteURL(pinNormalized: String, roomUUID: String) -> URL? {
        let pin = PeerPairingKit.normalizePin(pinNormalized)
        guard pin.count >= PeerPairingKit.pinMinDigits else { return nil }
        let room = roomUUID.lowercased()
        guard UUID(uuidString: room) != nil else { return nil }
        var c = URLComponents()
        c.scheme = scheme
        c.host = authority
        c.queryItems = [
            URLQueryItem(name: "pin", value: pin),
            URLQueryItem(name: "room", value: room),
        ]
        return c.url
    }

    static func parseInviteURL(_ url: URL) -> ParsedInvite? {
        guard url.scheme?.lowercased() == scheme else { return nil }
        guard url.host?.lowercased() == authority else { return nil }
        guard let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems else { return nil }
        guard let pinRaw = items.first(where: { $0.name.lowercased() == "pin" })?.value else { return nil }
        let pin = PeerPairingKit.normalizePin(pinRaw)
        guard pin.count >= PeerPairingKit.pinMinDigits else { return nil }
        let roomComponent = items.first(where: { $0.name.lowercased() == "room" })?.value
        let roomRaw = roomComponent?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let room: String?
        if let r = roomRaw, !r.isEmpty {
            guard UUID(uuidString: r) != nil else { return nil }
            room = r
        } else {
            room = nil
        }
        return ParsedInvite(pinNormalized: pin, roomUUID: room)
    }
}
