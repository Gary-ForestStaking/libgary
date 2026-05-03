import CryptoKit
import Foundation
import Security

/// Plaintext record shape before encryption (never written to disk raw).
struct InviteTranscriptRecord: Codable {
    var messages: [PersistedChatLine]
}

struct PersistedChatLine: Codable {
    let id: UUID
    let author: String
    let text: String
    let fromMe: Bool
    let sentAt: Date
}

/// AES-GCM encrypted transcripts for invite-link rooms, keyed by host Bonjour room UUID.
enum InviteTranscriptStore {
    private static let keychainService = "dev.libgary.shell"
    private static let keychainAccount = "invite-transcript-aes-key-v1"
    private static let transcriptSubdir = "InviteTranscripts"

    static func load(roomUUID: String) -> InviteTranscriptRecord? {
        guard let sanitized = sanitizeRoomUUID(roomUUID), let url = fileURL(forSanitized: sanitized) else { return nil }
        guard let cipher = try? Data(contentsOf: url), !cipher.isEmpty else { return nil }
        guard let key = try? loadOrCreateKey() else { return nil }
        guard let sealed = try? AES.GCM.SealedBox(combined: cipher) else { return nil }
        guard let plain = try? AES.GCM.open(sealed, using: key) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(InviteTranscriptRecord.self, from: plain)
    }

    static func save(roomUUID: String, record: InviteTranscriptRecord) {
        guard let dir = transcriptsDirectory() else { return }
        guard let sanitized = sanitizeRoomUUID(roomUUID), let url = fileURL(forSanitized: sanitized) else { return }
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            guard let key = try? loadOrCreateKey() else { return }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let plain = try encoder.encode(record)
            let sealed = try AES.GCM.seal(plain, using: key)
            guard let combined = sealed.combined else { return }
            try combined.write(to: url, options: [.atomic])
        } catch {
            #if DEBUG
                print("InviteTranscriptStore save failed: \(error)")
            #endif
        }
    }

    // MARK: - Key + paths

    private static func transcriptsDirectory() -> URL? {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        return base.appendingPathComponent(transcriptSubdir, isDirectory: true)
    }

    private static func fileURL(forSanitized name: String) -> URL? {
        transcriptsDirectory()?.appendingPathComponent("\(name).lgrytranscript", isDirectory: false)
    }

    /// Allow only lowercase UUID-shaped tokens for filenames.
    private static func sanitizeRoomUUID(_ raw: String) -> String? {
        let s = raw.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        let allowed = CharacterSet(charactersIn: "0123456789abcdef-")
        guard s.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return nil }
        guard s.count <= 64 else { return nil }
        return s
    }

    private static func loadOrCreateKey() throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecSuccess, let data = out as? Data, data.count == 32 {
            return SymmetricKey(data: data)
        }
        if status != errSecItemNotFound && status != errSecSuccess {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        var raw = Data(count: 32)
        let rc = raw.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
        guard rc == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(rc))
        }
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecValueData as String: raw,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(addStatus))
        }
        return SymmetricKey(data: raw)
    }
}

// MARK: - Stable invite-host Bonjour id

/// Pins Bonjour `lgry-host-<uuid>` across restarts for invite-link hosting with the same PIN on this device, so invite URLs and local transcripts keep working after the host leaves or restarts the app.
enum InviteHostRoomIdentity {
    private static let udPrefix = "lgry.inviteHostBonjourUUID.v1."

    static func stableHostBonjourUUID(pinDiscoveryTag: String) -> String {
        let key = udPrefix + pinDiscoveryTag
        if let existing = UserDefaults.standard.string(forKey: key),
           UUID(uuidString: existing.lowercased()) != nil {
            return existing.lowercased()
        }
        let fresh = UUID().uuidString.lowercased()
        UserDefaults.standard.set(fresh, forKey: key)
        return fresh
    }

    /// Clears the saved UUID for this PIN tag so the next invite-host session advertises a new room id (new links).
    static func forgetStableUUID(pinDiscoveryTag: String) {
        UserDefaults.standard.removeObject(forKey: udPrefix + pinDiscoveryTag)
    }
}
