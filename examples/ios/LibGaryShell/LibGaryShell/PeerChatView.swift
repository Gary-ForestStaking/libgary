import Combine
import CoreImage
import CoreImage.CIFilterBuiltins
import CryptoKit
import SwiftUI
import UIKit

// MARK: - PIN pairing (declared before views so Xcode always resolves symbols)

enum PeerPairingKit {
    static let pinMinDigits = 4
    static let pinMaxDigits = 12

    static func normalizePin(_ raw: String) -> String {
        let digits = raw.filter(\.isNumber)
        return String(digits.prefix(pinMaxDigits))
    }

    static func discoveryTag(forNormalizedPin pin: String) -> String {
        let payload = Data("lgry-pin-v1|".utf8) + Data(pin.utf8)
        let h = SHA256.hash(data: payload)
        return Data(h.prefix(8)).hexDumpLowercase()
    }

    static func pairingPhrase(forNormalizedPin pin: String) -> String {
        let payload = Data("lgry-shell-sas-v1|".utf8) + Data(pin.utf8)
        let h = SHA256.hash(data: payload)
        let prefix = Data(h.prefix(6))
        return stride(from: 0, to: prefix.count, by: 2).map { i in
            let hi = prefix[i]
            let lo = prefix[i + 1]
            return String(format: "%02x%02x", hi, lo)
        }.joined(separator: " · ")
    }

    private static let adjectives = [
        "Calm", "Swift", "Quiet", "Bright", "Gentle", "Clever", "Warm", "Bold",
        "Soft", "Quick", "Cool", "Kind",
    ]

    private static let nouns = [
        "River", "Harbor", "Maple", "Comet", "Otter", "Harrier", "Cedar", "Pebble",
        "Anchor", "Beacon", "Summit", "Orchard",
    ]

    static func randomNickname() -> String {
        let tag = String(UUID().uuidString.prefix(5)).lowercased()
        return "\(adjectives.randomElement()!) \(nouns.randomElement()!) \(tag)"
    }
}

/// Public LibGary relay (`libgary-relay` crate). Invite-link sessions use this instead of Bonjour.
enum PeerRelayKit {
    static let webSocketURL = URL(string: "wss://lgry.monmilios.com/ws")!
}

/// How the user entered the session — drives invite QR chrome and copy.
enum RoomSessionKind: Equatable {
    /// PIN + Bonjour near me; host UI does not emphasize share links.
    case disposable
    /// User chose invite-link flow; host gets QR/share while waiting.
    case inviteLink
}

final class PeerSessionController: ObservableObject {
    @Published var pinField = ""
    @Published private(set) var normalizedPin: String = ""
    @Published private(set) var pairingPhrase: String = ""
    @Published private(set) var transport: GaryPeerTransport?
    @Published private(set) var localNickname: String = ""
    @Published private(set) var sessionKind: RoomSessionKind = .disposable

    var pinLooksValid: Bool {
        PeerPairingKit.normalizePin(pinField).count >= PeerPairingKit.pinMinDigits
    }

    /// Short SAS-style phrase from the digits you typed (updates before Host/Join).
    var previewPairingPhrase: String {
        let n = PeerPairingKit.normalizePin(pinField)
        guard n.count >= PeerPairingKit.pinMinDigits else { return "" }
        return PeerPairingKit.pairingPhrase(forNormalizedPin: n)
    }

    func commitPin() -> Bool {
        let n = PeerPairingKit.normalizePin(pinField)
        guard n.count >= PeerPairingKit.pinMinDigits else { return false }
        normalizedPin = n
        pairingPhrase = PeerPairingKit.pairingPhrase(forNormalizedPin: n)
        return true
    }

    func clearPINAndSession() {
        stopSession(clearPin: true)
    }

    func stopSession(clearPin: Bool = false) {
        transport?.stopAll(clearStatus: true)
        transport = nil
        localNickname = ""
        sessionKind = .disposable
        if clearPin {
            normalizedPin = ""
            pairingPhrase = ""
            pinField = ""
        }
    }

    func startDiscovery(
        asHost: Bool,
        preferredGuestHostRoomUUID: String? = nil,
        sessionKind kind: RoomSessionKind = .disposable
    ) {
        guard !normalizedPin.isEmpty else { return }
        stopSession(clearPin: false)
        sessionKind = kind
        let tag = PeerPairingKit.discoveryTag(forNormalizedPin: normalizedPin)
        let nick = PeerPairingKit.randomNickname()
        localNickname = nick
        let role: GaryPeerTransport.RoomRole = asHost ? .host : .guest
        let prefBonjour: String?
        if asHost {
            prefBonjour = nil
        } else {
            prefBonjour = preferredGuestHostRoomUUID.map { "lgry-host-\($0.lowercased())" }
        }
        let stableHostUUID: String? =
            (asHost && kind == .inviteLink) ? InviteHostRoomIdentity.stableHostBonjourUUID(pinDiscoveryTag: tag) : nil
        let relayURL = kind == .inviteLink ? PeerRelayKit.webSocketURL : nil
        let tr = GaryPeerTransport(
            nickname: nick,
            pinDiscoveryTag: tag,
            role: role,
            preferredHostBonjourName: prefBonjour,
            stableHostBonjourUUID: stableHostUUID,
            relayWebSocketURL: relayURL
        )
        transport = tr
        tr.startFindingPeers()
    }

    /// Opens `libgaryshell://join?…` — fills PIN, optional targeted host, and starts joining.
    @discardableResult
    func applyInviteURL(_ url: URL) -> Bool {
        guard let parsed = PeerInviteKit.parseInviteURL(url) else { return false }
        transport?.stopAll(clearStatus: true)
        transport = nil
        sessionKind = .inviteLink
        pinField = parsed.pinNormalized
        normalizedPin = parsed.pinNormalized
        pairingPhrase = PeerPairingKit.pairingPhrase(forNormalizedPin: normalizedPin)
        localNickname = PeerPairingKit.randomNickname()
        let tag = PeerPairingKit.discoveryTag(forNormalizedPin: normalizedPin)
        let pref = parsed.roomUUID.map { "lgry-host-\($0)" }
        let tr = GaryPeerTransport(
            nickname: localNickname,
            pinDiscoveryTag: tag,
            role: .guest,
            preferredHostBonjourName: pref,
            relayWebSocketURL: PeerRelayKit.webSocketURL
        )
        transport = tr
        tr.startFindingPeers()
        return true
    }
}

// MARK: - Views

/// Same PIN on both devices → automatic nearby lookup (Simulator uses host/guest split).
struct PeerChatView: View {
    private enum GatePhase: Equatable {
        case pickRoomKind
        case disposablePickRole
        case disposablePin(asHost: Bool)
        case invitePickRole
        case inviteHostPin
        case inviteGuestPaste
    }

    @StateObject private var controller = PeerSessionController()
    @State private var gatePhase: GatePhase = .pickRoomKind
    @State private var invitePasteField = ""
    @State private var invitePasteError: String?

    private var navTitle: String {
        guard let tr = controller.transport else {
            switch gatePhase {
            case .pickRoomKind:
                return "LibGary peer"
            case .disposablePickRole:
                return "Disposable"
            case .disposablePin(let asHost):
                return asHost ? "Host" : "Join"
            case .invitePickRole:
                return "Invite link"
            case .inviteHostPin:
                return "Host"
            case .inviteGuestPaste:
                return "Join link"
            }
        }
        return tr.isRoomHost ? "Hosting" : "Joining"
    }

    var body: some View {
        NavigationStack {
            Group {
                if let tr = controller.transport {
                    ActivePeerSessionView(controller: controller, transport: tr)
                } else {
                    pairingGate
                }
            }
            .navigationTitle(navTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if controller.transport == nil, gatePhase != .pickRoomKind {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Back") {
                            switch gatePhase {
                            case .pickRoomKind:
                                break
                            case .disposablePickRole:
                                gatePhase = .pickRoomKind
                            case .disposablePin:
                                gatePhase = .disposablePickRole
                                controller.pinField = ""
                            case .invitePickRole:
                                gatePhase = .pickRoomKind
                            case .inviteHostPin:
                                gatePhase = .invitePickRole
                                controller.pinField = ""
                            case .inviteGuestPaste:
                                gatePhase = .invitePickRole
                                invitePasteField = ""
                                invitePasteError = nil
                            }
                        }
                        .accessibilityHint("Go back one step.")
                    }
                }
            }
            .onOpenURL { controller.applyInviteURL($0) }
            .onChange(of: controller.transport != nil) { _, sessionActive in
                if !sessionActive {
                    gatePhase = .pickRoomKind
                    invitePasteField = ""
                    invitePasteError = nil
                }
            }
        }
    }

    private var pairingGate: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                switch gatePhase {
                case .pickRoomKind:
                    pickRoomKindPage
                case .disposablePickRole:
                    disposablePickRolePage
                case .disposablePin(let asHost):
                    disposablePinPage(asHost: asHost)
                case .invitePickRole:
                    invitePickRolePage
                case .inviteHostPin:
                    inviteHostPinPage
                case .inviteGuestPaste:
                    inviteGuestPastePage
                }
            }
            .padding()
        }
        .background(Color(uiColor: .systemGroupedBackground))
    }

    private var pickRoomKindPage: some View {
        Group {
            Text("How do you want to connect?")
                .font(.title2.weight(.semibold))

            Text("Same Wi‑Fi for both paths. Pick what fits your hangout.")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            VStack(spacing: 12) {
                Button("Disposable room") {
                    gatePhase = .disposablePickRole
                }
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)
                .accessibilityHint("Quick PIN pairing near me. No share link on the host screen.")

                Button("Invite link room") {
                    gatePhase = .invitePickRole
                }
                .buttonStyle(.bordered)
                .frame(maxWidth: .infinity)
                .accessibilityHint("Host shares a QR or link so guests can join the same Bonjour room.")

                Text("Invite links still need the same LAN and don’t save chat by themselves — they’re easier for guests to open later from Messages.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Button("Clear PIN", role: .destructive) {
                controller.clearPINAndSession()
            }
            .font(.caption)
            .disabled(controller.pinField.isEmpty && controller.normalizedPin.isEmpty)
            .accessibilityLabel("Clear saved PIN")
        }
    }

    private var disposablePickRolePage: some View {
        Group {
            Text("Disposable room")
                .font(.title2.weight(.semibold))

            Text("Pick host or join — you’ll enter the PIN next. No invite link step on the host screen.")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            disposableRoomCaption()

            Group {
                Text("Checklist")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 6) {
                    checklistRow("Host starts first, then join with the same PIN.")
                    checklistRow("Same Wi‑Fi helps; two Simulators on one Mac work too.")
                    checklistRow("Compare pairing phrases before trusting chat.")
                    checklistRow("Rooms are disposable — leaving ends the session; chat isn’t saved.")
                }
            }

            VStack(spacing: 12) {
                Button("Host a room") {
                    gatePhase = .disposablePin(asHost: true)
                }
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)

                Button("Join a room") {
                    gatePhase = .disposablePin(asHost: false)
                }
                .buttonStyle(.bordered)
                .frame(maxWidth: .infinity)
            }

            Button("Clear PIN", role: .destructive) {
                controller.clearPINAndSession()
            }
            .font(.caption)
            .disabled(controller.pinField.isEmpty && controller.normalizedPin.isEmpty)
            .accessibilityLabel("Clear saved PIN")
        }
    }

    private func disposablePinPage(asHost: Bool) -> some View {
        Group {
            Text(asHost ? "Hosting — shared PIN" : "Joining — shared PIN")
                .font(.title3.weight(.semibold))

            Text("Enter the PIN you agreed with your friend, then continue.")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            disposableRoomCaption()

            pinFieldsAndPhrase

            Button(asHost ? "Start hosting" : "Join room") {
                guard controller.commitPin() else { return }
                controller.startDiscovery(asHost: asHost, sessionKind: .disposable)
            }
            .buttonStyle(.borderedProminent)
            .frame(maxWidth: .infinity)
            .disabled(!controller.pinLooksValid)
        }
    }

    private var invitePickRolePage: some View {
        Group {
            Text("Invite link room")
                .font(.title2.weight(.semibold))

            Text("Host gets a QR and share link after entering a PIN. Guests can open a link or paste it here.")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            inviteLinkHonestCaption()

            VStack(spacing: 12) {
                Button("Host and share a link") {
                    gatePhase = .inviteHostPin
                }
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)

                Button("Join with a link") {
                    gatePhase = .inviteGuestPaste
                    invitePasteError = nil
                }
                .buttonStyle(.bordered)
                .frame(maxWidth: .infinity)
            }

            Button("Clear PIN", role: .destructive) {
                controller.clearPINAndSession()
            }
            .font(.caption)
            .disabled(controller.pinField.isEmpty && controller.normalizedPin.isEmpty)
        }
    }

    private var inviteHostPinPage: some View {
        Group {
            Text("Hosting — shareable link")
                .font(.title3.weight(.semibold))

            Text("Enter a PIN, then you’ll get a QR and link to send your guest.")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            inviteLinkHonestCaption()

            pinFieldsAndPhrase

            Button("Start hosting") {
                guard controller.commitPin() else { return }
                controller.startDiscovery(asHost: true, sessionKind: .inviteLink)
            }
            .buttonStyle(.borderedProminent)
            .frame(maxWidth: .infinity)
            .disabled(!controller.pinLooksValid)
        }
    }

    private var inviteGuestPastePage: some View {
        Group {
            Text("Join from invite")
                .font(.title3.weight(.semibold))

            Text("Paste the `libgaryshell://…` link from your host (Messages, Notes, etc.).")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            inviteLinkHonestCaption()

            TextField("Invite URL", text: $invitePasteField, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .lineLimit(2 ... 5)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()

            if let invitePasteError {
                Text(invitePasteError)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            HStack(spacing: 12) {
                Button("Paste from clipboard") {
                    if let s = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines), !s.isEmpty {
                        invitePasteField = s
                        invitePasteError = nil
                    }
                }
                .buttonStyle(.bordered)

                Button("Join from link") {
                    tryJoinFromPastedLink()
                }
                .buttonStyle(.borderedProminent)
            }

            Text("Tip: opening the link from another app still switches here automatically when LibGary is installed.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
    }

    private func tryJoinFromPastedLink() {
        let raw = invitePasteField.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: raw), controller.applyInviteURL(url) else {
            invitePasteError = "Couldn’t read that link. Copy the full libgaryshell:// URL."
            return
        }
        invitePasteError = nil
    }

    private var pinFieldsAndPhrase: some View {
        Group {
            VStack(alignment: .leading, spacing: 8) {
                Text("PIN")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                SecureField("4–12 digits", text: $controller.pinField)
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("PIN, 4 to 12 digits")
                Text("\(PeerPairingKit.normalizePin(controller.pinField).count) digits")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            if !controller.previewPairingPhrase.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Pairing phrase (compare with the other device)")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    Text(controller.previewPairingPhrase)
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(uiColor: .secondarySystemGroupedBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                        .accessibilityLabel("Pairing phrase \(controller.previewPairingPhrase)")
                }
            }
        }
    }

    private func checklistRow(_ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: "checkmark.circle")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(text)
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }

    /// Sets expectations: no persistence; session ends on leave.
    private func disposableRoomCaption() -> some View {
        Text("Disposable room — it ends when someone leaves. Messages aren’t saved after you disconnect.")
            .font(.caption)
            .foregroundStyle(.tertiary)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityLabel("Disposable room. It ends when someone leaves. Messages are not saved after disconnect.")
    }

    /// Honest framing: invite transcripts stay on-device encrypted; still LAN-only for live chat.
    private func inviteLinkHonestCaption() -> some View {
        Text("Live chat goes through lgry.monmilios.com over TLS (relay). On this device, invite rooms keep an encrypted transcript until you delete app data — this sample does not upload chat to the cloud.")
            .font(.caption)
            .foregroundStyle(.tertiary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

private struct ChatLine: Identifiable {
    let id: UUID
    let author: String
    let text: String
    let fromMe: Bool
    let sentAt: Date

    init(id: UUID = UUID(), author: String, text: String, fromMe: Bool, sentAt: Date) {
        self.id = id
        self.author = author
        self.text = text
        self.fromMe = fromMe
        self.sentAt = sentAt
    }
}

private struct ActivePeerSessionView: View {
    private static let messageCharLimit = 4096

    @ObservedObject var controller: PeerSessionController
    @ObservedObject var transport: GaryPeerTransport

    @State private var draft = ""
    @State private var lines: [ChatLine] = []
    @State private var confirmLeave = false

    private var crypto: GarySession? { transport.cryptoSession }

    private var isLinked: Bool {
        !transport.connectedPeerNames.isEmpty
    }

    private var persistInviteTranscript: Bool {
        controller.sessionKind == .inviteLink && transport.invitePersistentRoomUUID != nil
    }

    private var linkedHonestyBannerText: String {
        switch controller.sessionKind {
        case .disposable:
            return "Disposable — this chat isn’t stored. Leaving ends the room."
        case .inviteLink:
            return "Invite link — messages stay on this device, encrypted; not on a cloud server. Same Wi‑Fi for live chat."
        }
    }

    private var waitingHonestyCaptionText: String {
        switch controller.sessionKind {
        case .disposable:
            return "Disposable room — ends when you leave; chat isn’t saved."
        case .inviteLink:
            return "Invite link — earlier messages on this phone load below (encrypted on disk). Same Wi‑Fi to connect live."
        }
    }

    private static let listTimeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.timeStyle = .short
        f.dateStyle = .none
        return f
    }()

    private func loadInviteTranscriptIfNeeded() {
        guard persistInviteTranscript, let uuid = transport.invitePersistentRoomUUID else { return }
        guard let rec = InviteTranscriptStore.load(roomUUID: uuid) else { return }
        lines = rec.messages.map { ChatLine(id: $0.id, author: $0.author, text: $0.text, fromMe: $0.fromMe, sentAt: $0.sentAt) }
    }

    private func persistInviteLinesIfNeeded() {
        guard persistInviteTranscript, let uuid = transport.invitePersistentRoomUUID else { return }
        let msgs = lines.map { PersistedChatLine(id: $0.id, author: $0.author, text: $0.text, fromMe: $0.fromMe, sentAt: $0.sentAt) }
        InviteTranscriptStore.save(roomUUID: uuid, record: InviteTranscriptRecord(messages: msgs))
    }

    private var inviteLinkedEmptyBlurb: String {
        "No new messages yet.\nSay hello below.\nOlder messages on this device stay encrypted until you delete app data."
    }

    var body: some View {
        Group {
            if isLinked {
                VStack(spacing: 0) {
                    Text(linkedHonestyBannerText)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                        .padding(.horizontal, 12)
                        .background(Color(uiColor: .secondarySystemGroupedBackground))

                    List {
                        Section {
                            if lines.isEmpty {
                                Text(
                                    persistInviteTranscript
                                        ? inviteLinkedEmptyBlurb
                                        : "No messages yet.\nSay hello below.\nNothing here is saved after you leave."
                                )
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                                    .multilineTextAlignment(.center)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 28)
                                    .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
                                    .listRowSeparator(.hidden)
                                    .listRowBackground(Color.clear)
                                    .accessibilityLabel(
                                        persistInviteTranscript
                                            ? "No new messages yet. Say hello below. Older messages on this device stay encrypted until you delete app data."
                                            : "No messages yet. Say hello below. Chat is not saved after you leave."
                                    )
                            }
                            ForEach(lines) { line in
                                bubble(line)
                                    .listRowInsets(EdgeInsets(top: 6, leading: 12, bottom: 6, trailing: 12))
                                    .listRowSeparator(.hidden)
                                    .listRowBackground(Color.clear)
                            }
                        }
                    }
                    .listStyle(.plain)

                    if let sr = transport.lastSendRc, sr != GARY_CODE_OK {
                        Text("Pack/send rc=\(sr) \(crypto?.lastErrorCString() ?? "")")
                            .font(.caption2.monospaced())
                            .foregroundStyle(.red)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal)
                    }
                    if let rr = transport.lastRecvRc, rr != GARY_CODE_OK {
                        Text("Ingest rc=\(rr) \(crypto?.lastErrorCString() ?? "")")
                            .font(.caption2.monospaced())
                            .foregroundStyle(.orange)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal)
                    }

                    composer
                }
            } else {
                VStack(spacing: 20) {
                    ProgressView()
                        .controlSize(.large)
                        .scaleEffect(1.35)
                        .accessibilityLabel("Connecting")
                    Text(waitingHonestyCaptionText)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                    Text(transport.statusLine.isEmpty ? "Starting nearby session…" : transport.statusLine)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 28)
                        .accessibilityHint("Connection progress for nearby pairing.")

                    if persistInviteTranscript, !lines.isEmpty {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Earlier messages on this device")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity)
                            ScrollView {
                                LazyVStack(spacing: 10) {
                                    ForEach(lines) { line in
                                        bubble(line)
                                    }
                                }
                                .padding(.horizontal, 10)
                                .padding(.vertical, 8)
                            }
                            .frame(maxHeight: 220)
                            .background(Color(uiColor: .secondarySystemGroupedBackground))
                            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                        }
                        .padding(.horizontal, 16)
                    }

                    if !controller.pairingPhrase.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Verify pairing phrase")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity)
                            Text(controller.pairingPhrase)
                                .font(.body.monospaced())
                                .multilineTextAlignment(.center)
                                .frame(maxWidth: .infinity)
                                .textSelection(.enabled)
                        }
                        .padding(.horizontal, 24)
                    }

                    if transport.isRoomHost,
                       controller.sessionKind == .inviteLink,
                       let inviteURL = transport.inviteURL(pinNormalized: controller.normalizedPin) {
                        HostInviteShareSection(inviteURL: inviteURL)
                    }

                    Text("Local Network access must be allowed in Settings if pairing stalls.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)

                    if !transport.isRoomHost {
                        Button("Retry scan") {
                            transport.retryGuestDiscovery()
                        }
                        .buttonStyle(.bordered)
                        .accessibilityLabel("Retry scan for hosts")
                        .accessibilityHint("Stops and starts browsing again with the same PIN.")
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color(uiColor: .systemGroupedBackground))
            }
        }
        .background(Color(uiColor: .systemGroupedBackground))
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Leave") {
                    confirmLeave = true
                }
                .accessibilityHint(
                    persistInviteTranscript
                        ? "Ends the live session. Encrypted transcript stays on this device."
                        : "Ends this room. Chat is not saved."
                )
            }
        }
        .alert("Leave this session?", isPresented: $confirmLeave) {
            Button("Cancel", role: .cancel) {}
            Button("Leave", role: .destructive) {
                lines.removeAll()
                controller.stopSession(clearPin: false)
            }
        } message: {
            Text(
                controller.sessionKind == .inviteLink
                    ? "Live chat stops when you leave. Invite-link messages stay encrypted on this device until you delete app data — they are not uploaded by this app. Your PIN stays filled unless you clear it on the previous screen."
                    : "This disposable room ends when you leave. Messages aren’t stored — they disappear from this app. Your PIN stays filled unless you clear it on the previous screen."
            )
        }
        .onAppear {
            loadInviteTranscriptIfNeeded()
            transport.onInboundDecrypt = { peer, text in
                lines.append(ChatLine(author: peer, text: text, fromMe: false, sentAt: Date()))
                persistInviteLinesIfNeeded()
            }
        }
        .onChange(of: isLinked) { _, linked in
            guard linked else { return }
            if persistInviteTranscript {
                persistInviteLinesIfNeeded()
            }
            let generator = UINotificationFeedbackGenerator()
            generator.notificationOccurred(.success)
        }
    }

    private func bubble(_ line: ChatLine) -> some View {
        HStack {
            if line.fromMe { Spacer(minLength: 48) }
            VStack(alignment: line.fromMe ? .trailing : .leading, spacing: 4) {
                Text(line.author)
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(line.text)
                    .font(.body)
                    .textSelection(.enabled)
                    .multilineTextAlignment(line.fromMe ? .trailing : .leading)
                Text(Self.listTimeFormatter.string(from: line.sentAt))
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background {
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(line.fromMe ? Color.accentColor.opacity(0.18) : Color(uiColor: .tertiarySystemFill))
            }
            if !line.fromMe { Spacer(minLength: 48) }
        }
        .accessibilityElement(children: .combine)
    }

    private var composer: some View {
        let remaining = max(0, Self.messageCharLimit - draft.count)
        return VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .bottom, spacing: 10) {
                TextField("Message", text: $draft, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .lineLimit(1 ... 6)
                    .submitLabel(.send)
                    .onSubmit { sendDraftIfPossible() }
                    .onChange(of: draft) { _, newValue in
                        if newValue.count > Self.messageCharLimit {
                            draft = String(newValue.prefix(Self.messageCharLimit))
                        }
                    }
                    .accessibilityLabel("Message text")
                Button(action: sendDraftIfPossible) {
                    Label("Send", systemImage: "paperplane.fill")
                        .labelStyle(.titleAndIcon)
                }
                .buttonStyle(.borderedProminent)
                .disabled(!transport.canSend || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .accessibilityHint("Sends the encrypted message.")
            }
            Text("\(remaining) characters left")
                .font(.caption2)
                .foregroundStyle(remaining < 200 ? Color.orange : Color.secondary)
                .accessibilityLabel("\(remaining) characters remaining")
        }
        .padding()
        .background(Color(uiColor: .secondarySystemGroupedBackground))
    }

    private func sendDraftIfPossible() {
        var t = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, transport.canSend else { return }
        if t.count > Self.messageCharLimit {
            t = String(t.prefix(Self.messageCharLimit))
        }
        transport.sendChat(t)
        lines.append(ChatLine(author: "Me (\(controller.localNickname))", text: t, fromMe: true, sentAt: Date()))
        persistInviteLinesIfNeeded()
        draft = ""
    }
}

// MARK: - Invite QR + share

private struct InviteQRCodeView: View {
    let payload: String
    private let side: CGFloat = 200

    var body: some View {
        Group {
            if let img = Self.render(payload: payload, side: side) {
                Image(uiImage: img)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: side, height: side)
            } else {
                Image(systemName: "qrcode")
                    .font(.system(size: 48))
                    .foregroundStyle(.tertiary)
            }
        }
        .accessibilityLabel("Invite QR code")
        .accessibilityHint("Contains your PIN and room id. Share only with a trusted guest on the same network.")
    }

    private static func render(payload: String, side: CGFloat) -> UIImage? {
        guard let data = payload.data(using: .utf8), data.count <= 2953 else { return nil }
        let filter = CIFilter.qrCodeGenerator()
        filter.message = data
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scale = side / output.extent.width
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let ctx = CIContext()
        guard let cg = ctx.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}

private struct HostInviteShareSection: View {
    let inviteURL: URL

    var body: some View {
        VStack(spacing: 14) {
            Text("Invite guest")
                .font(.subheadline.weight(.semibold))

            InviteQRCodeView(payload: inviteURL.absoluteString)

            ShareLink(item: inviteURL) {
                Label("Share invite link", systemImage: "square.and.arrow.up")
            }
            .buttonStyle(.borderedProminent)

            Button {
                UIPasteboard.general.url = inviteURL
            } label: {
                Label("Copy link", systemImage: "doc.on.doc")
            }
            .buttonStyle(.bordered)

            Text("Uses the LibGary relay at lgry.monmilios.com (no Bonjour). The link carries your PIN and this phone’s room id — same link when you host again with this PIN here.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(16)
        .frame(maxWidth: .infinity)
        .background(Color(uiColor: .secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .padding(.horizontal, 20)
    }
}

#Preview {
    PeerChatView()
}
