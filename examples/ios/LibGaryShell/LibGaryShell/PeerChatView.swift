import Combine
import CryptoKit
import SwiftUI

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

final class PeerSessionController: ObservableObject {
    @Published var pinField = ""
    @Published private(set) var normalizedPin: String = ""
    @Published private(set) var pairingPhrase: String = ""
    @Published private(set) var transport: GaryPeerTransport?
    @Published private(set) var localNickname: String = ""

    var pinLooksValid: Bool {
        PeerPairingKit.normalizePin(pinField).count >= PeerPairingKit.pinMinDigits
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
        if clearPin {
            normalizedPin = ""
            pairingPhrase = ""
            pinField = ""
        }
    }

    func startDiscovery(asHost: Bool) {
        guard !normalizedPin.isEmpty else { return }
        stopSession(clearPin: false)
        let tag = PeerPairingKit.discoveryTag(forNormalizedPin: normalizedPin)
        let nick = PeerPairingKit.randomNickname()
        localNickname = nick
        let role: GaryPeerTransport.RoomRole = asHost ? .host : .guest
        let tr = GaryPeerTransport(nickname: nick, pinDiscoveryTag: tag, role: role)
        transport = tr
        tr.startFindingPeers()
    }
}

// MARK: - Views

/// Same PIN on both devices → automatic nearby lookup (Simulator uses host/guest split).
struct PeerChatView: View {
    @StateObject private var controller = PeerSessionController()

    private var navTitle: String {
        guard let tr = controller.transport else { return "LibGary peer" }
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
        }
    }

    private var pairingGate: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Pair with someone nearby")
                    .font(.title2.weight(.semibold))

                Text("Agree on the same PIN, enter it here, then choose roles: one device **hosts** the room, the other **joins**. Use the same PIN on both.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                VStack(alignment: .leading, spacing: 8) {
                    Text("PIN")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    SecureField("4–12 digits", text: $controller.pinField)
                        .keyboardType(.numberPad)
                        .textContentType(.oneTimeCode)
                        .textFieldStyle(.roundedBorder)
                    Text("\(PeerPairingKit.normalizePin(controller.pinField).count) digits")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }

                VStack(spacing: 12) {
                    Button("Host a room") {
                        guard controller.commitPin() else { return }
                        controller.startDiscovery(asHost: true)
                    }
                    .buttonStyle(.borderedProminent)
                    .frame(maxWidth: .infinity)
                    .disabled(!controller.pinLooksValid)

                    Button("Join a room") {
                        guard controller.commitPin() else { return }
                        controller.startDiscovery(asHost: false)
                    }
                    .buttonStyle(.bordered)
                    .frame(maxWidth: .infinity)
                    .disabled(!controller.pinLooksValid)
                }

                Button("Clear PIN", role: .destructive) {
                    controller.clearPINAndSession()
                }
                .font(.caption)
                .disabled(controller.pinField.isEmpty && controller.normalizedPin.isEmpty)
            }
            .padding()
        }
        .background(Color(uiColor: .systemGroupedBackground))
    }
}

private struct ChatLine: Identifiable {
    let id = UUID()
    let author: String
    let text: String
    let fromMe: Bool
}

private struct ActivePeerSessionView: View {
    @ObservedObject var controller: PeerSessionController
    @ObservedObject var transport: GaryPeerTransport

    @State private var draft = ""
    @State private var lines: [ChatLine] = []

    private var crypto: GarySession? { transport.cryptoSession }

    private var isLinked: Bool {
        !transport.connectedPeerNames.isEmpty
    }

    var body: some View {
        Group {
            if isLinked {
                VStack(spacing: 0) {
                    List {
                        Section {
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
                    Text(transport.statusLine.isEmpty ? "Starting nearby session…" : transport.statusLine)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 28)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color(uiColor: .systemGroupedBackground))
            }
        }
        .background(Color(uiColor: .systemGroupedBackground))
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Leave") {
                    lines.removeAll()
                    controller.stopSession(clearPin: false)
                }
            }
        }
        .onAppear {
            transport.onInboundDecrypt = { peer, text in
                lines.append(ChatLine(author: peer, text: text, fromMe: false))
            }
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
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background {
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(line.fromMe ? Color.accentColor.opacity(0.18) : Color(uiColor: .tertiarySystemFill))
            }
            if !line.fromMe { Spacer(minLength: 48) }
        }
    }

    private var composer: some View {
        HStack(alignment: .bottom, spacing: 10) {
            TextField("Message", text: $draft)
                .textFieldStyle(.roundedBorder)
            Button {
                let t = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !t.isEmpty else { return }
                transport.sendChat(t)
                lines.append(ChatLine(author: "Me (\(controller.localNickname))", text: t, fromMe: true))
                draft = ""
            } label: {
                Label("Send", systemImage: "paperplane.fill")
                    .labelStyle(.titleAndIcon)
            }
            .buttonStyle(.borderedProminent)
            .disabled(!transport.canSend)
        }
        .padding()
        .background(Color(uiColor: .secondarySystemGroupedBackground))
    }
}

#Preview {
    PeerChatView()
}
