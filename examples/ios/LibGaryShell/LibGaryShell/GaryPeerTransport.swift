import Combine
import Foundation
import Network

/// Bonjour + TCP (`Network.framework`).
/// **Host** advertises and accepts TCP (`pairedResponder`). **Guest** browses and connects (`pairedInitiator`).
/// Payload: length-prefixed raw `OuterRecord` (`gary_send_utf8_data_outer` / `gary_ingest_outer`).
final class GaryPeerTransport: ObservableObject {
    enum RoomRole {
        case host
        case guest
    }
    /// Matches `Info.plist` `NSBonjourServices`
    private static let bonjourType = "_lgry-peer-v1._tcp"
    private static let handshakeMagic = Data([0x4C, 0x47, 0x52, 0x59]) // "LGRY"
    private static let okayMagic = Data([0x4F, 0x4B, 0x41, 0x59]) // "OKAY"

    private var crypto: GarySession?
    @Published private(set) var cryptoSession: GarySession?
    @Published private(set) var canSend = false

    private let pinDiscoveryTag: String
    private let displayNickname: String
    private let role: RoomRole
    /// Host advertises `lgry-host-<uuid>` so guests only open TCP to real rooms (not stray browse noise).
    private let bonjourInstanceName: String
    /// Guest: optional exact `lgry-host-…` Bonjour name from an invite link.
    private let preferredHostBonjourName: String?

    /// When set, skip Bonjour/TCP and use `libgary-relay` (`wss`) — opaque binary tunnel after JSON join.
    private let relayWebSocketURL: URL?
    private var urlSession: URLSession?
    private var webSocketTask: URLSessionWebSocketTask?
    private var relayLinked = false

    /// `true` when this run chose “Host a room” (listener side).
    var isRoomHost: Bool { role == .host }

    private let queue = DispatchQueue(label: "dev.libgary.peer.tcp")

    private var listener: NWListener?
    private var browser: NWBrowser?
    private var connection: NWConnection?

    /// TCP stream may split reads — accumulate until a full chunk is parsed.
    private var rxBuffer = Data()

    /// Guest: queue hosts from browse; try sequentially so one bad endpoint doesn’t strand us.
    private var guestPendingConnections: [(key: String, label: String, endpoint: NWEndpoint)] = []
    /// Guest: endpoints we already tried and failed (TCP / handshake); don’t immediately retry the same room.
    private var guestFailedEndpointKeys: Set<String> = []
    private var guestActiveEndpointKey: String?

    @Published private(set) var connectedPeerNames: [String] = []
    @Published private(set) var discoveredPeers: [String] = []
    @Published private(set) var statusLine = ""
    @Published private(set) var lastSendRc: Int32?
    @Published private(set) var lastRecvRc: Int32?

    var onInboundDecrypt: ((String, String) -> Void)?

    init(
        nickname: String,
        pinDiscoveryTag: String,
        role: RoomRole,
        preferredHostBonjourName: String? = nil,
        /// Invite-link host: reuse saved UUID so `libgaryshell://` targets stay valid across restarts. Disposable host: pass `nil` for a fresh id each session.
        stableHostBonjourUUID: String? = nil,
        relayWebSocketURL: URL? = nil
    ) {
        self.pinDiscoveryTag = pinDiscoveryTag
        self.displayNickname = nickname
        self.role = role
        self.relayWebSocketURL = relayWebSocketURL
        switch role {
        case .host:
            let uuid: String
            if let stable = stableHostBonjourUUID?.lowercased(),
               UUID(uuidString: stable) != nil {
                uuid = stable
            } else {
                uuid = UUID().uuidString.lowercased()
            }
            self.bonjourInstanceName = "lgry-host-\(uuid)"
            self.preferredHostBonjourName = nil
        case .guest:
            let uuid = UUID().uuidString.lowercased()
            self.bonjourInstanceName = "lgry-guest-\(uuid)"
            self.preferredHostBonjourName = preferredHostBonjourName?.lowercased()
        }
    }

    /// UUID suffix after `lgry-host-`; embed in invite links for targeted joins.
    var inviteRoomToken: String? {
        guard role == .host, bonjourInstanceName.hasPrefix("lgry-host-") else { return nil }
        return String(bonjourInstanceName.dropFirst("lgry-host-".count))
    }

    /// Stable key for invite-link transcript persistence (host token or guest’s targeted host `lgry-host-…`).
    var invitePersistentRoomUUID: String? {
        switch role {
        case .host:
            return inviteRoomToken
        case .guest:
            guard let pref = preferredHostBonjourName, pref.hasPrefix("lgry-host-") else { return nil }
            let suffix = String(pref.dropFirst("lgry-host-".count))
            return suffix.isEmpty ? nil : suffix
        }
    }

    func inviteURL(pinNormalized: String) -> URL? {
        guard role == .host, let token = inviteRoomToken else { return nil }
        return PeerInviteKit.makeInviteURL(pinNormalized: pinNormalized, roomUUID: token)
    }

    deinit {
        stopAllNetworking()
    }

    private func stopAllNetworking() {
        listener?.cancel()
        listener = nil
        browser?.cancel()
        browser = nil
        connection?.cancel()
        connection = nil
        relayLinked = false
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        webSocketTask = nil
        urlSession?.invalidateAndCancel()
        urlSession = nil
        rxBuffer.removeAll()
        guestPendingConnections.removeAll()
        guestFailedEndpointKeys.removeAll()
        guestActiveEndpointKey = nil
    }

    private func publishMain(_ block: @escaping () -> Void) {
        if Thread.isMainThread {
            block()
        } else {
            DispatchQueue.main.async(execute: block)
        }
    }

    private func refreshCanSend() {
        let tcpReady = connection?.state == .ready
        let ok = crypto != nil && (tcpReady || relayLinked)
        publishMain {
            self.canSend = ok
        }
    }

    private func bindCrypto(isInviter: Bool) {
        guard crypto == nil else { return }
        let sess = GarySession(factoryRole: isInviter ? .pairedInitiator : .pairedResponder)
        crypto = sess
        publishMain {
            self.cryptoSession = sess
            self.refreshCanSend()
        }
    }

    func stopAll(clearStatus: Bool = true) {
        stopAllNetworking()
        crypto = nil
        publishMain {
            self.cryptoSession = nil
            self.canSend = false
            self.discoveredPeers = []
            self.connectedPeerNames = []
            if clearStatus {
                self.statusLine = "Stopped."
            }
        }
    }

    func startFindingPeers() {
        stopAll(clearStatus: false)
        rxBuffer.removeAll()

        if relayWebSocketURL != nil {
            publishMain {
                self.statusLine = self.role == .host
                    ? "Hosting — connecting to relay…"
                    : "Joining — connecting to relay…"
            }
            queue.async { self.startRelaySession() }
            return
        }

        switch role {
        case .host:
            publishMain { self.statusLine = "Hosting — starting room…" }
            startBonjourListener(params: tcpParameters())
        case .guest:
            publishMain { self.statusLine = "Joining — looking for a host on the network…" }
            startBonjourBrowser(params: tcpParameters())
        }
    }

    /// Guest only: stop and restart browse/connect without clearing the PIN session on the controller.
    func retryGuestDiscovery() {
        guard role == .guest else { return }
        publishMain { self.statusLine = "Joining — scanning again…" }
        startFindingPeers()
    }

    // MARK: - Listener (TCP acceptor / crypto responder)

    private func startBonjourListener(params: NWParameters) {
        let txt = NWTXTRecord(["pin": pinDiscoveryTag])
        let service = NWListener.Service(name: bonjourInstanceName, type: Self.bonjourType, domain: nil, txtRecord: txt)

        let nwListener: NWListener
        do {
            nwListener = try NWListener(service: service, using: params)
        } catch {
            publishMain { self.statusLine = "Listen error: \(error.localizedDescription)" }
            return
        }

        nwListener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .setup:
                self.publishMain {
                    self.statusLine = "Hosting — preparing listener…"
                }
            case .waiting(let err):
                self.publishMain {
                    self.statusLine = "Waiting for network permission / Wi‑Fi — \(err.debugDescription)"
                }
            case .ready:
                let portNote = nwListener.port.map { "TCP \($0.rawValue)" } ?? "TCP port pending"
                self.publishMain {
                    self.statusLine =
                        "Room is live (\(portNote)) — guest taps Join with the same PIN."
                }
            case .failed(let err):
                self.publishMain {
                    self.statusLine = "Advertise failed: \(err.localizedDescription) (\(err.debugDescription))"
                }
            case .cancelled:
                break
            @unknown default:
                self.publishMain {
                    self.statusLine = "Listener update: \(String(describing: state))"
                }
            }
        }

        nwListener.newConnectionHandler = { [weak self] newConn in
            guard let self else {
                newConn.cancel()
                return
            }
            self.queue.async {
                self.acceptHostConnection(newConn)
            }
        }

        listener = nwListener
        // Run listener callbacks on the main queue: Simulator / Bonjour often stay “stuck” when the
        // listener shares an unrelated serial queue with TCP work.
        nwListener.start(queue: .main)
    }

    /// Shared TCP stack for browse + outbound; listener uses the same options but starts on `.main`.
    private func tcpParameters() -> NWParameters {
        let params = NWParameters.tcp
        // Needed for Bonjour browse/connect paths across Simulator + LAN + peer interfaces.
        params.includePeerToPeer = true
        params.allowLocalEndpointReuse = false
        return params
    }

    private func normalizedBonjourServiceType(_ type: String) -> String {
        type.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
    }

    private func bonjourTypesMatch(_ observed: String, _ expected: String) -> Bool {
        normalizedBonjourServiceType(observed) == normalizedBonjourServiceType(expected)
    }

    private func acceptHostConnection(_ conn: NWConnection) {
        if connection != nil {
            conn.cancel()
            return
        }

        connection = conn
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.queue.async {
                    self.rxBuffer.removeAll()
                    self.runHostHandshake(on: conn)
                }
            case .failed(let err):
                self.publishMain { self.statusLine = "Peer dropped: \(err.localizedDescription)" }
                self.queue.async {
                    self.teardownConnectionOnly()
                }
            case .cancelled:
                break
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    private func runHostHandshake(on conn: NWConnection) {
        recvExactly(on: conn, byteCount: Self.handshakeMagic.count) { [weak self] magic in
            guard let self else { return }
            guard magic == Self.handshakeMagic else {
                conn.cancel()
                self.publishMain { self.statusLine = "Wrong handshake — not LibGary" }
                self.teardownConnectionOnly()
                return
            }
            self.recvExactly(on: conn, byteCount: 2) { lenTwo in
                let pinLen = Int(lenTwo.withUnsafeBytes { raw -> UInt16 in
                    guard raw.count >= 2 else { return 0 }
                    return (UInt16(raw[0]) << 8) | UInt16(raw[1])
                })
                guard pinLen > 0, pinLen <= 512 else {
                    conn.cancel()
                    self.teardownConnectionOnly()
                    return
                }
                self.recvExactly(on: conn, byteCount: pinLen) { pinData in
                    guard let got = String(data: pinData, encoding: .utf8), got == self.pinDiscoveryTag else {
                        conn.cancel()
                        self.publishMain { self.statusLine = "Wrong PIN" }
                        self.teardownConnectionOnly()
                        return
                    }
                    conn.send(content: Self.okayMagic, completion: .contentProcessed { err in
                        if err != nil {
                            conn.cancel()
                            self.teardownConnectionOnly()
                            return
                        }
                        self.bindCrypto(isInviter: false)
                        self.publishMain {
                            self.connectedPeerNames = ["Peer"]
                            self.statusLine = "Linked — say hello"
                            self.refreshCanSend()
                        }
                        self.rxBuffer.removeAll()
                        self.runFramedReceiveLoop(on: conn)
                    })
                }
            }
        }
    }

    // MARK: - Browser (guest only — connects to host)

    private func startBonjourBrowser(params: NWParameters) {
        // Plain `.bonjour` does not populate TXT metadata; we need `pin` from TXT to pick the right host.
        let nwBrowser = NWBrowser(for: .bonjourWithTXTRecord(type: Self.bonjourType, domain: nil), using: params)

        nwBrowser.browseResultsChangedHandler = { [weak self] results, changes in
            guard let self else { return }
            self.queue.async {
                // Prefer `changes` so we react once per discovery event; iterating `results` every
                // callback can hit unresolved endpoints first and burn our single outbound attempt.
                if changes.isEmpty {
                    for result in results {
                        self.handleBrowseAdded(result)
                    }
                } else {
                    for change in changes {
                        switch change {
                        case let .added(result):
                            self.handleBrowseAdded(result)
                        case let .changed(_, new, _):
                            self.handleBrowseAdded(new)
                        case .removed, .identical:
                            break
                        @unknown default:
                            break
                        }
                    }
                }
            }
        }

        nwBrowser.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .failed(let err):
                self.publishMain {
                    self.statusLine = "Browse failed: \(err.debugDescription)"
                }
            case .waiting(let err):
                self.publishMain {
                    if !self.statusLine.contains("Linked") {
                        self.statusLine = "Browse waiting — \(err.debugDescription)"
                    }
                }
            default:
                break
            }
        }

        nwBrowser.start(queue: queue)
        browser = nwBrowser
    }

    /// Identity string from browse endpoint (`lgry-<uuid>`), for logging / dedupe.
    private func bonjourInstanceName(from endpoint: NWEndpoint) -> String? {
        switch endpoint {
        case let .service(name, type, _, _):
            guard bonjourTypesMatch(type, Self.bonjourType) else { return nil }
            return name
        case .opaque:
            return scrapeHostInstanceName(endpoint.debugDescription)
        default:
            return scrapeHostInstanceName(endpoint.debugDescription)
        }
    }

    private func endpointStableKey(_ endpoint: NWEndpoint) -> String {
        switch endpoint {
        case let .service(name, type, domain, _):
            return "\(name)|\(type)|\(domain)"
        default:
            return endpoint.debugDescription
        }
    }

    /// With `bonjourWithTXTRecord`, PIN appears after resolve; skip TXT mismatches, wait if TXT not ready yet.
    private func guestBrowseAllowsConnect(_ result: NWBrowser.Result) -> Bool {
        switch result.metadata {
        case .none:
            return true
        case .bonjour(let txt):
            guard let advertised = txt.dictionary["pin"] else { return false }
            return advertised == pinDiscoveryTag
        default:
            return true
        }
    }

    private func scrapeHostInstanceName(_ haystack: String) -> String? {
        guard let re = try? NSRegularExpression(
            pattern: #"lgry-host-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#,
            options: [.caseInsensitive]
        ) else {
            return nil
        }
        let range = NSRange(haystack.startIndex..., in: haystack)
        guard let m = re.firstMatch(in: haystack, options: [], range: range),
              let swiftRange = Range(m.range, in: haystack) else { return nil }
        return String(haystack[swiftRange]).lowercased()
    }

    private func handleBrowseAdded(_ result: NWBrowser.Result) {
        guard role == .guest else { return }

        let endpoint = result.endpoint
        let remoteName: String
        switch endpoint {
        case let .service(name, type, _, _):
            guard bonjourTypesMatch(type, Self.bonjourType) else { return }
            guard name.hasPrefix("lgry-host-") else { return }
            if let pref = preferredHostBonjourName, name.lowercased() != pref { return }
            remoteName = name
        default:
            guard let n = bonjourInstanceName(from: endpoint)
                ?? scrapeHostInstanceName(endpoint.debugDescription) else { return }
            if let pref = preferredHostBonjourName, n.lowercased() != pref { return }
            remoteName = n
        }

        guard guestBrowseAllowsConnect(result) else { return }

        let key = endpointStableKey(endpoint)
        guard !guestFailedEndpointKeys.contains(key) else { return }
        guard !guestPendingConnections.contains(where: { $0.key == key }) else { return }
        guard guestActiveEndpointKey != key else { return }

        guestPendingConnections.append((key, remoteName, endpoint))
        publishMain {
            if !self.discoveredPeers.contains(remoteName) {
                self.discoveredPeers.append(remoteName)
            }
            if self.connection == nil, !self.statusLine.contains("Linked") {
                self.statusLine = "Found host — connecting…"
            }
        }
        guestPumpOutboundConnections()
    }

    private func guestPumpOutboundConnections() {
        guard role == .guest else { return }
        guard connection == nil else { return }
        guard crypto == nil else { return }

        while let head = guestPendingConnections.first {
            guestPendingConnections.removeFirst()
            if guestFailedEndpointKeys.contains(head.key) { continue }
            startOutboundConnection(to: head.endpoint, label: head.label, endpointKey: head.key)
            return
        }
    }

    private func startOutboundConnection(to endpoint: NWEndpoint, label: String, endpointKey: String) {
        guestActiveEndpointKey = endpointKey
        publishMain {
            self.statusLine = "Connecting…"
        }

        let conn = NWConnection(to: endpoint, using: tcpParameters())
        connection = conn

        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.queue.async {
                    self.rxBuffer.removeAll()
                    self.runGuestHandshake(on: conn)
                }
            case .waiting(let err):
                self.publishMain {
                    if !self.statusLine.contains("Linked") {
                        self.statusLine = "Connecting… waiting (\(err.debugDescription))"
                    }
                }
            case .failed:
                self.publishMain {
                    self.statusLine = "Could not connect — trying another host if available…"
                }
                self.queue.async {
                    self.teardownConnectionOnly(markGuestAttemptFailed: true)
                }
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    private func runGuestHandshake(on conn: NWConnection) {
        var payload = Self.handshakeMagic
        let pinBytes = Data(pinDiscoveryTag.utf8)
        guard pinBytes.count <= Int(UInt16.max) else {
            publishMain { self.statusLine = "PIN too long" }
            queue.async { self.teardownConnectionOnly(markGuestAttemptFailed: true) }
            return
        }
        var lenBE = UInt16(pinBytes.count).bigEndian
        payload.append(Data(bytes: &lenBE, count: 2))
        payload.append(pinBytes)

        conn.send(content: payload, completion: .contentProcessed { [weak self] err in
            guard let self else { return }
            guard err == nil else {
                self.queue.async { self.teardownConnectionOnly(markGuestAttemptFailed: true) }
                return
            }
            self.recvExactly(on: conn, byteCount: Self.okayMagic.count) { ok in
                guard ok == Self.okayMagic else {
                    self.publishMain { self.statusLine = "Host rejected PIN" }
                    self.teardownConnectionOnly(markGuestAttemptFailed: true)
                    return
                }
                self.bindCrypto(isInviter: true)
                self.publishMain {
                    self.connectedPeerNames = ["Peer"]
                    self.statusLine = "Linked — say hello"
                    self.refreshCanSend()
                }
                self.rxBuffer.removeAll()
                self.runFramedReceiveLoop(on: conn)
            }
        })
    }

    // MARK: - Receive helpers

    private func recvExactly(on conn: NWConnection, byteCount: Int, completion: @escaping (Data) -> Void) {
        func drain() {
            queue.async {
                if self.rxBuffer.count >= byteCount {
                    let chunk = self.rxBuffer.prefix(byteCount)
                    self.rxBuffer.removeFirst(byteCount)
                    completion(Data(chunk))
                    return
                }
                conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
                    guard let self else { return }
                    self.queue.async {
                        if error != nil {
                            conn.cancel()
                            self.teardownConnectionOnly(markGuestAttemptFailed: self.role == .guest)
                            return
                        }
                        if let data, !data.isEmpty {
                            self.rxBuffer.append(data)
                        }
                        if isComplete, self.rxBuffer.count < byteCount {
                            conn.cancel()
                            self.publishMain { self.statusLine = "Connection closed before handshake/data finished." }
                            self.teardownConnectionOnly(markGuestAttemptFailed: self.role == .guest)
                            return
                        }
                        drain()
                    }
                }
            }
        }
        drain()
    }

    private func runFramedReceiveLoop(on conn: NWConnection) {
        recvExactly(on: conn, byteCount: 4) { [weak self] lenFour in
            guard let self else { return }
            let rawLen = lenFour.withUnsafeBytes { raw -> UInt32 in
                guard raw.count >= 4 else { return 0 }
                return (UInt32(raw[0]) << 24)
                    | (UInt32(raw[1]) << 16)
                    | (UInt32(raw[2]) << 8)
                    | UInt32(raw[3])
            }
            guard rawLen > 0, rawLen <= 1024 * 1024 else {
                conn.cancel()
                self.publishMain { self.statusLine = "Bad frame length" }
                return
            }
            let bodyLen = Int(rawLen)
            self.recvExactly(on: conn, byteCount: bodyLen) { payload in
                guard let crypto = self.crypto else { return }
                let rc = crypto.ingestOuter(payload)
                self.publishMain {
                    self.lastRecvRc = rc
                    if rc == GARY_CODE_OK {
                        let plain = crypto.lastInboundUtf8String()
                        self.onInboundDecrypt?("Peer", plain)
                    } else {
                        self.statusLine = "Ingest rc=\(rc) \(crypto.lastErrorCString())"
                    }
                }
                self.runFramedReceiveLoop(on: conn)
            }
        }
    }

    private func teardownConnectionOnly(markGuestAttemptFailed: Bool = false) {
        if markGuestAttemptFailed, role == .guest, let k = guestActiveEndpointKey {
            guestFailedEndpointKeys.insert(k)
        }
        guestActiveEndpointKey = nil
        connection?.cancel()
        connection = nil
        relayLinked = false
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        webSocketTask = nil
        crypto = nil
        publishMain {
            self.cryptoSession = nil
            self.canSend = false
            self.connectedPeerNames = []
        }
        rxBuffer.removeAll()
        if role == .guest {
            guestPumpOutboundConnections()
            publishMain {
                if self.connection == nil, !self.statusLine.contains("Linked"), self.guestPendingConnections.isEmpty {
                    self.statusLine = "Still looking — open Host on the other device with the same PIN."
                }
            }
        }
    }

    // MARK: - Send

    func sendChat(_ text: String) {
        guard let crypto else {
            publishMain { self.statusLine = "Session not ready yet" }
            return
        }
        let tcpReady = connection?.state == .ready
        guard tcpReady || relayLinked else {
            publishMain { self.statusLine = "Session not ready yet" }
            return
        }
        let pair = crypto.buildEncryptedOuter(text)
        guard pair.rc == GARY_CODE_OK else {
            publishMain {
                self.lastSendRc = pair.rc
                self.statusLine = "Encrypt rc=\(pair.rc) \(crypto.lastErrorCString())"
            }
            return
        }
        let wire = pair.wire
        var pkt = Data()
        var beLen = UInt32(wire.count).bigEndian
        pkt.append(Data(bytes: &beLen, count: 4))
        pkt.append(wire)

        if relayLinked, let task = webSocketTask {
            task.send(.data(pkt)) { [weak self] err in
                guard let self else { return }
                self.publishMain {
                    if let err {
                        self.statusLine = "Send error: \(err.localizedDescription)"
                        return
                    }
                    self.lastSendRc = GARY_CODE_OK
                    self.statusLine = "Linked — sent \(wire.count) B"
                }
            }
            return
        }

        guard let conn = connection else {
            publishMain { self.statusLine = "Session not ready yet" }
            return
        }

        conn.send(content: pkt, completion: .contentProcessed { [weak self] err in
            guard let self else { return }
            self.publishMain {
                if err != nil {
                    self.statusLine = "Send error: \(err!.localizedDescription)"
                    return
                }
                self.lastSendRc = GARY_CODE_OK
                self.statusLine = "Linked — sent \(wire.count) B"
            }
        })
    }

    // MARK: - Internet relay (WebSocket)

    private func relayRoomIdString() -> String? {
        switch role {
        case .host:
            return inviteRoomToken
        case .guest:
            return invitePersistentRoomUUID
        }
    }

    private func startRelaySession() {
        guard let relayURL = relayWebSocketURL else { return }
        guard let roomId = relayRoomIdString() else {
            publishMain {
                self.statusLine = "Relay needs a room id — open the invite link or host invite-link flow."
            }
            return
        }

        let cfg = URLSessionConfiguration.default
        cfg.waitsForConnectivity = true
        let sess = URLSession(configuration: cfg)
        urlSession = sess
        let task = sess.webSocketTask(with: relayURL)
        webSocketTask = task
        task.resume()

        let roleStr = role == .host ? "host" : "guest"
        let payload: [String: Any] = [
            "room": roomId,
            "pin_tag": pinDiscoveryTag,
            "role": roleStr,
        ]
        guard JSONSerialization.isValidJSONObject(payload),
              let body = try? JSONSerialization.data(withJSONObject: payload),
              let jsonText = String(data: body, encoding: .utf8)
        else {
            publishMain { self.statusLine = "Relay join encode failed" }
            return
        }

        task.send(.string(jsonText)) { [weak self] err in
            guard let self else { return }
            self.queue.async {
                if let err {
                    self.publishMain {
                        self.statusLine = "Relay send failed: \(err.localizedDescription)"
                    }
                    return
                }
                self.receiveRelayJoinResponse()
            }
        }
    }

    private func receiveRelayJoinResponse() {
        guard let task = webSocketTask else { return }
        task.receive { [weak self] result in
            guard let self else { return }
            self.queue.async {
                switch result {
                case .success(let message):
                    switch message {
                    case .string(let text):
                        guard self.consumeRelayJoinAck(text) else {
                            self.publishMain { self.statusLine = "Relay rejected join (PIN / role / duplicate)." }
                            self.teardownConnectionOnly(markGuestAttemptFailed: self.role == .guest)
                            return
                        }
                        self.bindCrypto(isInviter: self.role == .guest)
                        self.relayLinked = true
                        self.publishMain {
                            self.connectedPeerNames = ["Peer"]
                            self.statusLine = "Linked — say hello"
                            self.refreshCanSend()
                        }
                        self.rxBuffer.removeAll()
                        self.relayReceiveLoop()
                    case .data:
                        self.publishMain { self.statusLine = "Relay: unexpected data before join ack" }
                        self.teardownConnectionOnly(markGuestAttemptFailed: self.role == .guest)
                    @unknown default:
                        break
                    }
                case .failure(let err):
                    self.publishMain { self.statusLine = "Relay error: \(err.localizedDescription)" }
                    self.teardownConnectionOnly(markGuestAttemptFailed: self.role == .guest)
                }
            }
        }
    }

    private func consumeRelayJoinAck(_ text: String) -> Bool {
        guard let data = text.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ok = obj["ok"] as? Bool,
              ok
        else {
            return false
        }
        return true
    }

    private func relayReceiveLoop() {
        guard let task = webSocketTask else { return }
        task.receive { [weak self] result in
            guard let self else { return }
            self.queue.async {
                switch result {
                case .success(let message):
                    switch message {
                    case .data(let chunk):
                        self.rxBuffer.append(chunk)
                        self.processRelayInboundBuffer()
                    case .string:
                        self.publishMain { self.statusLine = "Unexpected text on data channel" }
                    @unknown default:
                        break
                    }
                case .failure:
                    self.teardownConnectionOnly(markGuestAttemptFailed: self.role == .guest)
                }
            }
        }
    }

    private func processRelayInboundBuffer() {
        while rxBuffer.count >= 4 {
            let rawLen = (UInt32(rxBuffer[0]) << 24)
                | (UInt32(rxBuffer[1]) << 16)
                | (UInt32(rxBuffer[2]) << 8)
                | UInt32(rxBuffer[3])
            guard rawLen > 0, rawLen <= 1024 * 1024 else {
                publishMain { self.statusLine = "Bad frame length" }
                teardownConnectionOnly(markGuestAttemptFailed: role == .guest)
                return
            }
            let need = 4 + Int(rawLen)
            guard rxBuffer.count >= need else {
                relayReceiveLoop()
                return
            }
            let payload = rxBuffer.subdata(in: 4..<need)
            rxBuffer.removeFirst(need)

            guard let crypto else { return }
            let rc = crypto.ingestOuter(payload)
            publishMain {
                self.lastRecvRc = rc
                if rc == GARY_CODE_OK {
                    let plain = crypto.lastInboundUtf8String()
                    self.onInboundDecrypt?("Peer", plain)
                } else {
                    self.statusLine = "Ingest rc=\(rc) \(crypto.lastErrorCString())"
                }
            }
        }
        relayReceiveLoop()
    }
}
