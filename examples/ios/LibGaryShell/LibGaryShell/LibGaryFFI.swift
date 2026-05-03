import Combine
import Foundation

/// Pointer lifetime only — forwards to `gary_*` (`include/libgary.h`).
final class GarySession: ObservableObject {
    enum FactoryRole {
        /// `gary_session_new_initiator` — pair with `.pairedResponder` on the other device.
        case pairedInitiator
        /// `gary_session_new` — doc handshake responder fixture.
        case pairedResponder
    }

    private var handle: UnsafeMutablePointer<SessionHandle>?

    init(factoryRole: FactoryRole = .pairedResponder) {
        switch factoryRole {
        case .pairedResponder:
            handle = gary_session_new()
        case .pairedInitiator:
            handle = gary_session_new_initiator()
        }
    }

    deinit {
        if let h = handle {
            gary_session_free(h)
            handle = nil
        }
    }

    var isReady: Bool { handle != nil }

    func ingestOuter(_ bytes: Data) -> Int32 {
        guard let h = handle else { return GARY_CODE_NULL_POINTER }
        return bytes.withUnsafeBytes { raw in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else {
                return GARY_CODE_NULL_POINTER
            }
            return gary_ingest_outer(h, base, raw.count)
        }
    }

    /// Full relay `PAD()` wire — send this blob on MCP/WebSocket unchanged (`route_token` from pairing/mailbox).
    func buildRelayOutbound(routeToken: Data, text: String) -> (wire: Data, rc: Int32) {
        guard let h = handle else { return (Data(), GARY_CODE_NULL_POINTER) }
        let cap = Int(GARY_RELAY_WIRE_CAP)
        var buf = [UInt8](repeating: 0, count: cap)
        var written: UInt = 0
        let utf8Arr = Array(text.utf8)
        let rc: Int32 = routeToken.withUnsafeBytes { rtRaw in
            guard let rtp = rtRaw.bindMemory(to: UInt8.self).baseAddress else {
                return GARY_CODE_NULL_POINTER
            }
            return utf8Arr.withUnsafeBufferPointer { uRaw in
                guard let up = uRaw.baseAddress else { return GARY_CODE_NULL_POINTER }
                return gary_prepare_relay_outbound_utf8(
                    h,
                    rtp,
                    rtRaw.count,
                    up,
                    uRaw.count,
                    &buf,
                    cap,
                    &written
                )
            }
        }
        guard rc == GARY_CODE_OK, written > 0, written <= UInt(cap) else {
            return (Data(), rc)
        }
        return (Data(buf[..<Int(written)]), rc)
    }

    func processRelayInbound(_ bytes: Data) -> Int32 {
        guard let h = handle else { return GARY_CODE_NULL_POINTER }
        return bytes.withUnsafeBytes { raw in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else {
                return GARY_CODE_NULL_POINTER
            }
            return gary_process_relay_inbound(h, base, raw.count)
        }
    }

    /// Serialized `OuterRecord` DATA frame, or empty data if `gary_send_utf8_data_outer` ≠ OK.
    func buildEncryptedOuter(_ text: String) -> (wire: Data, rc: Int32) {
        guard let h = handle else { return (Data(), GARY_CODE_NULL_POINTER) }
        let cap = Int(GARY_SEND_OUTER_CAP)
        var buf = [UInt8](repeating: 0, count: cap)
        var written: UInt = 0
        let rc: Int32 = {
            if let r = text.utf8.withContiguousStorageIfAvailable({ storage -> Int32 in
                guard let b = storage.baseAddress else { return GARY_CODE_NULL_POINTER }
                return gary_send_utf8_data_outer(h, b, storage.count, &buf, cap, &written)
            }) {
                return r
            }
            let utf8 = Array(text.utf8)
            return utf8.withUnsafeBufferPointer { ptr -> Int32 in
                guard let b = ptr.baseAddress else { return GARY_CODE_NULL_POINTER }
                return gary_send_utf8_data_outer(h, b, ptr.count, &buf, cap, &written)
            }
        }()
        guard rc == GARY_CODE_OK, written > 0, written <= UInt(cap) else {
            return (Data(), rc)
        }
        return (Data(buf[..<Int(written)]), rc)
    }

    func encryptedOuterRecord(fromUtf8 text: String) -> Data? {
        let pair = buildEncryptedOuter(text)
        return pair.rc == GARY_CODE_OK ? pair.wire : nil
    }

    func lastInboundUtf8String() -> String {
        guard let h = handle, let p = gary_last_inbound_utf8(h) else { return "" }
        return String(cString: p)
    }

    func readDigestBytes(into out: inout Data) {
        guard let h = handle else { return }
        guard out.count == 32 else { return }
        out.withUnsafeMutableBytes { raw in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return }
            gary_get_digest(h, base)
        }
    }

    func copyDigest() -> Data {
        var out = Data(count: 32)
        readDigestBytes(into: &out)
        return out
    }

    func lastErrorCString() -> String {
        guard let h = handle else { return "" }
        guard let cstr = gary_last_error(h) else { return "" }
        return String(cString: cstr)
    }
}

extension Data {
    /// Hex decode for fixed VECTOR001 wire only (glue).
    static func fromHexWire(_ hex: String) -> Data? {
        let cleaned = hex.filter { !$0.isWhitespace && !$0.isNewline }
        guard cleaned.count % 2 == 0, !cleaned.isEmpty else { return nil }
        var data = Data()
        data.reserveCapacity(cleaned.count / 2)
        var idx = cleaned.startIndex
        while idx < cleaned.endIndex {
            let next = cleaned.index(idx, offsetBy: 2)
            guard let byte = UInt8(String(cleaned[idx..<next]), radix: 16) else { return nil }
            data.append(byte)
            idx = next
        }
        return data
    }

    func hexDumpLowercase() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
