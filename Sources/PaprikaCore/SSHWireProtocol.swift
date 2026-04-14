import Foundation

public enum SSHError: Error {
    case notEnoughData
    case invalidString
}

public struct SSHReader {
    private var data: Data
    private(set) public var offset: Int = 0

    public init(data: Data) {
        self.data = data
    }

    public mutating func readUInt32() throws -> UInt32 {
        guard offset + 4 <= data.count else { throw SSHError.notEnoughData }
        let value = data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self) }
        offset += 4
        return UInt32(bigEndian: value)
    }
    
    public mutating func readByte() throws -> UInt8 {
         guard offset + 1 <= data.count else { throw SSHError.notEnoughData }
         let value = data[offset]
         offset += 1
         return value
    }

    public mutating func readString() throws -> String {
        let length = try Int(readUInt32())
        guard length >= 0 else { throw SSHError.invalidString }
        guard offset + length <= data.count else { throw SSHError.notEnoughData }
        let bytes = data.subdata(in: offset..<offset+length)
        offset += length
        guard let string = String(data: bytes, encoding: .utf8) else { throw SSHError.invalidString }
        return string
    }

    public mutating func readData() throws -> Data {
        let length = try Int(readUInt32())
        guard length >= 0 else { throw SSHError.notEnoughData }
        guard offset + length <= data.count else { throw SSHError.notEnoughData }
        let sub = data.subdata(in: offset..<offset+length)
        offset += length
        return sub
    }
    
    public mutating func readRest() -> Data {
        let sub = data.subdata(in: offset..<data.count)
        offset = data.count
        return sub
    }
}

public struct SSHWriter {
    public var data = Data()
    
    public init() {}

    public mutating func write(_ value: UInt32) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
    }
    
    public mutating func write(_ value: UInt8) {
        data.append(value)
    }

    public mutating func write(_ value: String) {
        let bytes = value.data(using: .utf8) ?? Data()
        write(UInt32(bytes.count))
        data.append(bytes)
    }

    public mutating func write(_ value: Data) {
        write(UInt32(value.count))
        data.append(value)
    }
    
    public mutating func writeRaw(_ value: Data) {
        data.append(value)
    }
}
