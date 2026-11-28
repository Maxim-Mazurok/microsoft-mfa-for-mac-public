import XCTest
@testable import DeviceIdentityCore

final class DeviceIdentityTests: XCTestCase {
    func request(_ update: [String: Any] = [:]) throws -> DeviceKeyRequest {
        var value: [String: Any] = ["v":1,"action":"public","namespace":"00000000-0000-4000-8000-000000000001","role":"device"]
        value.merge(update) { _, new in new }
        return try DeviceKeyRequest(data: JSONSerialization.data(withJSONObject: value))
    }
    func testNamespaceExactAndDistinctRoles() throws {
        let device = try request(), transport = try request(["role":"transport"])
        XCTAssertEqual(String(data: device.tag, encoding:.utf8), "org.example.microsoftmfamac.device-identity.research.00000000-0000-4000-8000-000000000001.device")
        XCTAssertNotEqual(device.tag, transport.tag)
    }
    func testRejectUnknownActionsRolesNamespaceAndFields() throws {
        for change: [String: Any] in [["action":"delete_all"],["role":"*"],["namespace":"../existing"],["namespace":"00000000-0000-4000-8000-00000000000A"],["v":true],["private_key":"forbidden"],["action":"sign"]] {
            XCTAssertThrowsError(try request(change))
        }
    }
    func testStrictBase64AndSigningBound() throws {
        XCTAssertEqual(try request(["action":"sign","data_base64":Data("synthetic".utf8).base64EncodedString()]).message,Data("synthetic".utf8))
        XCTAssertThrowsError(try request(["action":"sign","data_base64":"!!!!"]))
        XCTAssertThrowsError(try request(["action":"sign","data_base64":Data(repeating:0,count:DeviceKeyRequest.maximumMessageBytes+1).base64EncodedString()]))
        XCTAssertThrowsError(try request(["data_base64":""])); XCTAssertThrowsError(try DeviceKeyRequest(data:Data(repeating:0,count:DeviceKeyRequest.maximumInputBytes+1)))
    }
    func testDERLengthsAndSPKIWrapper() throws {
        XCTAssertEqual(RSAPublicEncoding.tlv(0x30,Data(repeating:0,count:127)).prefix(2), Data([0x30,0x7f]))
        XCTAssertEqual(RSAPublicEncoding.tlv(0x30,Data(repeating:0,count:128)).prefix(3), Data([0x30,0x81,0x80]))
        let pkcs1=Data([0x30])+Data(repeating:0,count:269)
        let spki=try RSAPublicEncoding.spki(pkcs1:pkcs1)
        XCTAssertEqual(spki.suffix(pkcs1.count),pkcs1)
        XCTAssertTrue(spki.contains(0x03)); XCTAssertThrowsError(try RSAPublicEncoding.spki(pkcs1:Data()))
    }
}
