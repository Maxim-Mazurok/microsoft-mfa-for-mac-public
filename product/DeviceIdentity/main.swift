import Foundation
import Security

func output(_ value: [String: Any]) {
    if let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(data + Data([10]))
    }
}

do {
    guard CommandLine.arguments.count == 1 else { throw DeviceKeyError.invalidInput }
    var data = Data()
    while let chunk = try FileHandle.standardInput.read(upToCount: 16384), !chunk.isEmpty {
        data.append(chunk)
        guard data.count <= DeviceKeyRequest.maximumInputBytes else { throw DeviceKeyError.invalidInput }
    }
    let request = try DeviceKeyRequest(data: data)
    output(try DeviceKeyStore().execute(request))
} catch {
    output(["v": 1, "ok": false, "error": (error as? DeviceKeyError)?.rawValue ?? "operation_failed"])
    exit(1)
}
