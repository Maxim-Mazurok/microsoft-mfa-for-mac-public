import Foundation

final class ProtocolProcess {
    var onEvent: (([String: Any]) -> Void)?
    var onFailure: ((String) -> Void)?
    private var process: Process?
    private var input: FileHandle?
    private var output: FileHandle?
    private var errors: FileHandle?
    private let queue = DispatchQueue(label: "org.example.microsoftmfamac.protocol")
    private let writes = DispatchQueue(label: "org.example.microsoftmfamac.protocol-writes")
    private var framer = LineFramer()
    private var intentionalStop = false
    private var generation = UUID()

    static func runtime() throws -> (URL, URL) {
        guard let root = Bundle.main.resourceURL?.appendingPathComponent("Runtime"),
              let pythonPath = Bundle.main.object(forInfoDictionaryKey: "MFADevelopmentPython") as? String,
              FileManager.default.isExecutableFile(atPath: pythonPath),
              FileManager.default.fileExists(atPath: root.appendingPathComponent("service/main.py").path)
        else { throw ProductError.unavailable }
        return (URL(fileURLWithPath: pythonPath), root.appendingPathComponent("service/main.py"))
    }

    func start(stateDirectory: URL, synthetic: Bool) throws {
        stop()
        intentionalStop = false
        let generation = self.generation
        framer = LineFramer()
        let (python, script) = try Self.runtime()
        try FileManager.default.createDirectory(at: stateDirectory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: stateDirectory.path)
        let child = Process()
        child.executableURL = python
        child.arguments = [script.path, "--state-dir", stateDirectory.path] + (synthetic ? ["--synthetic"] : [])
        child.environment = ["PATH": "/usr/bin:/bin", "HOME": NSHomeDirectory(), "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"]
        let inPipe = Pipe(), outPipe = Pipe(), errorPipe = Pipe()
        child.standardInput = inPipe; child.standardOutput = outPipe; child.standardError = errorPipe
        input = inPipe.fileHandleForWriting; output = outPipe.fileHandleForReading; errors = errorPipe.fileHandleForReading
        output?.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { handle.readabilityHandler = nil; return }
            self?.queue.async { [weak self] in
                guard let self else { return }
                guard self.generation == generation else { return }
                do {
                    for line in try self.framer.append(data) where !line.isEmpty {
                        let event = try Wire.decode(line)
                        DispatchQueue.main.async { [weak self] in
                            guard self?.generation == generation else { return }
                            self?.onEvent?(event)
                        }
                    }
                } catch { self.fail("service_message_invalid", generation: generation) }
            }
        }
        // Never log or persist child stderr: upstream errors can contain private payloads.
        errors?.readabilityHandler = { handle in if handle.availableData.isEmpty { handle.readabilityHandler = nil } }
        child.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async { [weak self] in
                guard let self, !self.intentionalStop, self.generation == generation else { return }
                self.onFailure?("service_stopped")
            }
        }
        process = child
        try child.run()
    }

    func send(_ command: [String: Any]) {
        do {
            guard process?.isRunning == true, let input else { throw ProductError.unavailable }
            let data = try Wire.encode(command), generation = self.generation
            writes.async { [weak self] in
                guard self?.generation == generation else { return }
                do { try input.write(contentsOf: data) }
                catch { self?.fail("service_write_failed", generation: generation) }
            }
        } catch { fail("service_write_failed") }
    }

    func stop() {
        intentionalStop = true
        generation = UUID()
        output?.readabilityHandler = nil; errors?.readabilityHandler = nil
        if process?.isRunning == true {
            // Never block the UI writing to a hung/full child pipe. Durable service
            // approval claims preserve at-most-once behavior if termination interrupts IO.
            process?.terminate()
        }
        try? input?.close(); try? output?.close(); try? errors?.close()
        process = nil; input = nil; output = nil; errors = nil
    }

    private func fail(_ code: String, generation: UUID? = nil) {
        DispatchQueue.main.async { [weak self] in
            guard let self, generation == nil || generation == self.generation else { return }
            self.onFailure?(code); self.stop()
        }
    }

    /// Read-only research export. Capture stdout privately; never place secrets in arguments.
    static func exportResearch(root: URL, completion: @escaping (Result<Data, Error>) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let (python, script) = try runtime()
                let child = Process(), out = Pipe(), err = Pipe()
                child.executableURL = python
                child.arguments = [script.path, "--export-research", root.path]
                child.environment = ["PATH": "/usr/bin:/bin", "HOME": NSHomeDirectory(), "PYTHONDONTWRITEBYTECODE": "1"]
                child.standardOutput = out; child.standardError = err; child.standardInput = FileHandle.nullDevice
                err.fileHandleForReading.readabilityHandler = { handle in
                    if handle.availableData.isEmpty { handle.readabilityHandler = nil }
                }
                try child.run()
                let timeout = DispatchWorkItem { if child.isRunning { child.terminate() } }
                DispatchQueue.global().asyncAfter(deadline: .now() + 30, execute: timeout)
                var data = Data()
                while true {
                    let part = out.fileHandleForReading.availableData
                    if part.isEmpty { break }
                    data.append(part)
                    if data.count > Wire.maximumLineBytes { child.terminate(); throw ProductError.invalidMessage }
                }
                child.waitUntilExit(); timeout.cancel()
                err.fileHandleForReading.readabilityHandler = nil
                guard child.terminationStatus == 0 else { throw ProductError.failed }
                DispatchQueue.main.async { completion(.success(data)) }
            } catch { DispatchQueue.main.async { completion(.failure(ProductError.failed)) } }
        }
    }
}
