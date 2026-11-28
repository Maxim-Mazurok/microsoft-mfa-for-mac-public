import Foundation
import WebKit

/// Uses the installed macOS WebKit parser; never loads a page or contacts a service.
@main struct ManifestTests {
    @MainActor static func main() async throws {
        guard CommandLine.arguments.count == 2 else { exit(2) }
        let url = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let webExtension = try await WKWebExtension(resourceBaseURL: url)
        guard webExtension.errors.isEmpty else {
            print("Safari manifest: \(webExtension.errors.count) parse errors")
            for error in webExtension.errors { print("Manifest parser error: \((error as NSError).code)") }
            exit(1)
        }
        print("Safari manifest: installed WebKit parser accepted the extension")
    }
}
