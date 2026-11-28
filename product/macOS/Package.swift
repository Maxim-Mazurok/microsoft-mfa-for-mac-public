// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "MFANativeCore",
    platforms: [.macOS(.v13)],
    products: [.library(name: "MFANativeCore", targets: ["MFANativeCore"])],
    targets: [
        .target(name: "MFANativeCore", path: ".", exclude: ["Tests", "Package.swift", "README.md", "MicrosoftMFAApp.swift", "AppModel.swift", "ProtocolProcess.swift", "KeychainStore.swift", "SessionMonitor.swift", "LocalVerification.swift", "BrowserInbox.swift", "NativeSelfTest.swift", "Info.plist", "App.entitlements", "DevelopmentApp.entitlements"], sources: ["Core.swift"]),
        .testTarget(name: "MFANativeCoreTests", dependencies: ["MFANativeCore"], path: "Tests", exclude: ["test_build_isolation.py", "__pycache__"])
    ]
)
