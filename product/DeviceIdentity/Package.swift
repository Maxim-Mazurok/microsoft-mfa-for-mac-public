// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "DeviceIdentity", platforms: [.macOS("15.4")], products: [.library(name: "DeviceIdentityCore", targets: ["DeviceIdentityCore"])], targets: [
    .target(name: "DeviceIdentityCore", path: "Core", linkerSettings: [.linkedFramework("Security")]),
    .testTarget(name: "DeviceIdentityTests", dependencies: ["DeviceIdentityCore"], path: "Tests")
])
