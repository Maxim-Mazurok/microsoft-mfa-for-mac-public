// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "WorkplaceJoinBootstrap",
    platforms: [.macOS("15.4")],
    products: [.library(name: "BootstrapCore", targets: ["BootstrapCore"])],
    targets: [
        .target(name: "BootstrapCore", path: "Core"),
        .testTarget(name: "BootstrapCoreTests", dependencies: ["BootstrapCore"], path: "Tests")
    ]
)
