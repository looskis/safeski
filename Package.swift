// swift-tools-version:5.10
import Foundation
import PackageDescription

// Swift 6.4 Command Line Tools ship the Swift Testing macros plugin but do not auto-load it,
// so `swift test` fails with "plugin for module 'TestingMacros' not found". Point at it when present.
let testingPluginPath = "/Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing"
// Skip it when a full Xcode is installed: Xcode loads its own matching plugin, and mixing in the
// Command Line Tools copy from a different Swift version breaks macro expansion.
let hasXcode = FileManager.default.fileExists(atPath: "/Applications/Xcode.app")
let testSwiftSettings: [SwiftSetting] = (!hasXcode && FileManager.default.fileExists(atPath: testingPluginPath))
    ? [.unsafeFlags(["-plugin-path", testingPluginPath])] : []

let package = Package(
    name: "safeski",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "safeski", targets: ["safeski"]),
        .library(name: "SafeskiCore", targets: ["SafeskiCore"]),
        .library(name: "safeski-pkcs11", type: .dynamic, targets: ["SafeskiPKCS11"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
    ],
    targets: [
        .target(
            name: "SafeskiCore",
            path: "Sources/SafeskiCore",
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("CryptoKit"),
            ]
        ),
        .executableTarget(
            name: "safeski",
            dependencies: [
                "SafeskiCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources/safeski"
        ),
        .target(name: "CPKCS11", path: "Sources/CPKCS11", publicHeadersPath: "include"),
        .target(
            name: "SafeskiPKCS11",
            dependencies: ["SafeskiCore", "CPKCS11"],
            path: "Sources/SafeskiPKCS11"
        ),
        .testTarget(
            name: "SafeskiCoreTests",
            dependencies: ["SafeskiCore"],
            path: "Tests/SafeskiCoreTests",
            swiftSettings: testSwiftSettings
        ),
    ],
    swiftLanguageVersions: [.v5]
)
