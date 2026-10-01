// swift-tools-version:5.10
import PackageDescription

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
            path: "Tests/SafeskiCoreTests"
        ),
    ],
    swiftLanguageVersions: [.v5]
)
