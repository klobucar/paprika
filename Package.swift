// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "paprika",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "paprika", targets: ["paprika"]),
        .library(name: "PaprikaCore", targets: ["PaprikaCore"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
    ],
    targets: [
        .target(
            name: "PaprikaCore",
            dependencies: []
        ),
        .executableTarget(
            name: "paprika",
            dependencies: [
                "PaprikaCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources/PaprikaCLI"
        ),
        .testTarget(
            name: "PaprikaCoreTests",
            dependencies: ["PaprikaCore"]
        ),
    ]
)
