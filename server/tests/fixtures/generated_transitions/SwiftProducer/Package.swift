// swift-tools-version: 6.0
import PackageDescription

// The reproduction driver verifies both exact source revisions and source bytes
// before SwiftPM resolves these sibling packages. Neither SDK is regenerated.
let package = Package(
    name: "GeneratedTransitionProducer",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(path: "../../../../../../Petrel"),
        .package(path: "../../../../../../PetrelCatbird"),
    ],
    targets: [
        .executableTarget(
            name: "GeneratedTransitionProducer",
            dependencies: [
                .product(name: "Petrel", package: "Petrel"),
                .product(name: "PetrelCatbird", package: "PetrelCatbird"),
            ]
        ),
    ]
)
