import ArgumentParser
import Foundation
import SafeskiCore

// Owned by the Broker/containers module. Replace this stub.
struct DockerCmd: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "docker", abstract: "Container integration (not yet implemented).", shouldDisplay: false)
    func run() throws { print("docker: not yet implemented") }
}
