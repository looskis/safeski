import ArgumentParser
import Foundation
import SafeskiCore

// Owned by the SSH module. Replace this stub.
struct SSHCmd: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "ssh", abstract: "SSH (not yet implemented).", shouldDisplay: false)
    func run() throws { print("SSH: not yet implemented") }
}
