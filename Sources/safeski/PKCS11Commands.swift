import ArgumentParser
import Foundation
import SafeskiCore

// Owned by the PKCS11 module. Replace this stub.
struct PKCS11Cmd: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "pkcs11", abstract: "PKCS11 (not yet implemented).", shouldDisplay: false)
    func run() throws { print("PKCS11: not yet implemented") }
}
