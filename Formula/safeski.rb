# Homebrew formula skeleton for safeski. Builds from source with SwiftPM.
#
# Not yet published: there is no v0.1.0 tag, so `url`/`sha256` below are placeholders. Until a
# release is cut and this is copied into looskis/homebrew-tap, install with scripts/install.sh
# or `brew install --HEAD --build-from-source ./Formula/safeski.rb`.
#
#   brew install --build-from-source ./Formula/safeski.rb
#   brew services start safeski          # per-user LaunchAgent running `safeski agent start`
#
# Notes:
# - Homebrew services generate the LaunchAgent plist from the `service` block below. The
#   formula DSL cannot set `ProcessType Interactive`, which `safeski agent install` sets so
#   that Touch ID / approval prompts get GUI priority. Prompts still work from a brew-managed
#   agent (it runs in the user's gui domain); if you want the Interactive process type, use
#   `safeski agent install` instead of `brew services`.
# - The root broker (cross-user access) is not managed by Homebrew: run `safeski broker install`
#   and follow the printed sudo commands.
class Safeski < Formula
  desc "Secure Enclave-backed keys and secrets for ssh, git, AI agents, containers and apps"
  homepage "https://github.com/looskis/safeski"
  url "https://github.com/looskis/safeski/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000" # TODO: fill on release
  head "https://github.com/looskis/safeski.git", branch: "main"

  depends_on :macos
  depends_on xcode: ["15.0", :build] # Command Line Tools with Swift 6 are sufficient; brew needs *a* toolchain

  def install
    system "swift", "build", "-c", "release", "--disable-sandbox"
    bin.install ".build/release/safeski"
    lib.install ".build/release/libsafeski-pkcs11.dylib" if File.exist?(".build/release/libsafeski-pkcs11.dylib")
    # Ad-hoc sign with a stable identifier so policy rules can match signing_id = "dev.safeski.cli".
    system "codesign", "--force", "-s", "-", "--identifier", "dev.safeski.cli", bin/"safeski"
    (libexec/"clients").install Dir["clients/*"]
  end

  service do
    run [opt_bin/"safeski", "agent", "start"]
    keep_alive true
    run_type :immediate
    log_path var/"log/safeski-agent.log"
    error_log_path var/"log/safeski-agent.log"
    environment_variables SAFESKI_HOME: "#{Dir.home}/.safeski"
  end

  def caveats
    <<~EOS
      Initialize your device identity, then start the agent:
        safeski init
        brew services start safeski      (or: safeski agent install, which sets ProcessType=Interactive)
      Add to your shell profile:
        eval "$(safeski agent env)"
      Container clients (python/node/shell) are in #{opt_libexec}/clients.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/safeski --version")
    # No Secure Enclave access in the sandbox; just check the CLI parses.
    system bin/"safeski", "policy", "path"
  end
end
