# DRAFT, not yet usable: the URL and sha256 below are placeholders until the
# repository is public and a release is tagged. After tagging v0.1.0:
#   1. set OWNER in homepage, url and head to the repository's owner;
#   2. set sha256 to `shasum -a 256` of the release tarball;
#   3. `brew install --build-from-source ./Formula/storekeeper.rb`, then `brew test storekeeper`.
#
# Standard library only, so nothing is pip-installed: the package folder goes to
# libexec and bin/storekeeper runs it with Homebrew's Python under -I (no
# PYTHONPATH, no current folder). It calls /usr/bin/security and /usr/bin/openssl
# by path, never through PATH.
class Storekeeper < Formula
  desc "Safety layer over Apple's App Store Connect API: Keychain key, dry run, write fences"
  homepage "https://github.com/OWNER/storekeeper"
  url "https://github.com/OWNER/storekeeper/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "Apache-2.0"
  head "https://github.com/OWNER/storekeeper.git", branch: "main"

  depends_on :macos # the key lives in the macOS Keychain
  depends_on "python@3.15"

  def install
    libexec.install "src/storekeeper"
    python = Formula["python@3.15"].opt_bin/"python3.15"
    (bin/"storekeeper").write <<~SH
      #!/bin/bash
      exec "#{python}" -I "#{libexec}/storekeeper/_run.py" "$@"
    SH
    pkgshare.install "skills"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/storekeeper --version")
    out = shell_output("#{bin}/storekeeper api GET /v1/apps --json")
    assert_match '"live": false', out
  end
end
