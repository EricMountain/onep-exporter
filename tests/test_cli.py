import sys

import onep_exporter.cli as cli


def test_cli_help_hides_keychain_flags_on_non_macos(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    p = cli.build_parser()
    # get the `backup` subparser to inspect its flags
    subparsers_action = next(
        a for a in p._actions if a.__class__.__name__ == "_SubParsersAction")
    backup_parser = subparsers_action.choices["backup"]
    help_text = backup_parser.format_help()

    # keychain-related flags must be hidden from help on non-macOS
    assert "--age-keychain-service" not in help_text
    assert "--age-keychain-username" not in help_text

    # `keychain` should not appear as a choice for --age-pass-source
    # keychain choice not applicable when passphrase support removed

    # check `init` subparser help doesn't show keychain flags either
    init_parser = subparsers_action.choices["init"]
    init_help = init_parser.format_help()
    assert "--store-in-keychain" not in init_help
    assert "--keychain-service" not in init_help
    assert "--keychain-username" not in init_help


def test_cli_help_shows_keychain_flags_on_macos(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    p = cli.build_parser()
    # inspect the backup + init subparsers
    subparsers_action = next(
        a for a in p._actions if a.__class__.__name__ == "_SubParsersAction")
    backup_parser = subparsers_action.choices["backup"]
    help_text = backup_parser.format_help()

    # keychain-related flags must be visible on macOS
    assert "--age-keychain-service" in help_text
    assert "--age-keychain-username" in help_text

    # `keychain` should be an allowed choice for --age-pass-source
    # keychain flags are visible on macOS; passphrase selection removed

    init_parser = subparsers_action.choices["init"]
    init_help = init_parser.format_help()
    # init only exposes signin flag now
    assert "--signin" in init_help
