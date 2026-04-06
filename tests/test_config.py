import os
import json
from pathlib import Path
import onep_exporter.exporter as exporter_module


def test_save_and_load_config(tmp_path, monkeypatch):
    cfg_path = tmp_path / "cfg.json"
    monkeypatch.setenv("ONEP_EXPORTER_CONFIG", str(cfg_path))
    data = {"output_base": "/tmp/backups", "encrypt": "age",
            "age": {"pass_source": "keychain"}}

    p = exporter_module.save_config(data)
    assert p.exists()
    loaded = exporter_module.load_config()
    assert loaded["output_base"] == "/tmp/backups"
    assert loaded["age"]["pass_source"] == "keychain"


def test_cli_uses_config_defaults(monkeypatch):
    # provide a config and ensure CLI merges values when flags not provided
    cfg = {"output_base": "/tmp/fromcfg", "encrypt": "age", "formats": ["json"], "download_attachments": True, "age": {
        "pass_source": "prompt", "recipients": "", "keychain_service": "onep-exporter", "keychain_username": "backup"}}
    monkeypatch.setattr(exporter_module, "load_config", lambda: cfg)

    called = {}

    def fake_run_backup(**kwargs):
        called.update(kwargs)

    import importlib
    import onep_exporter.cli as cli
    # ensure the cli module uses the patched exporter.load_config/run_backup
    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    monkeypatch.setattr(cli, "run_backup", fake_run_backup)

    cli.main(["backup"])

    assert called["output_base"] == "/tmp/fromcfg"
    assert called["encrypt"] == "age"
    assert called["formats"] == ["json"]


def test_cli_default_age_pass_source(monkeypatch):
    # when neither CLI nor config specifies a pass source, the default should
    # be "prompt" (not "1password", avoiding spurious fetches).
    cfg = {"encrypt": "age", "formats": ["json"]}
    monkeypatch.setattr(exporter_module, "load_config", lambda: cfg)
    called = {}
    def fake_run_backup(**kwargs):
        called.update(kwargs)
    import onep_exporter.cli as cli
    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    monkeypatch.setattr(cli, "run_backup", fake_run_backup)
    cli.main(["backup"])
    assert called.get("age_pass_source") == "prompt"


def test_cli_flag_overrides_config(monkeypatch):
    cfg = {"output_base": "/tmp/fromcfg",
           "encrypt": "age", "formats": ["json"]}
    monkeypatch.setattr(exporter_module, "load_config", lambda: cfg)

    called = {}

    def fake_run_backup(**kwargs):
        called.update(kwargs)

    import onep_exporter.cli as cli
    # ensure cli uses the patched load_config/run_backup
    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    monkeypatch.setattr(cli, "run_backup", fake_run_backup)

    cli.main(["backup", "--output", "/tmp/explicit",
             "--formats", "json,md", "--encrypt", "none"])

    assert called["output_base"] == "/tmp/explicit"
    assert called["encrypt"] == "none"
    assert called["formats"] == ["json", "md"]


def test_cli_doctor_success_exit_code(monkeypatch):
    import onep_exporter.cli as cli
    monkeypatch.setattr(cli, "doctor", lambda: True)
    try:
        cli.main(["doctor"])
    except SystemExit as e:
        assert e.code == 0
    else:
        raise AssertionError("expected SystemExit from cli.main")


def test_cli_doctor_failure_exit_code(monkeypatch):
    import onep_exporter.cli as cli
    monkeypatch.setattr(cli, "doctor", lambda: False)
    try:
        cli.main(["doctor"])
    except SystemExit as e:
        assert e.code == 2
    else:
        raise AssertionError("expected SystemExit from cli.main")


def test_cli_init_interactive_runs_doctor(monkeypatch):
    import onep_exporter.cli as cli
    called = {"interactive": False}
    monkeypatch.setattr(cli, "configure_interactive",
                        lambda: called.update({"interactive": True}) or {})
    monkeypatch.setattr(cli, "doctor", lambda: True)
    try:
        cli.main(["init"])
    except SystemExit as e:
        assert e.code == 0
    else:
        raise AssertionError("expected SystemExit from cli.main")


def test_configure_interactive_generates_age_key_and_stores(monkeypatch, tmp_path):
    """Interactive init should generate an age keypair, store private key and passphrase
    in a single 1Password Secure Note item, and include the public recipient in config."""
    import builtins
    import onep_exporter.exporter as exporter_module
    import onep_exporter.encryption as encryption_module
    import onep_exporter.keychain as keychain_module

    cfg_path = tmp_path / "cfg.json"
    monkeypatch.setenv("ONEP_EXPORTER_CONFIG", str(cfg_path))

    # pretend required tools are present
    monkeypatch.setattr(encryption_module, "ensure_tool", lambda name: True)

    # fake age-keygen output (private key block + public recipient)
    private_block = "-----BEGIN AGE PRIVATE KEY-----\nprivate-body\n-----END AGE PRIVATE KEY-----"
    public_recipient = "age1recipient12345"
    age_out = private_block + "\npublic key: " + public_recipient + "\n"

    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[0] == "age-keygen":
            return 0, age_out, ""
        return 0, "{}", ""

    monkeypatch.setattr(encryption_module, "run_cmd", fake_run_cmd)
    # prevent real keychain writes
    monkeypatch.setattr(keychain_module, "run_cmd", fake_run_cmd)

    upserted = {}

    def fake_ensure_secrets_item(self, title, vault=None):
        return {"id": "fake-item-id", "fields": []}  # no existing fields

    def fake_upsert_item_field(self, item_id, field_label, value, field_type="CONCEALED"):
        upserted[field_label] = {"value": value,
                                 "field_type": field_type, "item_id": item_id}
        return {"id": item_id}

    monkeypatch.setattr(exporter_module.OpExporter,
                        "ensure_secrets_item", fake_ensure_secrets_item)
    monkeypatch.setattr(exporter_module.OpExporter,
                        "upsert_item_field", fake_upsert_item_field)

    inputs = iter([
        "",       # Default backup directory (accept)
        "",       # formats (accept)
        "",       # encrypt (accept default 'age')
        "",       # download_attachments (accept)
        "",       # 1Password item title (accept default)
        "",       # 1Password vault (optional)
        "prompt",  # age_pass_source
        "y",      # Generate a new age keypair? -> yes
        "",       # age_recipients (accept default including generated pub)
        "n",      # include yubikey? -> no
        "y",      # Generate a new passphrase? -> yes
    ])

    monkeypatch.setattr(builtins, "input", lambda prompt="": next(inputs))

    # run interactive config
    cfg = exporter_module.configure_interactive()

    # config should contain the generated public recipient
    assert cfg["age"]["recipients"] == public_recipient
    # private key should have been stored via upsert
    assert "age_private_key" in upserted
    assert upserted["age_private_key"]["value"].startswith(
        "-----BEGIN AGE PRIVATE KEY-----")
    # passphrase should have been stored
    assert "passphrase" in upserted
    assert len(upserted["passphrase"]["value"]) > 0
    # recipients should have been stored
    assert "age_recipients" in upserted
    assert upserted["age_recipients"]["field_type"] == "TEXT"


def test_configure_interactive_parses_commented_public_and_secret_token(monkeypatch, tmp_path):
    """Ensure parser accepts commented public-key lines and AGE-SECRET-KEY tokens,
    and stores both in a single 1Password item via upsert."""
    import builtins
    import onep_exporter.exporter as exporter_module
    import onep_exporter.encryption as encryption_module
    import onep_exporter.keychain as keychain_module

    cfg_path = tmp_path / "cfg2.json"
    monkeypatch.setenv("ONEP_EXPORTER_CONFIG", str(cfg_path))
    monkeypatch.setattr(encryption_module, "ensure_tool", lambda name: True)

    # variant A: commented public key line with private block
    pub_a = "age1commentedpub"
    out_a = "# created: blah\n-----BEGIN AGE PRIVATE KEY-----\npriv-a\n-----END AGE PRIVATE KEY-----\n# public key: " + pub_a + "\n"

    # variant B: AGE-SECRET-KEY token + commented public line
    pub_b = "age1tokpub"
    secret_b = "AGE-SECRET-KEY-1ABCDEFGHIJKLMNOP"
    out_b = "# public key: " + pub_b + "\n" + secret_b + "\n"

    seq = iter([out_a, out_b])

    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[0] == "age-keygen":
            return 0, next(seq), ""
        return 0, "{}", ""

    monkeypatch.setattr(encryption_module, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(keychain_module, "run_cmd", fake_run_cmd)

    upserted_all = []

    def fake_ensure_secrets_item(self, title, vault=None):
        return {"id": "fake-item", "fields": []}

    def fake_upsert(self, item_id, field_label, value, field_type="CONCEALED"):
        upserted_all.append(
            {"label": field_label, "value": value, "type": field_type})
        return {"id": item_id}

    monkeypatch.setattr(exporter_module.OpExporter,
                        "ensure_secrets_item", fake_ensure_secrets_item)
    monkeypatch.setattr(exporter_module.OpExporter,
                        "upsert_item_field", fake_upsert)

    # run first interactive (out_a — PEM block)
    inputs_a = iter([
        "", "", "", "",     # basics
        "", "",             # 1P item title + vault
        "prompt",           # pass source
        "y",                # generate keypair
        "",                 # recipients (accept default)
        "n",                # yubikey
        "y",                # generate passphrase
    ])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(inputs_a))
    cfg1 = exporter_module.configure_interactive()
    assert cfg1["age"]["recipients"] == pub_a
    # private key stored should be PEM block
    pk_entry = [u for u in upserted_all if u["label"] == "age_private_key"][0]
    assert pk_entry["value"].startswith("-----BEGIN AGE PRIVATE KEY-----")

    # reset upserted list for second run
    upserted_all.clear()

    # For second run, load config from first run.
    # The ensure_secrets_item now returns existing recipients from first run
    # but no existing private key (simulating a fresh item for the second format test)
    def fake_ensure_secrets_item_2(self, title, vault=None):
        return {"id": "fake-item-2", "fields": [
            {"label": "age_recipients", "value": pub_a}
        ]}

    monkeypatch.setattr(exporter_module.OpExporter,
                        "ensure_secrets_item", fake_ensure_secrets_item_2)

    # run second interactive (out_b — AGE-SECRET-KEY token)
    inputs_b = iter([
        "", "", "", "",     # basics
        "", "",             # 1P item title + vault
        "prompt",           # pass source
        "y",                # generate keypair
        "",                 # recipients (accept default — should include both)
        "n",                # yubikey
        "y",                # generate passphrase
    ])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(inputs_b))
    cfg2 = exporter_module.configure_interactive()
    # new recipient should be present and previous recipient preserved
    assert pub_b in cfg2["age"]["recipients"]
    assert pub_a in cfg2["age"]["recipients"]
    # secret token stored via upsert
    pk_entry_2 = [u for u in upserted_all if u["label"]
                  == "age_private_key"][0]
    assert secret_b in pk_entry_2["value"]


def test_default_private_key_title_includes_username(monkeypatch, tmp_path):
    """Default 1Password item title should include the OS username and be used when accepted."""
    import builtins
    import getpass
    import onep_exporter.exporter as exporter_module

    import onep_exporter.encryption as encryption_module
    import onep_exporter.keychain as keychain_module

    cfg_path = tmp_path / "cfg3.json"
    monkeypatch.setenv("ONEP_EXPORTER_CONFIG", str(cfg_path))
    monkeypatch.setattr(encryption_module, "ensure_tool", lambda name: True)

    # fake age-keygen output
    public_recipient = "age1defaultpub"
    age_out = "-----BEGIN AGE PRIVATE KEY-----\npriv-default\n-----END AGE PRIVATE KEY-----\npublic key: " + \
        public_recipient + "\n"
    fake_run_cmd = lambda cmd, capture_output=True, check=True, input=None: (0, age_out, "") if cmd[0] == "age-keygen" else (0, "{}", "")
    monkeypatch.setattr(encryption_module, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(keychain_module, "run_cmd", fake_run_cmd)

    captured = {"title": None}

    def fake_ensure_secrets_item(self, title, vault=None):
        captured["title"] = title
        return {"id": "fake-item", "fields": []}

    def fake_upsert(self, item_id, field_label, value, field_type="CONCEALED"):
        return {"id": item_id}

    monkeypatch.setattr(exporter_module.OpExporter,
                        "ensure_secrets_item", fake_ensure_secrets_item)
    monkeypatch.setattr(exporter_module.OpExporter,
                        "upsert_item_field", fake_upsert)

    # ensure getuser returns a known value
    monkeypatch.setattr(getpass, "getuser", lambda: "ci-user")

    # interactive inputs: accept defaults for title (empty string)
    inputs = iter([
        "",       # Default backup directory
        "",       # formats
        "",       # encrypt (age)
        "",       # download_attachments
        "",       # Accept default 1P item title
        "",       # vault (optional)
        "prompt",  # age_pass_source
        "y",      # Generate age keypair
        "",       # age_recipients (accept default)
        "n",      # yubikey? no
        "y",      # Generate passphrase? yes
    ])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(inputs))

    cfg = exporter_module.configure_interactive()

    expected = "onep-exporter backup - ci-user"
    assert captured["title"] == expected
    assert public_recipient in cfg["age"]["recipients"]


def test_configure_interactive_reuses_existing_secrets(monkeypatch, tmp_path):
    """When the 1P item already has a private key and passphrase the user should be
    asked whether to reuse them. Choosing 'yes' must NOT overwrite anything."""
    import builtins
    import onep_exporter.exporter as exporter_module
    import onep_exporter.encryption as encryption_module
    import onep_exporter.keychain as keychain_module

    cfg_path = tmp_path / "cfg4.json"
    monkeypatch.setenv("ONEP_EXPORTER_CONFIG", str(cfg_path))
    monkeypatch.setattr(encryption_module, "ensure_tool", lambda name: True)

    # no age-keygen call should happen
    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[0] == "age-keygen":
            raise AssertionError(
                "age-keygen should not be called when reusing")
        return 0, "{}", ""

    monkeypatch.setattr(encryption_module, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(keychain_module, "run_cmd", fake_run_cmd)

    upserted = {}

    def fake_ensure_secrets_item(self, title, vault=None):
        return {
            "id": "existing-item",
            "fields": [
                {"label": "age_private_key", "value": "AGE-SECRET-KEY-EXISTING"},
                {"label": "passphrase", "value": "existing-passphrase"},
                {"label": "age_recipients", "value": "age1existingrecipient"},
            ],
        }

    def fake_upsert(self, item_id, field_label, value, field_type="CONCEALED"):
        upserted[field_label] = value
        return {"id": item_id}

    monkeypatch.setattr(exporter_module.OpExporter,
                        "ensure_secrets_item", fake_ensure_secrets_item)
    monkeypatch.setattr(exporter_module.OpExporter,
                        "upsert_item_field", fake_upsert)

    inputs = iter([
        "", "", "", "",    # basics
        "", "",            # 1P item title + vault
        "prompt",          # pass source
        "y",               # Reuse existing private key? -> yes
        "",                # recipients (accept existing)
        "n",               # yubikey
        "y",               # Reuse existing passphrase? -> yes
    ])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(inputs))

    cfg = exporter_module.configure_interactive()

    # existing recipients should be preserved
    assert "age1existingrecipient" in cfg["age"]["recipients"]
    # private key and passphrase should NOT have been overwritten
    assert "age_private_key" not in upserted
    assert "passphrase" not in upserted


def test_configure_interactive_overwrites_existing_secrets(monkeypatch, tmp_path):
    """When the user chooses to overwrite, new keypair and passphrase should be generated
    and stored, but existing values must NOT be displayed."""
    import builtins
    import onep_exporter.exporter as exporter_module
    import onep_exporter.encryption as encryption_module
    import onep_exporter.keychain as keychain_module

    cfg_path = tmp_path / "cfg5.json"
    monkeypatch.setenv("ONEP_EXPORTER_CONFIG", str(cfg_path))
    monkeypatch.setattr(encryption_module, "ensure_tool", lambda name: True)

    public_recipient = "age1newpub"
    age_out = "AGE-SECRET-KEY-1NEWKEY\npublic key: " + public_recipient + "\n"

    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[0] == "age-keygen":
            return 0, age_out, ""
        return 0, "{}", ""

    monkeypatch.setattr(encryption_module, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(keychain_module, "run_cmd", fake_run_cmd)

    upserted = {}

    def fake_ensure_secrets_item(self, title, vault=None):
        return {
            "id": "existing-item",
            "fields": [
                {"label": "age_private_key", "value": "AGE-SECRET-KEY-OLD"},
                {"label": "passphrase", "value": "old-passphrase"},
                {"label": "age_recipients", "value": "age1oldrecipient"},
            ],
        }

    def fake_upsert(self, item_id, field_label, value, field_type="CONCEALED"):
        upserted[field_label] = value
        return {"id": item_id}

    monkeypatch.setattr(exporter_module.OpExporter,
                        "ensure_secrets_item", fake_ensure_secrets_item)
    monkeypatch.setattr(exporter_module.OpExporter,
                        "upsert_item_field", fake_upsert)

    inputs = iter([
        "", "", "", "",    # basics
        "", "",            # 1P item title + vault
        "prompt",          # pass source
        "n",               # Reuse existing private key? -> NO (overwrite)
        "",                # recipients (accept default, should have new pub)
        "n",               # yubikey
        "n",               # Reuse existing passphrase? -> NO (overwrite)
    ])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(inputs))

    cfg = exporter_module.configure_interactive()

    # new recipient should be present
    assert public_recipient in cfg["age"]["recipients"]
    # private key should have been overwritten with the new one
    assert "age_private_key" in upserted
    assert upserted["age_private_key"] == "AGE-SECRET-KEY-1NEWKEY"
    # passphrase should have been overwritten with a new generated value
    assert "passphrase" in upserted
    assert upserted["passphrase"] != "old-passphrase"
    assert len(upserted["passphrase"]) > 0


def test_cli_init_flagged_runs_doctor_failure(monkeypatch):
    import onep_exporter.cli as cli
    called = {"init_setup": False}

    def fake_init_setup(**kwargs):
        called["init_setup"] = True
        return "pw"
    monkeypatch.setattr(cli, "init_setup", fake_init_setup)
    monkeypatch.setattr(cli, "doctor", lambda: False)
    try:
        cli.main(["init", "--generate"])
    except SystemExit as e:
        assert e.code == 2
        assert called["init_setup"] is True
    else:
        raise AssertionError("expected SystemExit from cli.main")
