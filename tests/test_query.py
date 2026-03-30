import json
from pathlib import Path

import pytest

from onep_exporter.cli import main
from onep_exporter.exporter import query_list_titles


def test_query_list_titles_dir(tmp_path):
    # create some vault JSON files with different titles
    d = tmp_path
    data1 = [{"id": "1", "title": "FooItem"}, {"id": "2", "title": "Bar"}]
    data2 = [{"id": "3", "title": "AnotherFoo"}]
    (d / "vault-a.json").write_text(json.dumps(data1))
    (d / "vault-b.json").write_text(json.dumps(data2))

    # pattern filters case-sensitively
    res = query_list_titles(d, "Foo")
    assert sorted(res) == ["AnotherFoo", "FooItem"]

    # no matches returns empty list
    assert query_list_titles(d, "^Q") == []


def test_query_list_cli(tmp_path, capsys):
    d = tmp_path
    data = [{"id": "1", "title": "baz"}, {"id": "2", "title": "qux"}]
    (d / "vault.json").write_text(json.dumps(data))

    # run command and capture output (cli.main exits via SystemExit)
    with pytest.raises(SystemExit) as exc:
        main(["query", "list", "ba", "--dir", str(d)])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "baz" in captured.out
    assert "qux" not in captured.out


def test_query_list_cli_age_identity(tmp_path, capsys):
    # ensure encrypted archive can be queried via CLI options
    import shutil, subprocess, os
    if shutil.which("age") is None:
        pytest.skip("age not installed")

    root = tmp_path / "out3"
    root.mkdir()
    data = [{"id": "1", "title": "spam"}]
    (root / "vault.json").write_text(json.dumps(data))
    archive = tmp_path / "archive3.tar.gz"
    import tarfile
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root / "vault.json", arcname="vault.json")

    keyfile = tmp_path / "agekey2.txt"
    proc = subprocess.run(["age-keygen", "-o", str(keyfile)], capture_output=True, text=True, check=True)
    pubkey = None
    for line in proc.stderr.splitlines():
        if line.startswith("Public key:"):
            pubkey = line.split(":", 1)[1].strip()
            break
    assert pubkey
    enc = tmp_path / "archive3.tar.gz.age"
    subprocess.run(["age", "-r", pubkey, "-o", str(enc), str(archive)], check=True)

    # use CLI flag to provide identity; should print "spam"
    with pytest.raises(SystemExit) as exc:
        main(["query", "list", "sp", "--dir", str(enc), "--age-identity", str(keyfile)])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "spam" in captured.out


def test_query_list_auto_identity(monkeypatch, tmp_path):
    # if age isn't installed we can't do anything useful
    import shutil, subprocess, os
    if shutil.which("age") is None:
        pytest.skip("age not installed")

    # generate a real age keypair so we know the private key text and public
    # recipient value.
    keyfile = tmp_path / "auto-key.txt"
    proc = subprocess.run(["age-keygen", "-o", str(keyfile)], capture_output=True, text=True, check=True)
    priv = keyfile.read_text()
    pubkey = None
    for line in proc.stderr.splitlines():
        if line.startswith("Public key:"):
            pubkey = line.split(":", 1)[1].strip()
            break
    assert pubkey

    # create a simple tarball and encrypt it to the public key
    root = tmp_path / "out4"
    root.mkdir()
    data = [{"id": "1", "title": "spam"}]
    (root / "vault.json").write_text(json.dumps(data))
    archive = tmp_path / "archive4.tar.gz"
    import tarfile
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root / "vault.json", arcname="vault.json")
    enc = tmp_path / "archive4.tar.gz.age"
    subprocess.run(["age", "-r", pubkey, "-o", str(enc), str(archive)], check=True)

    # configure load_config to return an age config pointing at some item
    cfg = {"age": {"pass_item": "dummy"}}
    monkeypatch.setattr("onep_exporter.config.load_config", lambda: cfg)
    # stub keychain to return nothing so the code falls through to 1Password
    monkeypatch.setattr(
        "onep_exporter.keychain.get_passphrase_from_keychain", lambda service, username: None)
    # stub the exporter method to return our private key when requested
    def fake_get(self, item_ref, field_name=None):
        if field_name == "age_private_key":
            return priv
        return None
    monkeypatch.setattr("onep_exporter.exporter.OpExporter.get_item_field_value", fake_get)

    # ensure no environment vars interfere
    monkeypatch.delenv("BACKUP_PASSPHRASE", raising=False)
    monkeypatch.delenv("AGE_IDENTITIES", raising=False)

    # run query without specifying identity; config+stub should supply it
    res = query_list_titles(enc, "sp")
    assert res == ["spam"]


def test_query_list_keychain_private_key(monkeypatch, tmp_path):
    """Private key stored in keychain is used before falling back to 1Password."""
    import shutil, subprocess, os
    if shutil.which("age") is None:
        pytest.skip("age not installed")

    # generate a real age keypair
    keyfile = tmp_path / "kc-key.txt"
    proc = subprocess.run(
        ["age-keygen", "-o", str(keyfile)], capture_output=True, text=True, check=True)
    priv = keyfile.read_text()
    pubkey = None
    for line in proc.stderr.splitlines():
        if line.startswith("Public key:"):
            pubkey = line.split(":", 1)[1].strip()
            break
    assert pubkey

    # create and encrypt a tarball
    root = tmp_path / "kc-out"
    root.mkdir()
    data = [{"id": "1", "title": "keychain-item"}]
    (root / "vault.json").write_text(json.dumps(data))
    archive = tmp_path / "kc-archive.tar.gz"
    import tarfile
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root / "vault.json", arcname="vault.json")
    enc = tmp_path / "kc-archive.tar.gz.age"
    subprocess.run(["age", "-r", pubkey, "-o", str(enc), str(archive)], check=True)

    # ensure no env vars provide credentials
    monkeypatch.delenv("BACKUP_PASSPHRASE", raising=False)
    monkeypatch.delenv("AGE_IDENTITIES", raising=False)

    # stub load_config to return a minimal config (no pass_item — no 1Password)
    monkeypatch.setattr("onep_exporter.config.load_config", lambda: {"age": {}})

    # stub _get_passphrase_from_keychain to return the private key for the
    # "age_private_key" account, simulating keychain storage
    def fake_keychain(service, username):
        if username == "age_private_key":
            return priv
        return None
    monkeypatch.setattr(
        "onep_exporter.keychain.get_passphrase_from_keychain", fake_keychain)

    res = query_list_titles(enc, "keychain")
    assert res == ["keychain-item"]


def test_resolve_decrypt_credentials_order(monkeypatch, tmp_path):
    """Verify the local-first resolution order of _resolve_decrypt_credentials."""
    from onep_exporter.encryption import resolve_decrypt_credentials as _resolve_decrypt_credentials
    import os

    # 1. env var AGE_IDENTITIES takes priority
    monkeypatch.setenv("AGE_IDENTITIES", "/tmp/fake-id.txt")
    ids, pp = _resolve_decrypt_credentials({"age": {}}, verbose=False)
    assert ids == "/tmp/fake-id.txt"
    assert pp is None
    monkeypatch.delenv("AGE_IDENTITIES")

    # 2. env var BACKUP_PASSPHRASE is next
    monkeypatch.setenv("BACKUP_PASSPHRASE", "secret123")
    ids, pp = _resolve_decrypt_credentials({"age": {}}, verbose=False)
    assert ids is None
    assert pp == "secret123"
    monkeypatch.delenv("BACKUP_PASSPHRASE")

    # 3. keychain private key takes priority over 1Password
    called_1p = False
    def fake_keychain(service, username):
        if username == "age_private_key":
            return "AGE-SECRET-KEY-FAKE"
        return None
    monkeypatch.setattr(
        "onep_exporter.keychain.get_passphrase_from_keychain", fake_keychain)
    def fake_op_get(self, item_ref, field_name=None):
        nonlocal called_1p
        called_1p = True
        return None
    monkeypatch.setattr(
        "onep_exporter.exporter.OpExporter.get_item_field_value", fake_op_get)
    ids, pp = _resolve_decrypt_credentials({"age": {"pass_item": "dummy"}}, verbose=False)
    assert ids is not None  # a temp file path
    assert pp is None
    assert not called_1p, "should NOT have called 1Password when keychain had the key"
    # clean up temp file
    try:
        os.unlink(ids)
    except Exception:
        pass

    # 4. if keychain is empty, falls back to 1Password
    def empty_keychain(service, username):
        return None
    monkeypatch.setattr(
        "onep_exporter.keychain.get_passphrase_from_keychain", empty_keychain)
    def fake_op_get2(self, item_ref, field_name=None):
        if field_name == "age_private_key":
            return "AGE-SECRET-KEY-FROM-1P"
        return None
    monkeypatch.setattr(
        "onep_exporter.exporter.OpExporter.get_item_field_value", fake_op_get2)
    ids, pp = _resolve_decrypt_credentials({"age": {"pass_item": "myitem"}}, verbose=False)
    assert ids is not None
    assert pp is None
    try:
        os.unlink(ids)
    except Exception:
        pass

    # 5. returns (None, None) when nothing is available
    monkeypatch.setattr(
        "onep_exporter.keychain.get_passphrase_from_keychain", empty_keychain)
    def fake_op_empty(self, item_ref, field_name=None):
        return None
    monkeypatch.setattr(
        "onep_exporter.exporter.OpExporter.get_item_field_value", fake_op_empty)
    ids, pp = _resolve_decrypt_credentials({"age": {"pass_item": "myitem"}}, verbose=False)
    assert ids is None
    assert pp is None


def test_query_list_tarball(tmp_path):
    # construct a tar.gz archive containing a vault json
    root = tmp_path / "out"
    root.mkdir()
    data = [{"id": "1", "title": "spam"}, {"id": "2", "title": "eggs"}]
    (root / "vault.json").write_text(json.dumps(data))
    archive = tmp_path / "archive.tar.gz"
    import tarfile
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root / "vault.json", arcname="vault.json")

    res = query_list_titles(archive, "sp")
    assert res == ["spam"]


def test_query_list_age(tmp_path):
    # if the age binary isn't present we can't perform decryption; skip
    import shutil, subprocess
    if shutil.which("age") is None:
        pytest.skip("age not installed")

    # create a simple tarball just like the previous test
    root = tmp_path / "out2"
    root.mkdir()
    data = [{"id": "1", "title": "spam"}, {"id": "2", "title": "eggs"}]
    (root / "vault.json").write_text(json.dumps(data))
    archive = tmp_path / "archive2.tar.gz"
    import tarfile
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root / "vault.json", arcname="vault.json")

    # generate an ephemeral age keypair and extract the public recipient
    keyfile = tmp_path / "agekey.txt"
    proc = subprocess.run(["age-keygen", "-o", str(keyfile)], capture_output=True, text=True, check=True)
    # the command prints the public key on stderr
    pubkey = None
    for line in proc.stderr.splitlines():
        if line.startswith("Public key:"):
            pubkey = line.split(":", 1)[1].strip()
            break
    assert pubkey, "failed to derive public key from age-keygen"

    # encrypt the archive using that recipient (no interaction)
    enc = tmp_path / "archive2.tar.gz.age"
    subprocess.run(["age", "-r", pubkey, "-o", str(enc), str(archive)], check=True)

    # tell query_list_titles where to find the corresponding identity
    import os
    os.environ["AGE_IDENTITIES"] = str(keyfile)

    # the query function should transparently decrypt and search
    res = query_list_titles(enc, "sp")
    assert res == ["spam"]


# ---------------------------------------------------------------------------
# query get (query_get_item + CLI)
# ---------------------------------------------------------------------------

from onep_exporter.exporter import query_get_item


def test_query_get_item_by_title(tmp_path):
    data = [
        {"id": "i1", "title": "FooItem", "fields": [{"label": "password", "value": "secret"}]},
        {"id": "i2", "title": "Bar"},
    ]
    (tmp_path / "vault.json").write_text(json.dumps(data))

    item = query_get_item(tmp_path, "FooItem")
    assert item["id"] == "i1"
    assert item["title"] == "FooItem"


def test_query_get_item_by_id(tmp_path):
    data = [{"id": "abc123", "title": "SomeItem"}]
    (tmp_path / "vault.json").write_text(json.dumps(data))

    item = query_get_item(tmp_path, "abc123")
    assert item["title"] == "SomeItem"


def test_query_get_item_not_found(tmp_path):
    data = [{"id": "i1", "title": "FooItem"}]
    (tmp_path / "vault.json").write_text(json.dumps(data))

    with pytest.raises(KeyError, match="no item found"):
        query_get_item(tmp_path, "DoesNotExist")


def test_query_get_item_ambiguous(tmp_path):
    # two items with the same title in different vault files
    data1 = [{"id": "i1", "title": "Duplicate"}]
    data2 = [{"id": "i2", "title": "Duplicate"}]
    (tmp_path / "vault-a.json").write_text(json.dumps(data1))
    (tmp_path / "vault-b.json").write_text(json.dumps(data2))

    with pytest.raises(ValueError, match="multiple items"):
        query_get_item(tmp_path, "Duplicate")


def test_query_get_item_tarball(tmp_path):
    import tarfile as _tarfile

    root = tmp_path / "out"
    root.mkdir()
    data = [{"id": "t1", "title": "TarItem"}, {"id": "t2", "title": "Other"}]
    (root / "vault.json").write_text(json.dumps(data))
    archive = tmp_path / "archive.tar.gz"
    with _tarfile.open(archive, "w:gz") as tf:
        tf.add(root / "vault.json", arcname="vault.json")

    item = query_get_item(archive, "TarItem")
    assert item["id"] == "t1"


def test_query_get_cli_json(tmp_path, capsys):
    data = [{"id": "x1", "title": "MyPass", "fields": []}]
    (tmp_path / "vault.json").write_text(json.dumps(data))

    with pytest.raises(SystemExit) as exc:
        main(["query", "get", "MyPass", "--dir", str(tmp_path), "--format", "json"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["id"] == "x1"


def test_query_get_cli_md(tmp_path, capsys):
    data = [{"id": "x2", "title": "MDItem", "fields": []}]
    (tmp_path / "vault.json").write_text(json.dumps(data))

    with pytest.raises(SystemExit) as exc:
        main(["query", "get", "MDItem", "--dir", str(tmp_path), "--format", "md"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "MDItem" in captured.out


def test_query_get_cli_default_md(tmp_path, capsys):
    """Default output format (no --format flag) should be markdown."""
    data = [{"id": "x2d", "title": "DefaultMD", "fields": []}]
    (tmp_path / "vault.json").write_text(json.dumps(data))

    with pytest.raises(SystemExit) as exc:
        main(["query", "get", "DefaultMD", "--dir", str(tmp_path)])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "DefaultMD" in captured.out
    # must NOT be raw JSON (no leading '{')
    assert not captured.out.strip().startswith("{")


def test_query_get_cli_field(tmp_path, capsys):
    data = [{"id": "x3", "title": "FieldItem", "fields": [
        {"label": "password", "name": "password", "value": "hunter2"}
    ]}]
    (tmp_path / "vault.json").write_text(json.dumps(data))

    with pytest.raises(SystemExit) as exc:
        main(["query", "get", "FieldItem", "--dir", str(tmp_path), "--field", "password"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == "hunter2"


def test_query_get_cli_field_missing(tmp_path, capsys):
    data = [{"id": "x4", "title": "NoField", "fields": []}]
    (tmp_path / "vault.json").write_text(json.dumps(data))

    with pytest.raises(SystemExit) as exc:
        main(["query", "get", "NoField", "--dir", str(tmp_path), "--field", "nonexistent"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "error" in captured.out


def test_query_get_cli_not_found(tmp_path, capsys):
    data = [{"id": "x5", "title": "Something"}]
    (tmp_path / "vault.json").write_text(json.dumps(data))

    with pytest.raises(SystemExit) as exc:
        main(["query", "get", "NotHere", "--dir", str(tmp_path)])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "error" in captured.out
