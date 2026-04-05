import pytest

from onep_exporter import cli as cli_module
from onep_exporter import exporter as exporter_module


def test_cli_exits_nonzero_on_op_item_failure(monkeypatch, tmp_path):
    # avoid checking for 'op' binary
    monkeypatch.setattr(exporter_module, "ensure_tool", lambda name: True)

    # fake a single vault and a single item summary
    monkeypatch.setattr(exporter_module.OpExporter, "list_vaults", lambda self: [{"id": "v1", "name": "Vault1"}])
    monkeypatch.setattr(exporter_module.OpExporter, "list_items", lambda self, vault_id: [{"id": "i1"}])

    # simulate a failure when fetching the full item
    def fail_get_item(self, item_id):
        raise Exception("op item get failed: promptError")

    monkeypatch.setattr(exporter_module.OpExporter, "get_item", fail_get_item)

    # run CLI; it should sys.exit(1) when run_backup raises and CLI handles it
    with pytest.raises(SystemExit) as se:
        cli_module.main(["backup", "--output", str(tmp_path), "--quiet"])
    assert se.value.code == 1
