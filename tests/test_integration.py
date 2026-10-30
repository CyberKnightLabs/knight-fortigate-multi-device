import json
import tomllib

import pytest

import ai_client_integration as codex
import claude_integration as claude
import manager


@pytest.mark.parametrize('client', ['codex', 'claude'])
def test_two_devices_preserve_existing_settings(tmp_path, monkeypatch, client):
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'server.py').touch()
    (project / 'pyproject.toml').touch()
    path = tmp_path / ('config.toml' if client == 'codex' else 'config.json')
    if client == 'codex':
        path.write_text('model = "existing"\n[mcp_servers.other]\ncommand = "other"\n')
        module, build, apply = codex, codex.build_codex_plan, codex.apply_codex_plan
    else:
        path.write_text(json.dumps({'theme': 'existing', 'mcpServers': {'other': {'command': 'other'}}}))
        module, build, apply = claude, claude.build_claude_plan, claude.apply_claude_plan
    monkeypatch.setattr(module, 'detect_ai_clients', lambda: {client: {'config': str(path)}})
    monkeypatch.setattr(module.shutil, 'which', lambda _: '/example/uv')
    original = path.read_bytes()
    for name in ['LAB-A', 'LAB-B']:
        plan = build(project, name)
        backup = apply(plan)
        assert __import__('pathlib').Path(backup).exists()
    result = tomllib.loads(path.read_text()) if client == 'codex' else json.loads(path.read_text())
    servers = result['mcp_servers' if client == 'codex' else 'mcpServers']
    assert servers['other'] == {'command': 'other'}
    for name in ['LAB-A', 'LAB-B']:
        assert servers['fortigate-' + name]['env'] == {'FORTIGATE_DEVICE': name}
    assert result['model' if client == 'codex' else 'theme'] == 'existing'
    assert 'API_TOKEN' not in path.read_text()
    if client == 'codex':
        before = path.read_bytes()
        with pytest.raises(RuntimeError):
            apply(build(project, 'LAB-A'))
        assert path.read_bytes() == before
    else:
        apply(build(project, 'LAB-A'))


def test_wizard_exit_without_writing(tmp_path, monkeypatch):
    path = tmp_path / 'config.json'
    monkeypatch.setattr(manager, 'CONFIG_FILE', path)
    monkeypatch.setattr('builtins.input', lambda _: '0')
    manager.main()
    assert not path.exists()
