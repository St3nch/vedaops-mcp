"""Operator policy, principal grants, and manifest narrowing."""

from __future__ import annotations

from pathlib import Path

import pytest
from support import init_project, write_manifest, write_registry

from vedaops_mcp.authority import (
    get_authorized_check,
    get_authorized_project,
    get_project_detail,
    list_authorized_projects,
    load_registry,
)
from vedaops_mcp.errors import AuthorityError, IdentityError
from vedaops_mcp.inspect import observe_git


def test_registry_inside_a_managed_project_root_is_refused(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    inside = root / "config"
    inside.mkdir()
    registry = write_registry(inside / "projects.toml", root=root)

    with pytest.raises(AuthorityError, match="VEDAOPS_TRUSTED_PATH_INSIDE_MANAGED_PROJECT"):
        load_registry(registry)


def test_registry_outside_every_managed_project_root_loads(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    registry = write_registry(tmp_path / "projects.toml", root=root)

    result = list_authorized_projects(registry, principal_id="test-agent", cursor=None, limit=50)

    assert result.total_count == 1
    assert result.projects[0].id == "example"
    assert result.projects[0].workspace_id == "primary"
    assert result.projects[0].authorized is True


def test_unknown_principal_is_refused(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    registry = write_registry(tmp_path / "projects.toml", root=root)

    with pytest.raises(IdentityError, match="VEDAOPS_PRINCIPAL_UNKNOWN"):
        list_authorized_projects(registry, principal_id="other-agent", cursor=None, limit=50)


def test_principal_without_a_grant_does_not_see_the_project(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        principal_capabilities=(),
    )

    result = list_authorized_projects(registry, principal_id="test-agent", cursor=None, limit=50)
    assert result.total_count == 0

    with pytest.raises(AuthorityError, match="VEDAOPS_PROJECT_NOT_AUTHORIZED"):
        get_authorized_project(
            registry,
            principal_id="test-agent",
            project_id="example",
            capability="read",
        )


def test_manifest_narrows_and_cannot_expand_the_registry(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root, capabilities=())
    registry = write_registry(tmp_path / "projects.toml", root=root, capabilities=("read",))

    with pytest.raises(AuthorityError, match="VEDAOPS_CAPABILITY_DENIED"):
        get_authorized_project(
            registry,
            principal_id="test-agent",
            project_id="example",
            capability="read",
        )


def test_manifest_cannot_grant_a_capability_the_registry_withholds(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root, capabilities=("read",))
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        capabilities=("read",),
        principal_capabilities=(),
    )

    with pytest.raises(AuthorityError, match="VEDAOPS_PROJECT_NOT_AUTHORIZED"):
        get_authorized_project(
            registry,
            principal_id="test-agent",
            project_id="example",
            capability="read",
        )


def test_absent_manifest_narrows_every_capability_to_nothing(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    (root / ".vedaops" / "project.toml").unlink()
    registry = write_registry(tmp_path / "projects.toml", root=root)

    with pytest.raises(AuthorityError, match="VEDAOPS_MANIFEST_UNAVAILABLE"):
        get_authorized_project(
            registry,
            principal_id="test-agent",
            project_id="example",
            capability="read",
        )

    detail = get_project_detail(
        registry,
        principal_id="test-agent",
        project_id="example",
        git_orientation=observe_git(root),
    )
    assert detail.registry_capabilities == ["read"]
    assert detail.effective_capabilities == []
    assert detail.manifest_valid is False
    assert detail.authorized is False


def test_invalid_manifest_narrows_to_nothing(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    write_manifest(root, extra="not_toml = {\n")
    registry = write_registry(tmp_path / "projects.toml", root=root)

    with pytest.raises(AuthorityError, match="VEDAOPS_MANIFEST_INVALID"):
        get_authorized_project(
            registry,
            principal_id="test-agent",
            project_id="example",
            capability="read",
        )


def test_unknown_capability_is_refused_at_registry_load(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    registry = tmp_path / "projects.toml"
    registry.write_text(
        "schema_version = 1\n\n"
        "[[projects]]\n"
        "id = 'example'\n"
        "name = 'Example'\n"
        "status = 'active'\n"
        f"root = {str(root)!r}\n"
        "workspace_id = 'primary'\n"
        "mutable = false\n"
        'capabilities = ["read", "execute"]\n'
        "context_files = []\n\n"
        "[[principals]]\n"
        "id = 'test-agent'\n"
        "[principals.projects]\n"
        'example = ["read"]\n'
    )
    registry.chmod(0o600)

    with pytest.raises(AuthorityError, match="VEDAOPS_REGISTRY_INVALID"):
        load_registry(registry)


def test_inactive_status_revokes_authorization(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    registry = write_registry(tmp_path / "projects.toml", root=root, status="retired")

    with pytest.raises(AuthorityError, match="VEDAOPS_PROJECT_INACTIVE"):
        get_authorized_project(
            registry,
            principal_id="test-agent",
            project_id="example",
            capability="read",
        )

    listed = list_authorized_projects(registry, principal_id="test-agent", cursor=None, limit=50)
    assert listed.projects[0].authorized is False
    assert listed.projects[0].status == "retired"


def test_manifest_id_mismatch_is_a_collision(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root)
    write_manifest(root, project_id="other")
    registry = write_registry(tmp_path / "projects.toml", root=root)

    with pytest.raises(AuthorityError, match="VEDAOPS_PROJECT_ID_COLLISION"):
        get_authorized_project(
            registry,
            principal_id="test-agent",
            project_id="example",
            capability="read",
        )


def test_effective_authority_is_the_three_way_intersection(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root, capabilities=("read",))
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        capabilities=("read",),
        principal_capabilities=("read",),
    )

    authorized = get_authorized_project(
        registry,
        principal_id="test-agent",
        project_id="example",
        capability="read",
    )
    assert authorized.capabilities == frozenset({"read"})
    assert authorized.workspace_id == "primary"
    assert authorized.workspace_kind == "ordinary"
    assert authorized.principal_id == "test-agent"


def test_check_capability_resolves_only_operator_defined_checks(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root, capabilities=("read", "check"))
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        capabilities=("read", "check"),
        principal_capabilities=("read", "check"),
        checks_toml=(
            "\n[[projects.checks]]\n"
            "id = 'syntax'\n"
            "argv = ['/usr/bin/python3', '-m', 'compileall', '-q', 'src']\n"
            "timeout_seconds = 30\n"
            "memory_mb = 512\n"
        ),
    )

    project, check = get_authorized_check(
        registry,
        principal_id="test-agent",
        project_id="example",
        check_id="syntax",
    )
    assert "check" in project.capabilities
    assert check.argv[0] == "/usr/bin/python3"
    assert check.timeout_seconds == 30
    detail = get_project_detail(
        registry,
        principal_id="test-agent",
        project_id="example",
        git_orientation=observe_git(root),
    )
    assert detail.check_ids == ["syntax"]

    with pytest.raises(AuthorityError, match="VEDAOPS_CHECK_NOT_AUTHORIZED"):
        get_authorized_check(
            registry, principal_id="test-agent", project_id="example", check_id="missing"
        )


def test_check_capability_can_be_denied_by_principal_grant(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root, capabilities=("read", "check"))
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        capabilities=("read", "check"),
        principal_capabilities=("read",),
        checks_toml=(
            "\n[[projects.checks]]\n"
            "id = 'syntax'\n"
            "argv = ['/usr/bin/python3', '-m', 'compileall', '-q', 'src']\n"
        ),
    )

    with pytest.raises(AuthorityError, match="VEDAOPS_CAPABILITY_DENIED"):
        get_authorized_check(
            registry, principal_id="test-agent", project_id="example", check_id="syntax"
        )


def test_check_capability_can_be_denied_by_project_manifest(tmp_path: Path):
    root = tmp_path / "project"
    init_project(root, capabilities=("read",))
    registry = write_registry(
        tmp_path / "projects.toml",
        root=root,
        capabilities=("read", "check"),
        principal_capabilities=("read", "check"),
        checks_toml=(
            "\n[[projects.checks]]\n"
            "id = 'syntax'\n"
            "argv = ['/usr/bin/python3', '-m', 'compileall', '-q', 'src']\n"
        ),
    )

    with pytest.raises(AuthorityError, match="VEDAOPS_CAPABILITY_DENIED"):
        get_authorized_check(
            registry, principal_id="test-agent", project_id="example", check_id="syntax"
        )
