#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# resolver.py - 内核源码树定位与路径安全校验
"""Locate and validate the kernel source tree that matches a vmcore.

Two sources of configuration, in priority order:

1. a per-request path (``--kernel-source-root`` on the client, carried through
   ``AgentState`` and injected into the tool payload); typically the tree that
   ``rpmbuild -bp kernel.spec`` produced, i.e. ``BUILD/kernel-<ver>/linux-<ver>/``;
2. ``KERNEL_SOURCE_ROOT`` from the process environment / ``.env``, used as the
   deployment-wide default when the request does not carry a path.

Any source-level claim the agent makes must be traceable to this tree.  When no
tree matches the dump, callers return an explicit "source unavailable" message
instead of letting the model fall back to its memory of kernel code.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

try:  # .env is optional for standalone use (tests, ad-hoc scripts).
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - python-dotenv is a declared dependency
    load_dotenv = None

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
if load_dotenv is not None:
    load_dotenv(_PROJECT_ROOT / ".env", override=False)

ENV_VAR = "KERNEL_SOURCE_ROOT"
ENV_ALLOWED_ROOTS = "KERNEL_SOURCE_ALLOWED_ROOTS"

# Upper bound on directories inspected while locating a tree below a given root.
_MAX_SCANNED_DIRS = 5_000

_MAKEFILE_VERSION_RE = re.compile(
    r"^\s*(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)\s*=\s*(.*?)\s*$"
)
# rpmbuild -bp leaves the tree as BUILD/kernel-<ver>/linux-<full-ver>/ ; the
# directory name is often the only place that carries the distro suffix.
_DIR_VERSION_RE = re.compile(r"linux-(\d+\.\d+\.\d+[^\s/\\]*)")


class SourceTreeError(RuntimeError):
    """Raised when the configured source tree cannot satisfy a request."""


@dataclass(frozen=True)
class SourceTree:
    """A kernel source tree usable for source-level reasoning."""

    root: Path
    version: str
    has_git: bool
    # Set when the tree version and the requested kver differ only in their
    # dist/arch suffix (e.g. tree linux-...el9.x86_64 for an el8_10 kernel).
    note: str = ""

    @property
    def basis(self) -> str:
        return "git" if self.has_git else "snapshot"


def _read_kernel_release(root: Path) -> str:
    release_file = root / "include" / "config" / "kernel.release"
    try:
        return release_file.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _read_makefile_version(root: Path) -> str:
    try:
        text = (root / "Makefile").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    parts: dict[str, str] = {}
    for line in text.splitlines():
        match = _MAKEFILE_VERSION_RE.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip().strip('"')
        parts[key] = value
        if key == "EXTRAVERSION":
            break
    if "VERSION" not in parts:
        return ""
    version = ".".join(
        parts.get(key, "0") for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL")
    )
    extra = parts.get("EXTRAVERSION", "")
    if not extra:
        return version
    return f"{version}{extra if extra.startswith(('-', '_')) else '-' + extra}"


def _version_from_name(root: Path) -> str:
    match = _DIR_VERSION_RE.search(root.name)
    return match.group(1).strip("-_ ") if match else ""


def is_kernel_tree(path: Path) -> bool:
    """Return True when ``path`` looks like an unpacked kernel source tree."""

    try:
        if not (path / "Makefile").is_file():
            return False
    except OSError:
        return False
    return (path / "kernel").is_dir() or (path / "include" / "linux").is_dir()


def tree_version(root: Path) -> str:
    """Best-effort kernel version of a source tree.

    ``include/config/kernel.release`` is authoritative for a built tree.  For a
    ``rpmbuild -bp`` tree it does not exist, and the Makefile may still carry the
    upstream version while ``EXTRAVERSION`` is passed on the make command line —
    in that case the ``linux-<version>`` directory name is the accurate answer.
    """

    release = _read_kernel_release(root)
    if release:
        return release
    makefile = _read_makefile_version(root)
    from_name = _version_from_name(root)
    if from_name and (not makefile or from_name.startswith(makefile)):
        return from_name
    return makefile


def normalize_kver(value: str) -> str:
    """Normalize a ``crash`` KERNEL string for comparison."""

    return " ".join(str(value or "").split()).strip().strip("'\"")


def version_core(value: str) -> str:
    """Strip the dist tag and arch suffix.

    ``4.18.0-553.22.1.el8_10.x86_64`` and ``4.18.0-553.22.1.el9.x86_64`` both
    reduce to ``4.18.0-553.22.1``.  rpmbuild uses the host's ``%{?dist}`` when it
    names the prepared tree, so a tree prepped on a different RHEL major can
    carry a dist tag that does not match the dump even though the upstream base
    and the applied patches are the same.
    """

    normalized = normalize_kver(value)
    marker = normalized.find(".el")
    return normalized[:marker] if marker > 0 else normalized


def _find_trees(
    base: Path, depth: int = 3, budget: list[int] | None = None
) -> list[Path]:
    """Collect source trees at ``base`` or up to ``depth`` levels below it.

    Three levels cover the rpmbuild layout the helper script produces:
    ``<topdir>/BUILD/kernel-<ver>/linux-<ver>/``.  A directory budget keeps a
    mistakenly broad root (``/usr/src``) from turning into a full filesystem walk.
    """

    budget = budget if budget is not None else [_MAX_SCANNED_DIRS]
    if budget[0] <= 0:
        return []
    budget[0] -= 1

    if is_kernel_tree(base):
        return [base]
    if depth <= 0:
        return []
    try:
        children = sorted(child for child in base.iterdir() if child.is_dir())
    except OSError:
        return []
    found: list[Path] = []
    for child in children:
        found.extend(_find_trees(child, depth - 1, budget))
        if budget[0] <= 0:
            break
    return found


def find_kernel_trees(base: str | Path) -> list[Path]:
    """Return the kernel source trees at or below ``base`` (request validation)."""

    try:
        path = Path(base).expanduser().resolve()
    except OSError:
        return []
    if not path.is_dir():
        return []
    return _find_trees(path)


def _allowed_roots() -> list[Path]:
    raw = os.environ.get(ENV_ALLOWED_ROOTS, "").strip()
    if not raw:
        return []
    roots = []
    for part in re.split(r"[;,\n]", raw):
        part = part.strip()
        if not part:
            continue
        try:
            roots.append(Path(part).expanduser().resolve())
        except OSError:
            continue
    return roots


def _check_allowed(root: Path) -> None:
    """Reject a request-supplied path outside the optional deployment allowlist."""

    allowed = _allowed_roots()
    if not allowed:
        return
    for candidate in allowed:
        if root == candidate or candidate in root.parents:
            return
    raise SourceTreeError(
        f"kernel source root {root} is outside {ENV_ALLOWED_ROOTS}; "
        "ask the administrator to add it to the allowlist"
    )


def _current_uid() -> str:
    getuid = getattr(os, "getuid", None)
    return str(getuid()) if getuid is not None else "n/a"


def resolve_tree(requested_kver: str = "", requested_root: str = "") -> SourceTree:
    """Resolve the source tree for ``requested_kver``.

    The per-request ``requested_root`` wins over ``KERNEL_SOURCE_ROOT``.

    Raises:
        SourceTreeError: when nothing is configured, the path is not a kernel
            tree, the allowlist rejects it, the version does not match, or the
            choice between several trees is ambiguous.
    """

    configured = str(requested_root or "").strip() or os.environ.get(ENV_VAR, "").strip()
    origin = (
        "kernel_source_root request field"
        if str(requested_root or "").strip()
        else f"{ENV_VAR} environment variable"
    )
    if not configured:
        raise SourceTreeError(
            "no kernel source tree is configured (pass --kernel-source-root or set "
            f"{ENV_VAR}); kernel source could not be verified for this dump. "
            "Do not quote kernel source from memory."
        )

    base = Path(configured).expanduser()
    try:
        base.stat()
    except PermissionError:
        raise SourceTreeError(
            f"source root from {origin} exists but is not accessible to the account "
            f"running the service (uid={_current_uid()}): {configured}. "
            "Fix ownership/permissions or run the service as a user that can read it."
        ) from None
    except OSError:
        raise SourceTreeError(
            f"source root from {origin} does not exist: {configured}"
        ) from None
    if not base.is_dir():
        raise SourceTreeError(
            f"source root from {origin} is not a directory: {configured}"
        )
    base = base.resolve()
    _check_allowed(base)

    candidates = _find_trees(base)
    if not candidates:
        raise SourceTreeError(
            f"no kernel source tree found under {base} "
            "(expected a Makefile plus kernel/ or include/linux/)"
        )

    scored: list[tuple[Path, str]] = [(path, tree_version(path)) for path in candidates]
    requested = normalize_kver(requested_kver)
    note = ""

    if requested:
        exact = [
            (path, version)
            for path, version in scored
            if version and normalize_kver(version) == requested
        ]
        if exact:
            scored = exact
        else:
            core = version_core(requested)
            tolerant = [
                (path, version)
                for path, version in scored
                if version and version_core(version) == core
            ]
            by_name = [
                (path, version)
                for path, version in scored
                if path.name.strip() == requested
            ]
            if len(tolerant) == 1:
                scored = tolerant
                tree_version_string = tolerant[0][1]
                note = (
                    "source tree version "
                    f"{tree_version_string!r} differs from the requested kver "
                    f"{requested!r} only in its dist/arch suffix; the upstream base "
                    "matches, but distro patch levels may differ"
                )
            elif by_name:
                scored = by_name
            else:
                known = ", ".join(
                    f"{path.name}={version or 'unknown'}" for path, version in scored
                )
                raise SourceTreeError(
                    f"SOURCE_TREE_MISMATCH: requested kver={requested!r} does not "
                    f"match any configured tree ({known}) from {origin}; source-level "
                    "reasoning from the wrong tree would be invalid"
                )

    if len(scored) == 1:
        path, version = scored[0]
        return SourceTree(
            path.resolve(), version, (path / ".git").exists(), note=note
        )

    known = ", ".join(f"{path.name}={version or 'unknown'}" for path, version in scored)
    raise SourceTreeError(
        f"multiple kernel source trees are configured under {base} ({known}); "
        "pass kver with the exact KERNEL value from `sys`, or point the request at "
        "one specific tree"
    )


def resolve_relative_file(tree: SourceTree, file: str) -> Path:
    """Resolve ``file`` inside ``tree`` and reject anything outside it."""

    raw = str(file or "").strip().strip("'\"")
    if not raw:
        raise SourceTreeError("file is required")

    # ``dis -s`` prints "path:line"; accept that form as well.
    raw = raw.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", raw):
        raise SourceTreeError(
            "absolute paths are not allowed; pass the path as printed by dis -s, "
            "relative to the kernel tree root"
        )
    if raw.startswith("/"):
        raise SourceTreeError(
            "absolute paths are not allowed; pass the path as printed by dis -s, "
            "relative to the kernel tree root"
        )
    if re.match(r"^[\w./\\-]+:\d+$", raw):
        raw = raw.rpartition(":")[0]

    root = tree.root
    candidate = (root / raw).resolve()
    if candidate != root and root not in candidate.parents:
        raise SourceTreeError(
            f"path escapes the configured kernel tree: {raw}"
        )
    if not candidate.is_file():
        raise SourceTreeError(f"file not found in kernel tree: {raw}")
    return candidate


def relative_name(tree: SourceTree, path: Path) -> str:
    """Return the path relative to the tree root, using forward slashes."""

    try:
        return path.resolve().relative_to(tree.root).as_posix()
    except ValueError:
        return path.name