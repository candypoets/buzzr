from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_AVATAR_PACK = "bees-v1"
AVATAR_PACKS_ROOT = Path(__file__).resolve().parents[1] / "assets" / "avatars"
PACK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class AvatarPackError(ValueError):
    """Raised when an avatar pack is malformed or unsafe to use."""


@dataclass(frozen=True)
class AvatarAsset:
    asset_id: str
    collection: str
    path: Path
    sha256: str


@dataclass(frozen=True)
class AvatarPack:
    pack_id: str
    root: Path
    assets: tuple[AvatarAsset, ...]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pack_root(pack_id: str, custom_path: Path | None) -> Path:
    if custom_path is not None:
        return custom_path.expanduser().resolve()
    if not PACK_ID_RE.fullmatch(pack_id):
        raise AvatarPackError(f"invalid bundled avatar pack id: {pack_id!r}")
    return (AVATAR_PACKS_ROOT / pack_id).resolve()


def load_avatar_pack(
    pack_id: str = DEFAULT_AVATAR_PACK,
    custom_path: Path | None = None,
) -> AvatarPack:
    """Load and integrity-check a bundled or user-supplied avatar pack."""

    root = _pack_root(pack_id, custom_path)
    manifest_path = root / "manifest.json"
    try:
        manifest: Any = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AvatarPackError(f"avatar pack manifest does not exist: {manifest_path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AvatarPackError(f"cannot read avatar pack manifest {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict):
        raise AvatarPackError(f"avatar pack manifest must be an object: {manifest_path}")

    manifest_id = manifest.get("id")
    if not isinstance(manifest_id, str) or not PACK_ID_RE.fullmatch(manifest_id):
        raise AvatarPackError("avatar pack manifest has an invalid id")
    raw_assets = manifest.get("assets")
    if not isinstance(raw_assets, list) or not raw_assets:
        raise AvatarPackError("avatar pack manifest must contain at least one asset")

    assets: list[AvatarAsset] = []
    seen_ids: set[str] = set()
    seen_files: set[Path] = set()
    for index, raw in enumerate(raw_assets):
        if not isinstance(raw, dict):
            raise AvatarPackError(f"avatar entry {index} must be an object")
        asset_id = raw.get("id")
        collection = raw.get("collection")
        filename = raw.get("file")
        expected_sha256 = raw.get("sha256")
        if not isinstance(asset_id, str) or not PACK_ID_RE.fullmatch(asset_id):
            raise AvatarPackError(f"avatar entry {index} has an invalid id")
        if asset_id in seen_ids:
            raise AvatarPackError(f"duplicate avatar id: {asset_id}")
        if not isinstance(collection, str) or not collection.strip():
            raise AvatarPackError(f"avatar {asset_id} has an invalid collection")
        if not isinstance(filename, str) or not filename:
            raise AvatarPackError(f"avatar {asset_id} has an invalid file")
        if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
            raise AvatarPackError(f"avatar {asset_id} has an invalid sha256")

        asset_path = (root / filename).resolve()
        try:
            asset_path.relative_to(root)
        except ValueError as exc:
            raise AvatarPackError(f"avatar {asset_id} escapes its pack directory") from exc
        if asset_path.suffix.lower() not in {".png", ".jpg", ".jpeg", ".webp"}:
            raise AvatarPackError(f"avatar {asset_id} uses an unsupported image format")
        if asset_path in seen_files:
            raise AvatarPackError(f"duplicate avatar file: {filename}")
        if not asset_path.is_file():
            raise AvatarPackError(f"avatar file does not exist: {asset_path}")
        actual_sha256 = _sha256(asset_path)
        if actual_sha256 != expected_sha256:
            raise AvatarPackError(f"avatar {asset_id} failed its sha256 integrity check")

        seen_ids.add(asset_id)
        seen_files.add(asset_path)
        assets.append(
            AvatarAsset(
                asset_id=asset_id,
                collection=collection,
                path=asset_path,
                sha256=actual_sha256,
            )
        )

    return AvatarPack(pack_id=manifest_id, root=root, assets=tuple(assets))


def select_avatar(
    pack: AvatarPack,
    public_key: str,
    excluded_ids: set[str] | frozenset[str] = frozenset(),
) -> AvatarAsset:
    """Select a stable pseudo-random avatar, avoiding assigned IDs when possible."""

    candidates = [asset for asset in pack.assets if asset.asset_id not in excluded_ids]
    if not candidates:
        candidates = list(pack.assets)
    seed = f"buzzr-avatar-v1:{pack.pack_id}:{public_key.lower()}:"
    return max(
        candidates,
        key=lambda asset: hashlib.sha256(
            (seed + asset.asset_id).encode("utf-8")
        ).digest(),
    )
