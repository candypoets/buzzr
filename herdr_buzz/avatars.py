from __future__ import annotations

import binascii
import hashlib
import json
import os
import re
import struct
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_AVATAR_PACK = "bees-v2"
AVATAR_PACKS_ROOT = Path(__file__).resolve().parents[1] / "assets" / "avatars"
PACK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
COMPOSITOR_VERSION = 1
MAX_CANVAS_EDGE = 2048


class AvatarPackError(ValueError):
    """Raised when an avatar pack is malformed or unsafe to use."""


@dataclass(frozen=True)
class AvatarAsset:
    asset_id: str
    collection: str
    path: Path
    sha256: str
    traits: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class AvatarTrait:
    trait_id: str
    path: Path | None
    sha256: str | None


@dataclass(frozen=True)
class AvatarLayer:
    layer_id: str
    z_index: int
    traits: tuple[AvatarTrait, ...]


@dataclass(frozen=True)
class AvatarPack:
    pack_id: str
    root: Path
    assets: tuple[AvatarAsset, ...] = ()
    layers: tuple[AvatarLayer, ...] = ()
    width: int = 0
    height: int = 0
    version: int = 1

    @property
    def layered(self) -> bool:
        return bool(self.layers)

    @property
    def combination_count(self) -> int:
        if not self.layered:
            return len(self.assets)
        result = 1
        for layer in self.layers:
            result *= len(layer.traits)
        return result


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


def _asset_path(root: Path, filename: Any, asset_id: str, suffixes: set[str]) -> Path:
    if not isinstance(filename, str) or not filename:
        raise AvatarPackError(f"avatar {asset_id} has an invalid file")
    path = (root / filename).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise AvatarPackError(f"avatar {asset_id} escapes its pack directory") from exc
    if path.suffix.lower() not in suffixes:
        raise AvatarPackError(f"avatar {asset_id} uses an unsupported image format")
    if not path.is_file():
        raise AvatarPackError(f"avatar file does not exist: {path}")
    return path


def _load_flat_pack(root: Path, manifest_id: str, manifest: dict[str, Any]) -> AvatarPack:
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
        expected_sha256 = raw.get("sha256")
        if not isinstance(asset_id, str) or not PACK_ID_RE.fullmatch(asset_id):
            raise AvatarPackError(f"avatar entry {index} has an invalid id")
        if asset_id in seen_ids:
            raise AvatarPackError(f"duplicate avatar id: {asset_id}")
        if not isinstance(collection, str) or not collection.strip():
            raise AvatarPackError(f"avatar {asset_id} has an invalid collection")
        if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
            raise AvatarPackError(f"avatar {asset_id} has an invalid sha256")

        path = _asset_path(
            root,
            raw.get("file"),
            asset_id,
            {".png", ".jpg", ".jpeg", ".webp"},
        )
        if path in seen_files:
            raise AvatarPackError(f"duplicate avatar file: {raw.get('file')}")
        actual_sha256 = _sha256(path)
        if actual_sha256 != expected_sha256:
            raise AvatarPackError(f"avatar {asset_id} failed its sha256 integrity check")

        seen_ids.add(asset_id)
        seen_files.add(path)
        assets.append(
            AvatarAsset(
                asset_id=asset_id,
                collection=collection,
                path=path,
                sha256=actual_sha256,
            )
        )

    return AvatarPack(pack_id=manifest_id, root=root, assets=tuple(assets))


def _png_info(path: Path) -> tuple[int, int]:
    try:
        header = path.read_bytes()[:33]
    except OSError as exc:
        raise AvatarPackError(f"cannot read PNG layer {path}: {exc}") from exc
    if len(header) != 33 or header[:8] != PNG_SIGNATURE:
        raise AvatarPackError(f"avatar layer is not a valid PNG: {path}")
    length = struct.unpack(">I", header[8:12])[0]
    if length != 13 or header[12:16] != b"IHDR":
        raise AvatarPackError(f"avatar layer has no valid IHDR chunk: {path}")
    width, height, depth, color_type, compression, filtering, interlace = struct.unpack(
        ">IIBBBBB", header[16:29]
    )
    if (
        depth != 8
        or color_type != 6
        or compression != 0
        or filtering != 0
        or interlace != 0
    ):
        raise AvatarPackError(
            f"avatar layer must be a non-interlaced 8-bit RGBA PNG: {path}"
        )
    return width, height


def _load_layered_pack(
    root: Path,
    manifest_id: str,
    manifest: dict[str, Any],
) -> AvatarPack:
    canvas = manifest.get("canvas")
    if not isinstance(canvas, dict):
        raise AvatarPackError("layered avatar pack must define a canvas")
    width = canvas.get("width")
    height = canvas.get("height")
    if (
        not isinstance(width, int)
        or isinstance(width, bool)
        or not isinstance(height, int)
        or isinstance(height, bool)
        or not 0 < width <= MAX_CANVAS_EDGE
        or not 0 < height <= MAX_CANVAS_EDGE
    ):
        raise AvatarPackError("layered avatar pack has invalid canvas dimensions")

    raw_layers = manifest.get("layers")
    if not isinstance(raw_layers, list) or not raw_layers:
        raise AvatarPackError("layered avatar pack must contain at least one layer")
    layers: list[AvatarLayer] = []
    seen_layer_ids: set[str] = set()
    seen_files: set[Path] = set()
    for layer_index, raw_layer in enumerate(raw_layers):
        if not isinstance(raw_layer, dict):
            raise AvatarPackError(f"avatar layer {layer_index} must be an object")
        layer_id = raw_layer.get("id")
        z_index = raw_layer.get("z", layer_index)
        raw_traits = raw_layer.get("traits")
        if not isinstance(layer_id, str) or not PACK_ID_RE.fullmatch(layer_id):
            raise AvatarPackError(f"avatar layer {layer_index} has an invalid id")
        if layer_id in seen_layer_ids:
            raise AvatarPackError(f"duplicate avatar layer id: {layer_id}")
        if not isinstance(z_index, int) or isinstance(z_index, bool):
            raise AvatarPackError(f"avatar layer {layer_id} has an invalid z index")
        if not isinstance(raw_traits, list) or not raw_traits:
            raise AvatarPackError(f"avatar layer {layer_id} has no traits")

        traits: list[AvatarTrait] = []
        seen_trait_ids: set[str] = set()
        for trait_index, raw_trait in enumerate(raw_traits):
            if not isinstance(raw_trait, dict):
                raise AvatarPackError(
                    f"trait {trait_index} in avatar layer {layer_id} must be an object"
                )
            trait_id = raw_trait.get("id")
            if not isinstance(trait_id, str) or not PACK_ID_RE.fullmatch(trait_id):
                raise AvatarPackError(
                    f"trait {trait_index} in avatar layer {layer_id} has an invalid id"
                )
            if trait_id in seen_trait_ids:
                raise AvatarPackError(f"duplicate trait {layer_id}/{trait_id}")

            filename = raw_trait.get("file")
            expected_sha256 = raw_trait.get("sha256")
            if filename is None:
                if expected_sha256 is not None:
                    raise AvatarPackError(
                        f"empty trait {layer_id}/{trait_id} cannot have a sha256"
                    )
                trait = AvatarTrait(trait_id=trait_id, path=None, sha256=None)
            else:
                if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(
                    expected_sha256
                ):
                    raise AvatarPackError(
                        f"trait {layer_id}/{trait_id} has an invalid sha256"
                    )
                path = _asset_path(
                    root,
                    filename,
                    f"{layer_id}/{trait_id}",
                    {".png"},
                )
                if path in seen_files:
                    raise AvatarPackError(f"duplicate avatar layer file: {filename}")
                actual_sha256 = _sha256(path)
                if actual_sha256 != expected_sha256:
                    raise AvatarPackError(
                        f"trait {layer_id}/{trait_id} failed its sha256 integrity check"
                    )
                if _png_info(path) != (width, height):
                    raise AvatarPackError(
                        f"trait {layer_id}/{trait_id} does not match the "
                        f"{width}x{height} canvas"
                    )
                seen_files.add(path)
                trait = AvatarTrait(
                    trait_id=trait_id,
                    path=path,
                    sha256=actual_sha256,
                )

            seen_trait_ids.add(trait_id)
            traits.append(trait)

        seen_layer_ids.add(layer_id)
        layers.append(
            AvatarLayer(
                layer_id=layer_id,
                z_index=z_index,
                traits=tuple(traits),
            )
        )

    return AvatarPack(
        pack_id=manifest_id,
        root=root,
        layers=tuple(sorted(layers, key=lambda layer: layer.z_index)),
        width=width,
        height=height,
        version=2,
    )


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
    version = manifest.get("version", 1)
    if version == 2:
        return _load_layered_pack(root, manifest_id, manifest)
    if version != 1:
        raise AvatarPackError(f"unsupported avatar pack version: {version!r}")
    return _load_flat_pack(root, manifest_id, manifest)


def select_avatar(
    pack: AvatarPack,
    public_key: str,
    excluded_ids: set[str] | frozenset[str] = frozenset(),
) -> AvatarAsset:
    """Select from a legacy pack of complete avatars."""

    if pack.layered:
        raise AvatarPackError("select_avatar cannot select from a layered avatar pack")
    candidates = [asset for asset in pack.assets if asset.asset_id not in excluded_ids]
    if not candidates:
        candidates = list(pack.assets)
    if not candidates:
        raise AvatarPackError(f"avatar pack {pack.pack_id} contains no assets")
    seed = f"buzzr-avatar-v1:{pack.pack_id}:{public_key.lower()}:"
    return max(
        candidates,
        key=lambda asset: hashlib.sha256(
            (seed + asset.asset_id).encode("utf-8")
        ).digest(),
    )


def select_avatar_traits(
    pack: AvatarPack,
    public_key: str,
) -> tuple[tuple[AvatarLayer, AvatarTrait], ...]:
    """Independently and deterministically select one trait in every layer."""

    if not pack.layered:
        raise AvatarPackError(f"avatar pack {pack.pack_id} is not layered")
    selected: list[tuple[AvatarLayer, AvatarTrait]] = []
    for layer in pack.layers:
        seed = (
            f"buzzr-avatar-v2:{pack.pack_id}:{public_key.lower()}:{layer.layer_id}"
        ).encode("utf-8")
        index = int.from_bytes(hashlib.sha256(seed).digest(), "big") % len(layer.traits)
        selected.append((layer, layer.traits[index]))
    return tuple(selected)


def _decode_png(path: Path) -> tuple[int, int, bytearray]:
    try:
        encoded = path.read_bytes()
    except OSError as exc:
        raise AvatarPackError(f"cannot read PNG layer {path}: {exc}") from exc
    if encoded[:8] != PNG_SIGNATURE:
        raise AvatarPackError(f"avatar layer is not a valid PNG: {path}")

    offset = 8
    header: tuple[int, int, int, int, int, int, int] | None = None
    compressed = bytearray()
    found_end = False
    while offset + 12 <= len(encoded):
        length = struct.unpack(">I", encoded[offset : offset + 4])[0]
        chunk_end = offset + 12 + length
        if chunk_end > len(encoded):
            raise AvatarPackError(f"avatar layer has a truncated PNG chunk: {path}")
        chunk_type = encoded[offset + 4 : offset + 8]
        data = encoded[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", encoded[offset + 8 + length : chunk_end])[0]
        actual_crc = binascii.crc32(chunk_type + data) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise AvatarPackError(f"avatar layer has a corrupt PNG chunk: {path}")
        if chunk_type == b"IHDR":
            if length != 13:
                raise AvatarPackError(f"avatar layer has an invalid IHDR chunk: {path}")
            header = struct.unpack(">IIBBBBB", data)
        elif chunk_type == b"IDAT":
            compressed.extend(data)
        elif chunk_type == b"IEND":
            found_end = True
            break
        offset = chunk_end

    if header is None or not found_end or not compressed:
        raise AvatarPackError(f"avatar layer has an incomplete PNG stream: {path}")
    width, height, depth, color_type, compression, filtering, interlace = header
    if (
        depth != 8
        or color_type != 6
        or compression != 0
        or filtering != 0
        or interlace != 0
    ):
        raise AvatarPackError(
            f"avatar layer must be a non-interlaced 8-bit RGBA PNG: {path}"
        )

    try:
        filtered = zlib.decompress(bytes(compressed))
    except zlib.error as exc:
        raise AvatarPackError(f"avatar layer has invalid compressed pixels: {path}") from exc
    stride = width * 4
    expected_length = (stride + 1) * height
    if len(filtered) != expected_length:
        raise AvatarPackError(f"avatar layer has an invalid pixel payload: {path}")

    pixels = bytearray(stride * height)
    previous = bytearray(stride)
    source_offset = 0
    for row_number in range(height):
        filter_type = filtered[source_offset]
        source_offset += 1
        row = bytearray(filtered[source_offset : source_offset + stride])
        source_offset += stride
        if filter_type == 1:
            for index in range(stride):
                left = row[index - 4] if index >= 4 else 0
                row[index] = (row[index] + left) & 0xFF
        elif filter_type == 2:
            for index in range(stride):
                row[index] = (row[index] + previous[index]) & 0xFF
        elif filter_type == 3:
            for index in range(stride):
                left = row[index - 4] if index >= 4 else 0
                row[index] = (row[index] + ((left + previous[index]) >> 1)) & 0xFF
        elif filter_type == 4:
            for index in range(stride):
                left = row[index - 4] if index >= 4 else 0
                up = previous[index]
                upper_left = previous[index - 4] if index >= 4 else 0
                estimate = left + up - upper_left
                left_distance = abs(estimate - left)
                up_distance = abs(estimate - up)
                upper_left_distance = abs(estimate - upper_left)
                predictor = (
                    left
                    if left_distance <= up_distance and left_distance <= upper_left_distance
                    else up
                    if up_distance <= upper_left_distance
                    else upper_left
                )
                row[index] = (row[index] + predictor) & 0xFF
        elif filter_type != 0:
            raise AvatarPackError(
                f"avatar layer uses unknown PNG filter {filter_type}: {path}"
            )
        destination_offset = row_number * stride
        pixels[destination_offset : destination_offset + stride] = row
        previous = row
    return width, height, pixels


def _alpha_over(destination: bytearray, source: bytearray) -> None:
    for index in range(0, len(destination), 4):
        source_alpha = source[index + 3]
        if source_alpha == 0:
            continue
        destination_alpha = destination[index + 3]
        if source_alpha == 255 or destination_alpha == 0:
            destination[index : index + 4] = source[index : index + 4]
            continue
        inverse_alpha = 255 - source_alpha
        if destination_alpha == 255:
            for channel in range(3):
                destination[index + channel] = (
                    source[index + channel] * source_alpha
                    + destination[index + channel] * inverse_alpha
                    + 127
                ) // 255
            continue

        output_alpha_scaled = (
            source_alpha * 255 + destination_alpha * inverse_alpha
        )
        for channel in range(3):
            destination[index + channel] = (
                source[index + channel] * source_alpha * 255
                + destination[index + channel] * destination_alpha * inverse_alpha
                + output_alpha_scaled // 2
            ) // output_alpha_scaled
        destination[index + 3] = (output_alpha_scaled + 127) // 255


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    checksum = binascii.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", checksum)


def _encode_png(width: int, height: int, pixels: bytearray) -> bytes:
    stride = width * 4
    scanlines = bytearray((stride + 1) * height)
    for row_number in range(height):
        destination_offset = row_number * (stride + 1)
        source_offset = row_number * stride
        scanlines[destination_offset] = 0
        scanlines[destination_offset + 1 : destination_offset + 1 + stride] = pixels[
            source_offset : source_offset + stride
        ]
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return b"".join(
        (
            PNG_SIGNATURE,
            _png_chunk(b"IHDR", header),
            _png_chunk(b"IDAT", zlib.compress(bytes(scanlines), level=9)),
            _png_chunk(b"IEND", b""),
        )
    )


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f"{path.stem}-",
        suffix=path.suffix,
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def compose_avatar(
    pack: AvatarPack,
    public_key: str,
    output_directory: Path | None = None,
) -> AvatarAsset:
    """Compose a layered pack into one stable PNG derived from a public key."""

    selected = select_avatar_traits(pack, public_key)
    traits = tuple(
        (layer.layer_id, trait.trait_id) for layer, trait in selected
    )
    composition = json.dumps(
        {
            "compositor": COMPOSITOR_VERSION,
            "pack": pack.pack_id,
            "canvas": [pack.width, pack.height],
            "traits": [
                [layer.layer_id, trait.trait_id, trait.sha256]
                for layer, trait in selected
            ],
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    composition_id = hashlib.sha256(composition).hexdigest()[:20]
    asset_id = f"{pack.pack_id}-{composition_id}"
    path = (
        output_directory / f"{asset_id}.png"
        if output_directory is not None
        else pack.root / ".composed" / f"{asset_id}.png"
    )
    if output_directory is not None and path.is_file():
        try:
            if _png_info(path) == (pack.width, pack.height):
                return AvatarAsset(
                    asset_id=asset_id,
                    collection="composed",
                    path=path,
                    sha256=_sha256(path),
                    traits=traits,
                )
        except AvatarPackError:
            pass

    canvas = bytearray(pack.width * pack.height * 4)
    for _layer, trait in selected:
        if trait.path is None:
            continue
        width, height, pixels = _decode_png(trait.path)
        if (width, height) != (pack.width, pack.height):
            raise AvatarPackError(
                f"trait {trait.trait_id} changed dimensions after pack validation"
            )
        _alpha_over(canvas, pixels)
    encoded = _encode_png(pack.width, pack.height, canvas)
    digest = hashlib.sha256(encoded).hexdigest()
    if output_directory is not None:
        _atomic_write(path, encoded)
    return AvatarAsset(
        asset_id=asset_id,
        collection="composed",
        path=path,
        sha256=digest,
        traits=traits,
    )


def build_avatar(
    pack: AvatarPack,
    public_key: str,
    output_directory: Path | None = None,
    excluded_ids: set[str] | frozenset[str] = frozenset(),
) -> AvatarAsset:
    """Build a layered avatar or select a legacy complete avatar."""

    if pack.layered:
        return compose_avatar(pack, public_key, output_directory)
    return select_avatar(pack, public_key, excluded_ids)
