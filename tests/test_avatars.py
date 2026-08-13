from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from herdr_buzz.avatars import (
    AvatarPackError,
    compose_avatar,
    load_avatar_pack,
    select_avatar,
    select_avatar_traits,
)


class AvatarPackTests(unittest.TestCase):
    def test_bundled_recraft_pack_is_layered_and_selection_is_stable(self) -> None:
        pack = load_avatar_pack()
        self.assertEqual(pack.pack_id, "bees-v2")
        self.assertTrue(pack.layered)
        self.assertEqual((pack.width, pack.height), (512, 512))
        self.assertEqual(pack.combination_count, 12_348)
        self.assertEqual(
            [layer.layer_id for layer in pack.layers],
            ["background", "body", "neck", "eyewear", "headwear"],
        )

        selected = select_avatar_traits(pack, "a" * 64)
        self.assertEqual(selected, select_avatar_traits(pack, "a" * 64))
        self.assertEqual(
            [(layer.layer_id, trait.trait_id) for layer, trait in selected],
            [
                ("background", "confetti"),
                ("body", "coral"),
                ("neck", "flower-collar"),
                ("eyewear", "hearts"),
                ("headwear", "mushroom"),
            ],
        )

    def test_layered_avatar_is_composed_once_as_a_stable_rgba_png(self) -> None:
        pack = load_avatar_pack()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            first = compose_avatar(pack, "a" * 64, output)
            second = compose_avatar(pack, "a" * 64, output)

            self.assertEqual(first, second)
            self.assertTrue(first.path.is_file())
            self.assertEqual(first.path.suffix, ".png")
            self.assertEqual(first.path.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(len(first.traits), 5)

    def test_legacy_complete_image_pack_selection_remains_supported(self) -> None:
        pack = load_avatar_pack("bees-v1")
        self.assertFalse(pack.layered)
        self.assertEqual(len(pack.assets), 24)
        selected = select_avatar(pack, "a" * 64)
        self.assertEqual(selected, select_avatar(pack, "a" * 64))

        assigned: set[str] = set()
        for number in range(24):
            avatar = select_avatar(pack, f"{number:064x}", assigned)
            assigned.add(avatar.asset_id)
        self.assertEqual(len(assigned), 24)

    def test_custom_pack_checks_asset_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            asset = root / "bee.webp"
            asset.write_bytes(b"test-image")
            manifest = {
                "id": "custom-bees",
                "assets": [
                    {
                        "id": "bee-01",
                        "collection": "test",
                        "file": "bee.webp",
                        "sha256": hashlib.sha256(b"test-image").hexdigest(),
                    }
                ],
            }
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            pack = load_avatar_pack("ignored", root)
            self.assertEqual(pack.assets[0].path, asset)

            asset.write_bytes(b"tampered")
            with self.assertRaises(AvatarPackError):
                load_avatar_pack("ignored", root)

    def test_pack_files_cannot_escape_the_pack_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            container = Path(directory)
            root = container / "pack"
            root.mkdir()
            outside = container / "outside.webp"
            outside.write_bytes(b"image")
            try:
                manifest = {
                    "id": "unsafe",
                    "assets": [
                        {
                            "id": "escape",
                            "collection": "test",
                            "file": "../outside.webp",
                            "sha256": hashlib.sha256(b"image").hexdigest(),
                        }
                    ],
                }
                (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaises(AvatarPackError):
                    load_avatar_pack("ignored", root)
            finally:
                outside.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
