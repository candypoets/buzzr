from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from herdr_buzz.avatars import AvatarPackError, load_avatar_pack, select_avatar


class AvatarPackTests(unittest.TestCase):
    def test_bundled_recraft_pack_is_complete_and_selection_is_stable(self) -> None:
        pack = load_avatar_pack()
        self.assertEqual(pack.pack_id, "bees-v1")
        self.assertEqual(len(pack.assets), 24)
        selected = select_avatar(pack, "a" * 64)
        self.assertEqual(selected, select_avatar(pack, "a" * 64))
        self.assertIn(selected.collection, {"sunforge", "moonwire", "mossbyte", "rosycore"})
        self.assertEqual(selected.path.suffix, ".webp")

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
