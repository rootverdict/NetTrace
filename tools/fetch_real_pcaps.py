from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import urllib.request
import zipfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = PROJECT_ROOT / "samples" / "real" / "manifest.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(path: Path, sample: dict[str, object]) -> None:
    expected_size = int(sample["size_bytes"])
    expected_hash = str(sample["sha256"])
    if path.stat().st_size != expected_size:
        raise ValueError(f"Size mismatch for {path.name}")
    actual_hash = sha256(path)
    if actual_hash != expected_hash:
        raise ValueError(f"SHA-256 mismatch for {path.name}: {actual_hash}")


def download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "NetTrace-PCAP-Fetcher/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as output:
        shutil.copyfileobj(response, output)
    partial.replace(destination)


def extract(archive: Path, destination: Path, password: str) -> None:
    with zipfile.ZipFile(archive) as bundle:
        member = next((name for name in bundle.namelist() if Path(name).name == destination.name), None)
        if member is None:
            raise ValueError(f"{destination.name} was not found in {archive.name}")
        with bundle.open(member, pwd=password.encode("utf-8")) as source, destination.open("wb") as output:
            shutil.copyfileobj(source, output)


def main() -> None:
    parser = argparse.ArgumentParser(description="Download and verify the real PCAP validation corpus")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--sample", action="append", help="Filename to fetch; repeat for multiple samples")
    parser.add_argument("--verify-only", action="store_true", help="Verify local files without network access")
    parser.add_argument("--accept-risk", action="store_true", help="Acknowledge that captures contain malware traffic")
    parser.add_argument("--password", default=os.getenv("NETTRACE_PCAP_PASSWORD", ""))
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    requested = set(args.sample or [])
    samples = [sample for sample in manifest["samples"] if not requested or sample["filename"] in requested]
    if requested - {sample["filename"] for sample in samples}:
        parser.error("one or more --sample values are not present in the manifest")
    if not args.verify_only and not args.accept_risk:
        parser.error("downloading requires --accept-risk; read the manifest warning first")

    output_dir = args.manifest.parent
    download_dir = output_dir / "_downloads"
    for sample in samples:
        destination = output_dir / sample["filename"]
        if destination.is_file():
            verify(destination, sample)
            print(f"Verified {destination.name}")
            continue
        if args.verify_only:
            raise FileNotFoundError(destination)
        if not args.password:
            parser.error("set NETTRACE_PCAP_PASSWORD or pass --password to extract protected archives")
        archive = download_dir / (sample["filename"] + ".zip")
        if not archive.is_file():
            print(f"Downloading {sample['name']} ...")
            download(str(sample["archive_url"]), archive)
        extract(archive, destination, args.password)
        verify(destination, sample)
        print(f"Downloaded and verified {destination.name}")


if __name__ == "__main__":
    main()
