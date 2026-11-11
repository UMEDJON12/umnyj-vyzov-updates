#!/usr/bin/env python3
"""Проверить опубликованный релиз GitHub и записать updates/stable.json.

Запускается GitHub Actions на событии release:published. Ничего не публикует
сам: релиз должен быть уже опубликован пользователем. Перед записью:

  * релиз — не черновик и не предварительный (проверяется дважды: по событию
    и повторным запросом к GitHub API);
  * APK скачивается с asset'а релиза, сверяются размер и SHA-256;
  * `aapt dump badging` — пакет, versionCode, versionName;
  * `apksigner verify` — ровно один сертификат, его отпечаток равен
    закреплённому в скрипте (оригинальная подпись «Умного Вызов»);
  * versionCode строго больше уже опубликованного stable.json (защита от
    отката); повторный запуск для той же версии — идемпотентен.

Используется только стандартная библиотека Python и внешние aapt/apksigner.
Никаких токенов: анонимный HTTPS к GitHub.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

EXPECTED_PACKAGE = "com.smartcall.ru"
EXPECTED_CERT_SHA256 = "baedb1a77af5b2a9a0f34de72e7f88526e0e82c508eb07fee8b04ce2cf023c01"
MAX_APK_BYTES = 200 * 1024 * 1024
SCHEMA_VERSION = 1
VARIANT = "standard"
UA = "SmartCall-StablePublisher/1.0"


class Rejected(Exception):
    pass


def http_get(url, limit=None, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept": "application/vnd.github+json",
                                               **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as resp:
        if limit is not None and int(resp.headers.get("Content-Length") or 0) > limit:
            raise Rejected("ответ больше лимита")
        data = resp.read(limit + 1 if limit else None)
        if limit is not None and len(data) > limit:
            raise Rejected("тело ответа больше лимита")
        return data


def release_from_api(owner, repo, tag):
    url = f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"
    return json.loads(http_get(url, limit=512 * 1024))


def pick_apk(release, asset_name=None):
    assets = release.get("assets") or []
    apks = [a for a in assets if (a.get("name") or "").lower().endswith(".apk")]
    if asset_name:
        apks = [a for a in apks if a.get("name") == asset_name]
    if len(apks) != 1:
        raise Rejected(f"нужен ровно один APK-ассет, найдено {len(apks)}")
    return apks[0]


def download(url, dest, expected_size):
    if expected_size > MAX_APK_BYTES:
        raise Rejected("APK больше допустимого лимита")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    total = 0
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as out:
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_APK_BYTES:
                raise Rejected("APK больше допустимого лимита во время скачивания")
            out.write(chunk)
    if total != expected_size:
        raise Rejected(f"размер скачанного файла {total} != заявленному {expected_size}")
    return total


def run_tool(args):
    proc = subprocess.run(args, capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        raise Rejected(f"инструмент не прошёл: {' '.join(args[:2])}: {proc.stderr.strip()[:300]}")
    return proc.stdout


def apk_identity(apk, aapt, apksigner):
    badging = run_tool([aapt, "dump", "badging", apk])
    pkg = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)'", badging, re.M)
    if not pkg:
        raise Rejected("aapt не смог прочитать пакет")
    name = re.search(r"versionName='([^']+)'", badging)
    signing = run_tool([apksigner, "verify", "--verbose", "--print-certs",
                        "--min-sdk-version", "24", apk])
    certs = re.findall(r"^Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]{64})$",
                       signing, re.M)
    if len(certs) != 1:
        raise Rejected(f"ожидался один сертификат подписи, найдено {len(certs)}")
    if certs[0].lower() != EXPECTED_CERT_SHA256:
        raise Rejected("отпечаток подписи не совпадает с оригинальным ключом")
    return {
        "packageName": pkg.group(1),
        "versionCode": int(pkg.group(2)),
        "versionName": name.group(1) if name else "",
        "certSha256": certs[0].lower(),
    }


def load_previous(stable_path):
    if not stable_path.is_file():
        return 0, None
    try:
        data = json.loads(stable_path.read_text(encoding="utf-8"))
        return int(data.get("versionCode", 0)), data
    except (ValueError, TypeError):
        raise Rejected("существующий stable.json повреждён — откат невозможен, исправьте вручную")


def build_stable(identity, asset, apk_url, sha256, size, notes, tag, published_at):
    return {
        "schemaVersion": SCHEMA_VERSION,
        "packageName": identity["packageName"],
        "variant": VARIANT,
        "testOnly": False,
        "versionCode": identity["versionCode"],
        "versionName": identity["versionName"],
        "minSdk": 24,
        "signingCertificateSha256": identity["certSha256"],
        "sizeBytes": size,
        "sha256": sha256,
        "apkFileName": asset["name"],
        "apkUrl": apk_url,
        "releaseNotes": notes,
        "ready": True,
        "tagName": tag,
        "publishedAt": published_at,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--event", required=True, help="путь к GitHub event JSON")
    p.add_argument("--owner", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--output", required=True, help="каталог репозитория")
    p.add_argument("--aapt", default="aapt")
    p.add_argument("--apksigner", default="apksigner")
    p.add_argument("--asset-name", default=None)
    p.add_argument("--package", default=EXPECTED_PACKAGE)
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()

    event = json.loads(Path(a.event).read_text(encoding="utf-8"))
    release = event.get("release") or {}
    if release.get("draft") or release.get("prerelease"):
        raise Rejected("релиз — черновик или предварительный")
    tag = release.get("tag_name")
    if not tag:
        raise Rejected("в событии нет tag_name")

    # Повторная проверка состояния релиза непосредственно перед записью.
    fresh = release_from_api(a.owner, a.repo, tag)
    if fresh.get("draft") or fresh.get("prerelease"):
        raise Rejected("релиз стал черновиком/предварительным после события")
    if fresh.get("tag_name") != tag:
        raise Rejected("тег релиза изменился")

    asset = pick_apk(fresh, a.asset_name)
    out_dir = Path(a.output)
    stable_path = out_dir / "updates" / "stable.json"
    prev_version, _ = load_previous(stable_path)

    with tempfile.TemporaryDirectory(prefix="stable-pub-") as td:
        apk = str(Path(td) / (asset["name"] or "release.apk"))
        download(asset["browser_download_url"], apk, int(asset["size"]))
        sha256 = hashlib.sha256(Path(apk).read_bytes()).hexdigest()
        identity = apk_identity(apk, a.aapt, a.apksigner)

    if identity["packageName"] != a.package:
        raise Rejected(f"пакет {identity['packageName']} != {a.package}")
    if identity["versionCode"] <= prev_version:
        if identity["versionCode"] == prev_version:
            print(f"versionCode {identity['versionCode']} уже опубликован — без изменений")
            return 0
        raise Rejected(f"откат запрещён: {identity['versionCode']} <= {prev_version}")

    notes = (fresh.get("body") or "").strip()
    if len(notes) > 4000:
        notes = notes[:4000] + "…"
    stable = build_stable(identity, asset, asset["browser_download_url"], sha256,
                          int(asset["size"]), notes, tag, fresh.get("published_at") or "")

    if a.dry_run:
        print(json.dumps(stable, ensure_ascii=False, indent=2))
        return 0

    stable_path.parent.mkdir(parents=True, exist_ok=True)
    stable_path.write_text(json.dumps(stable, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(f"stable.json обновлён: {identity['packageName']} "
          f"{identity['versionName']} (code {identity['versionCode']}), sha256={sha256}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Rejected as exc:
        print(f"ОТКАЗ: {exc}", file=sys.stderr)
        sys.exit(1)
