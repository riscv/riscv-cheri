#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
import json
import urllib.request
import re
from pathlib import Path
from typing import List, Dict, Tuple, Union

DIST_DIR: Path = Path("dist")


def semver_key(version_str: str) -> Tuple[Union[int, str], ...]:
    """Parses standard version strings (e.g. 0.9.8.2, 0.9.3-prerelease) for sorting."""
    parts: List[str] = version_str.split("-")
    num_parts: List[Union[int, str]] = []
    for x in parts[0].split("."):
        try:
            num_parts.append(int(x))
        except ValueError:
            num_parts.append(x)

    if len(parts) > 1:
        return tuple(num_parts) + (-1, parts[1])
    return tuple(num_parts) + (1,)


def spec_sort_key(f: str) -> Tuple[int, str]:
    """Shorthand sorting mapping to enforce standard logical order of specs."""
    lower_f: str = f.lower()
    order: int
    if "full" in lower_f:
        order = 2
    elif "unprivileged" in lower_f:
        order = 4
    elif "privileged" in lower_f:
        order = 3
    elif "cheri" in lower_f:
        order = 1
    else:
        order = 5
    return (order, f)


def get_repo_details() -> str:
    """Queries or extracts GITHUB_REPOSITORY dynamically, supporting local testing."""
    repo: Union[str, None] = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        try:
            res = subprocess.run(
                ["gh", "repo", "view", "--json", "owner,name", "--jq", '.owner.login + "/" + .name'],
                capture_output=True,
                text=True,
                check=True,
            )
            repo = res.stdout.strip()
        except Exception:
            repo = "riscv/riscv-cheri"
    return repo


def stage_snapshot_local(build_dir: Path) -> None:
    """Stages snapshot from local build files (main branch workflow runs)."""
    print("Staging snapshot from local build...")
    for spec in ["unprivileged", "privileged", "riscv-cheri", "riscv-cheri-debug", "riscv-cheri-full"]:
        (DIST_DIR / "snapshot" / spec).mkdir(parents=True, exist_ok=True)

    shutil.copy(build_dir / "riscv-unprivileged.html", DIST_DIR / "snapshot/unprivileged/index.html")
    shutil.copy(build_dir / "riscv-privileged.html", DIST_DIR / "snapshot/privileged/index.html")
    shutil.copy(build_dir / "riscv-cheri.html", DIST_DIR / "snapshot/riscv-cheri/index.html")
    shutil.copy(build_dir / "riscv-cheri-debug.html", DIST_DIR / "snapshot/riscv-cheri-debug/index.html")
    shutil.copy(build_dir / "riscv-cheri-full.html", DIST_DIR / "snapshot/riscv-cheri-full/index.html")

    # Root index.html remains the latest active spec snapshot
    shutil.copy(build_dir / "riscv-cheri.html", DIST_DIR / "index.html")


def stage_snapshot_download(repo: str) -> None:
    """Downloads live snapshots from the deployed site (release/pages workflow runs)."""
    print("No local build found. Downloading live snapshots from website...")
    pages_url: str = ""
    try:
        res = subprocess.run(["gh", "api", f"repos/{repo}/pages"], capture_output=True, text=True, check=True)
        pages_info: Dict[str, str] = json.loads(res.stdout)
        pages_url = pages_info.get("html_url", "")
    except Exception as e:
        print(f"Warning: Could not determine Pages URL ({e})")

    if pages_url:
        print(f"Pages URL is {pages_url}")
        for spec in ["unprivileged", "privileged", "riscv-cheri", "riscv-cheri-debug", "riscv-cheri-full"]:
            (DIST_DIR / "snapshot" / spec).mkdir(parents=True, exist_ok=True)

        def download_file(url_path: str, dest_path: str) -> None:
            url: str = f"{pages_url}{url_path}"
            try:
                with urllib.request.urlopen(url) as response, open(DIST_DIR / dest_path, "wb") as out_file:
                    out_file.write(response.read())
                print(f"Downloaded snapshot {url_path}")
            except Exception as ex:
                print(f"Warning: Could not download {url_path} ({ex}). Creating placeholder.")
                with open(DIST_DIR / dest_path, "w") as out_file:
                    out_file.write("Snapshot not available.")

        download_file("snapshot/unprivileged/index.html", "snapshot/unprivileged/index.html")
        download_file("snapshot/privileged/index.html", "snapshot/privileged/index.html")
        download_file("snapshot/riscv-cheri/index.html", "snapshot/riscv-cheri/index.html")
        download_file("snapshot/riscv-cheri-debug/index.html", "snapshot/riscv-cheri-debug/index.html")
        download_file("snapshot/riscv-cheri-full/index.html", "snapshot/riscv-cheri-full/index.html")

        # Root index.html remains the latest active spec snapshot
        download_file("snapshot/riscv-cheri/index.html", "index.html")
    else:
        print("Warning: Creating placeholder snapshots.")
        for spec in ["unprivileged", "privileged", "riscv-cheri", "riscv-cheri-debug", "riscv-cheri-full"]:
            (DIST_DIR / "snapshot" / spec).mkdir(parents=True, exist_ok=True)
            with open(DIST_DIR / "snapshot" / spec / "index.html", "w") as out_file:
                out_file.write("Snapshot not available.")
        with open(DIST_DIR / "index.html", "w") as out_file:
            out_file.write("Snapshot not available.")


def fetch_stable_releases() -> List[str]:
    """Queries stable release tags from GitHub API (excluding pre-releases)."""
    print("Fetching stable releases list from GitHub...")
    try:
        res = subprocess.run(
            [
                "gh",
                "release",
                "list",
                "--limit",
                "1000",
                "--exclude-pre-releases",
                "--json",
                "tagName",
                "--jq",
                ".[].tagName",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return [line.strip() for line in res.stdout.strip().split("\n") if line.strip()]
    except Exception as e:
        print(f"Warning: Could not fetch releases list ({e})")
        return []


def query_release_assets(tag: str) -> List[str]:
    """Queries the attached assets list for a specific release."""
    print(f"Querying assets list for stable release {tag}...")
    try:
        res = subprocess.run(
            ["gh", "release", "view", tag, "--json", "assets", "--jq", ".assets[].name"],
            capture_output=True,
            text=True,
            check=True,
        )
        return [line.strip() for line in res.stdout.strip().split("\n") if line.strip()]
    except Exception as e:
        print(f"Warning: Could not fetch assets for {tag} ({e})")
        return []


def download_release_html(tag: str, version: str, html_assets: List[str]) -> None:
    """Downloads release HTML files and copies primary spec to index.html."""
    print(f"Downloading HTML assets for release {tag}...")
    target_dir: Path = DIST_DIR / version
    target_dir.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            ["gh", "release", "download", tag, "--pattern", "*.html", "--dir", str(target_dir)],
            check=True,
            capture_output=True,
        )

        # Ensure index.html exists in the versioned folder
        if (target_dir / "riscv-cheri.html").exists():
            shutil.copy(target_dir / "riscv-cheri.html", target_dir / "index.html")
        else:
            main_spec: Union[str, None] = None
            for p in target_dir.iterdir():
                if (
                    p.is_file()
                    and p.name.startswith("riscv-cheri-")
                    and p.name.endswith(".html")
                    and "-full" not in p.name
                ):
                    main_spec = p.name
                    break
            if main_spec:
                shutil.copy(target_dir / main_spec, target_dir / "index.html")
            else:
                if len(html_assets) == 1:
                    shutil.copy(target_dir / html_assets[0], target_dir / "index.html")
    except Exception as e:
        print(f"Warning: Failed to download HTML assets for {version} ({e})")


def generate_snapshot_block() -> str:
    """Dynamically generates the Snapshot HTML spec links block."""
    snapshot_links: List[str] = []
    snapshot_path: Path = DIST_DIR / "snapshot"
    if snapshot_path.exists():
        for d in sorted(snapshot_path.iterdir()):
            if d.is_dir() and (d / "index.html").exists():
                lower_d: str = d.name.lower()
                label: str
                if "full" in lower_d:
                    label = "CHERI Specification (including unstable sections)"
                elif "unprivileged" in lower_d:
                    label = "Unprivileged"
                elif "privileged" in lower_d:
                    label = "Privileged"
                elif "debug" in lower_d:
                    label = "CHERI Debug Specification"
                elif "cheri" in lower_d:
                    label = "CHERI Specification"
                else:
                    label = d.name.replace("-", " ").replace("_", " ").title()
                snapshot_links.append(
                    f'        <li><strong>{label}</strong> (<a href="snapshot/{d.name}/index.html">HTML</a>)</li>'
                )

    snapshot_links_html: str = "\n".join(snapshot_links)
    return f"""    <ul>
        <li><strong>All Specs Overview</strong> (<a href="index.html">HTML Snapshot</a>)</li>
{snapshot_links_html}
    </ul>"""


def generate_releases_block(versions: List[str], version_assets: Dict[str, List[str]], repo_url: str) -> str:
    """Dynamically generates the Releases HTML headers and spec links blocks."""
    releases_block: str = ""
    if not versions:
        releases_block = """    <ul>
        <li>
            <span style="color: #666;">No official releases deployed yet.</span>
        </li>
    </ul>"""
    else:
        re_ver_suffix: re.Pattern = re.compile(r"-v?\d+(?:\.\d+)*(?:-[a-zA-Z]+)?$")

        for v in versions:
            tag: str = f"v{v}"
            release_page_url: str = f"{repo_url}/releases/tag/{tag}"
            links: List[str] = []

            assets: List[str] = version_assets.get(v, [])
            html_files: List[str] = [a for a in assets if a.endswith(".html")]
            pdf_files: List[str] = [a for a in assets if a.endswith(".pdf")]

            specs: List[str] = []
            for a in html_files + pdf_files:
                if a == "index.html":
                    continue
                base_with_ver: str = os.path.splitext(a)[0]
                clean_base: str = re_ver_suffix.sub("", base_with_ver)
                specs.append(clean_base)

            specs = list(set(specs))
            specs.sort(key=lambda s: spec_sort_key(s + ".html"))

            main_spec_links: Union[str, None] = None
            for spec in specs:
                html_file: Union[str, None] = None
                for h in html_files:
                    if os.path.splitext(h)[0].startswith(spec):
                        html_file = h
                        break

                pdf_file: Union[str, None] = None
                for p in pdf_files:
                    if os.path.splitext(p)[0].startswith(spec):
                        pdf_file = p
                        break

                if not html_file and not pdf_file:
                    continue

                lower_spec: str = spec.lower()
                label: str
                if lower_spec == "riscv-cheri":
                    # This is the primary standalone CHERI spec. Promote to top level
                    spec_links: List[str] = []
                    if html_file:
                        spec_links.append(f'<a href="{v}/{html_file}">HTML</a>')
                    if pdf_file:
                        spec_links.append(f'<a href="{repo_url}/releases/download/{tag}/{pdf_file}">PDF</a>')
                    main_spec_links = " | ".join(spec_links)
                else:
                    # These are auxiliary specs. List them as bullet points below
                    if "full" in lower_spec:
                        label = "CHERI Specification (including unstable sections)"
                    elif "unprivileged" in lower_spec:
                        label = "Unprivileged"
                    elif "privileged" in lower_spec:
                        label = "Privileged"
                    elif "debug" in lower_spec:
                        label = "CHERI Debug Specification"
                    else:
                        label = spec.replace("-", " ").replace("_", " ").title()

                    spec_links = []
                    if html_file:
                        spec_links.append(f'<a href="{v}/{html_file}">HTML</a>')
                    if pdf_file:
                        spec_links.append(f'<a href="{repo_url}/releases/download/{tag}/{pdf_file}">PDF</a>')

                    spec_links_html: str = " | ".join(spec_links)
                    links.append(f"        <li><strong>{label}</strong> ({spec_links_html})</li>")

            header_html: str
            if main_spec_links:
                header_html = f'<h3><a href="{release_page_url}">v{v}</a>: CHERI Specification ({main_spec_links})</h3>'
            else:
                header_html = f'<h3><a href="{release_page_url}">v{v}</a></h3>'

            releases_block += header_html + "\n"
            if links:
                links_html: str = "\n".join(links)
                releases_block += f"""    <ul>
{links_html}
    </ul>\n"""

    return releases_block


def generate_overview(skip_download: bool = False) -> None:
    output_path: Path = DIST_DIR / "versions.html"
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    repo: str = get_repo_details()
    repo_url: str = f"https://github.com/{repo}"
    releases_url: str = f"{repo_url}/releases"

    # Stage Snapshot
    build_dir: Path = Path("build")
    if build_dir.is_dir() and (build_dir / "riscv-cheri.html").is_file():
        stage_snapshot_local(build_dir)
    else:
        stage_snapshot_download(repo)

    # Process Official Releases
    releases: List[str] = fetch_stable_releases()
    versions: List[str] = []
    version_assets: Dict[str, List[str]] = {}

    for tag in releases:
        if not re.match(r"^v[0-9]", tag):
            print(f"Skipping non-real release: {tag}")
            continue

        version: str = tag[1:] if tag.startswith("v") else tag
        assets: List[str] = query_release_assets(tag)

        html_assets: List[str] = [a for a in assets if a.endswith(".html")]
        pdf_assets: List[str] = [a for a in assets if a.endswith(".pdf")]

        # Skip if release has neither spec format
        if not html_assets and not pdf_assets:
            print(f"Skipping release {version} (no HTML or PDF assets found)")
            continue

        versions.append(version)
        version_assets[version] = assets

        # Download HTML files if they exist and skip_download is not active
        if html_assets:
            if not skip_download:
                download_release_html(tag, version, html_assets)
            else:
                print(f"Skipping download for release {tag} (--skip-download active)")

    # Sort versions semver-wise
    try:
        versions = list(set(versions))  # De-duplicate
        versions.sort(key=semver_key, reverse=True)
    except Exception as e:
        print(f"Warning: Error sorting versions semver-wise ({e}), falling back to basic sort.")
        versions.sort(reverse=True)

    # Assemble HTML version overview
    content: str = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RISC-V CHERI Specification Documentation</title>
</head>
<body>
    <h1>RISC-V CHERI Specification Documentation</h1>

    <p><a href="{releases_url}">View all official releases on GitHub</a></p>
    <hr>

    <h2>Latest Work-in-Progress (Snapshot)</h2>
{generate_snapshot_block()}
    <hr>

    <h2>Official Releases</h2>
{generate_releases_block(versions, version_assets, repo_url)}</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Successfully generated versions overview page at {output_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate GitHub Pages versions overview for RISC-V CHERI specs.")
    parser.add_argument(
        "--skip-download", action="store_true", help="Skip downloading HTML assets from GitHub Releases."
    )
    args = parser.parse_args()
    generate_overview(skip_download=args.skip_download)
