from __future__ import annotations

import math
import re
import socket
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import numpy as np
from PIL import Image, ImageChops, ImageFilter

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "buff.ly", "ow.ly", "rb.gy",
    "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at"
}

SUSPICIOUS_TLDS = {
    ".zip", ".top", ".xyz", ".click", ".country", ".gq", ".tk", ".work", ".cam"
}

KEYWORDS = {
    "login", "verify", "secure", "update", "account", "wallet", "invoice",
    "pay", "bank", "password", "mfa", "otp", "reset", "signin"
}

DANGEROUS_EXTENSIONS = {".exe", ".js", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs"}


@dataclass
class ScanResult:
    classification: str
    risk_score: float
    reasons: list[str]
    details: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "risk_score": round(self.risk_score, 4),
            "reasons": self.reasons,
            "details": self.details,
        }


def _clamp(v: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, v))


def scan_link(url: str) -> ScanResult:
    reasons: list[str] = []
    score = 0.05
    candidate = url.strip()

    if not candidate:
        return ScanResult("invalid", 1.0, ["No URL provided."], {})

    if not re.match(r"^https?://", candidate, flags=re.I):
        candidate = "https://" + candidate
        reasons.append("Protocol missing; normalized to HTTPS for analysis.")
        score += 0.03

    parsed = urlparse(candidate)
    host = (parsed.netloc or "").lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    if not host:
        return ScanResult("invalid", 1.0, ["Could not parse domain."], {"normalized_url": candidate})

    domain_len = len(host)
    hyphen_count = host.count("-")
    digit_count = sum(ch.isdigit() for ch in host)
    contains_at = "@" in candidate
    has_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))
    subdomain_depth = max(0, len(host.split(".")) - 2)
    suspicious_tld = any(host.endswith(tld) for tld in SUSPICIOUS_TLDS)
    keyword_hits = sorted({kw for kw in KEYWORDS if kw in (host + path + query)})
    shortener = host in SHORTENERS
    long_url = len(candidate) > 90
    punycode = "xn--" in host
    encoded_chars = sum(candidate.count(x) for x in ["%", "=", "&"])

    if shortener:
        score += 0.22
        reasons.append("Shortened URL detected.")
    if contains_at:
        score += 0.25
        reasons.append("'@' symbol in URL can obscure the real destination.")
    if has_ip:
        score += 0.25
        reasons.append("Raw IP address used instead of a normal domain.")
    if suspicious_tld:
        score += 0.14
        reasons.append("High-risk or commonly abused top-level domain.")
    if punycode:
        score += 0.16
        reasons.append("Punycode/homograph style domain detected.")
    if hyphen_count >= 2:
        score += 0.09
        reasons.append("Multiple hyphens in the domain can indicate impersonation.")
    if digit_count >= 4:
        score += 0.06
        reasons.append("Heavy use of digits in domain name.")
    if subdomain_depth >= 3:
        score += 0.08
        reasons.append("Deep subdomain structure can hide impersonation.")
    if domain_len > 28:
        score += 0.05
        reasons.append("Long domain name detected.")
    if long_url:
        score += 0.06
        reasons.append("Long URL with many components.")
    if encoded_chars >= 6:
        score += 0.05
        reasons.append("URL contains a high amount of encoded/query characters.")
    if keyword_hits:
        score += min(0.18, 0.04 * len(keyword_hits))
        reasons.append("Sensitive-action keywords detected in domain or path.")

    try:
        socket.gethostbyname(host)
        resolved = True
    except Exception:
        resolved = False
        score += 0.10
        reasons.append("Domain did not resolve during scan.")

    if parsed.scheme == "http":
        score += 0.05
        reasons.append("HTTP used instead of HTTPS.")

    risk_score = _clamp(score)
    if risk_score >= 0.72:
        classification = "dangerous"
    elif risk_score >= 0.45:
        classification = "suspicious"
    else:
        classification = "low-risk"

    details = {
        "normalized_url": candidate,
        "domain": host,
        "resolved": resolved,
        "signals": {
            "domain_length": domain_len,
            "hyphen_count": hyphen_count,
            "digit_count": digit_count,
            "subdomain_depth": subdomain_depth,
            "contains_at": contains_at,
            "uses_ip": has_ip,
            "shortener": shortener,
            "punycode": punycode,
            "suspicious_tld": suspicious_tld,
            "keyword_hits": keyword_hits,
        },
    }
    return ScanResult(classification, risk_score, reasons or ["No major risk signal detected."], details)


def image_features(image: Image.Image) -> dict[str, float]:
    gray = image.convert("L")
    arr = np.asarray(gray, dtype=np.uint8)
    hist, _ = np.histogram(arr.flatten(), bins=256, range=(0, 256))
    probs = hist / max(1, hist.sum())
    probs = probs[probs > 0]
    entropy = float(-np.sum(probs * np.log2(probs)))
    variance = float(np.var(arr))
    lsb = arr & 1
    lsb_mean = float(np.mean(lsb))
    lsb_var = float(np.var(lsb))

    shifted = np.roll(arr, 1, axis=1)
    correlation = float(np.mean((arr.astype(np.float32) - shifted.astype(np.float32)) ** 2))

    return {
        "entropy": entropy,
        "variance": variance,
        "lsb_mean": lsb_mean,
        "lsb_variance": lsb_var,
        "adjacent_diff": correlation,
    }


def build_heatmap(image: Image.Image, out_path: Path) -> None:
    base = image.convert("RGB")
    gray = image.convert("L")
    lsb_plane = gray.point(lambda p: (p & 1) * 255)
    lsb_edges = lsb_plane.filter(ImageFilter.GaussianBlur(radius=2))
    overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))
    heat = Image.merge("RGBA", (lsb_edges, ImageChops.invert(lsb_edges), Image.new("L", base.size, 32), lsb_edges.point(lambda p: min(180, p))))
    overlay = Image.alpha_composite(overlay, heat)
    combined = Image.alpha_composite(base.convert("RGBA"), overlay)
    combined.save(out_path)


def scan_image_file(file_bytes: bytes, filename: str, heatmap_dir: Path) -> ScanResult:
    reasons: list[str] = []
    score = 0.08
    image = Image.open(BytesIO(file_bytes))
    image.load()
    feats = image_features(image)

    entropy = feats["entropy"]
    variance = feats["variance"]
    lsb_mean = feats["lsb_mean"]
    lsb_var = feats["lsb_variance"]
    adj = feats["adjacent_diff"]

    if entropy > 7.35:
        score += 0.18
        reasons.append("High entropy can indicate embedded payload randomization.")
    if 0.46 <= lsb_mean <= 0.54:
        score += 0.20
        reasons.append("Least-significant-bit distribution is unusually balanced.")
    if lsb_var > 0.24:
        score += 0.10
        reasons.append("LSB variance is higher than expected for typical images.")
    if variance < 400 or variance > 6500:
        score += 0.05
        reasons.append("Image variance sits in an atypical range.")
    if adj > 1800:
        score += 0.08
        reasons.append("Neighbor pixel differences are elevated.")

    risk_score = _clamp(score)
    if risk_score >= 0.68:
        classification = "dangerous"
    elif risk_score >= 0.43:
        classification = "suspicious"
    else:
        classification = "low-risk"

    heatmap_name = Path(filename).stem + "_heatmap.png"
    heatmap_path = heatmap_dir / heatmap_name
    build_heatmap(image, heatmap_path)

    return ScanResult(
        classification,
        risk_score,
        reasons or ["No major hidden-data signal detected."],
        {
            "filename": filename,
            "heatmap": f"/heatmaps/{heatmap_name}",
            "image_metrics": {k: round(v, 4) for k, v in feats.items()},
            "dimensions": {"width": image.width, "height": image.height},
        },
    )


def scan_generic_file(filename: str, file_bytes: bytes) -> ScanResult:
    reasons: list[str] = []
    score = 0.06
    ext = Path(filename).suffix.lower()
    size_kb = len(file_bytes) / 1024.0

    if ext in DANGEROUS_EXTENSIONS:
        score += 0.55
        reasons.append("Known executable/script extension detected.")

    sample = file_bytes[:2048]
    text = sample.decode("utf-8", errors="ignore").lower()

    patterns = [
        ("powershell", 0.22, "PowerShell command patterns found."),
        ("cmd.exe", 0.20, "Command-shell execution pattern found."),
        ("http://", 0.12, "Embedded outbound HTTP URL found inside file content."),
        ("https://", 0.08, "Embedded outbound URL found inside file content."),
        ("base64", 0.10, "Base64 indicator found inside file content."),
        ("invoke-webrequest", 0.22, "Suspicious remote download command found."),
        ("curl ", 0.12, "Curl invocation found inside file content."),
        ("wget ", 0.12, "Wget invocation found inside file content."),
    ]
    for pat, add, msg in patterns:
        if pat in text:
            score += add
            reasons.append(msg)

    entropy = 0.0
    if file_bytes:
        counts = np.bincount(np.frombuffer(file_bytes, dtype=np.uint8), minlength=256)
        probs = counts / counts.sum()
        probs = probs[probs > 0]
        entropy = float(-np.sum(probs * np.log2(probs)))
        if entropy > 7.6 and ext not in {".png", ".jpg", ".jpeg", ".pdf"}:
            score += 0.12
            reasons.append("High binary entropy detected.")

    if size_kb > 5120:
        score += 0.05
        reasons.append("Large file size may warrant manual inspection.")

    risk_score = _clamp(score)
    if risk_score >= 0.70:
        classification = "dangerous"
    elif risk_score >= 0.45:
        classification = "suspicious"
    else:
        classification = "low-risk"

    return ScanResult(
        classification,
        risk_score,
        reasons or ["No major risk pattern detected in sampled content."],
        {
            "filename": filename,
            "extension": ext,
            "size_kb": round(size_kb, 2),
            "binary_entropy": round(entropy, 4),
        },
    )
