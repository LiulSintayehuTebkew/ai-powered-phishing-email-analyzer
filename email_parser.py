import email
import hashlib
import re
from email import policy

from bs4 import BeautifulSoup

URL_RE = re.compile(r"https?://[^\s<>\"'`]+", re.I)
RISKY_EXT = {"exe", "scr", "bat", "cmd", "com", "pif", "vbs", "js", "jse", "wsf", "hta", "ps1", "msi", "jar", "lnk", "dll", "iso", "img"}
DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt"}


def _clean_url(u):
    return u.rstrip(".,;:!?)>]}'\"")


def _host(u):
    m = re.match(r"(?i)^(?:https?://)?([^/:?#]+)", u.strip())
    return m.group(1).lower() if m else ""


def _root(host):
    return ".".join(host.split(".")[-2:])


def _read_bytes(source):
    """Accept raw bytes or a Streamlit UploadedFile (use getvalue so reruns never see an empty file)."""
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    if hasattr(source, "getvalue"):
        return source.getvalue()
    return source.read()


def _check_attachment(name, data):
    parts = name.lower().split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    flags = []
    if len(parts) >= 3 and parts[-1] in RISKY_EXT and parts[-2] in DECOY_EXT:
        flags.append(f"double extension (.{parts[-2]}.{parts[-1]})")
    elif ext in RISKY_EXT:
        flags.append(f"executable/script type (.{ext})")
    if ext in {"zip", "rar", "7z"}:
        flags.append("archive (may hide a payload)")
    if data[:2] == b"MZ" and ext not in RISKY_EXT:
        flags.append("file content is a Windows executable")
    return flags


def parse_eml(source):
    msg = email.message_from_bytes(_read_bytes(source), policy=policy.default)
    text_parts, html_parts, attachments = [], [], []

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        if fname or part.get_content_disposition() == "attachment":
            data = part.get_payload(decode=True) or b""
            attachments.append({"filename": fname or "unnamed", "size": len(data),
                                "sha256": hashlib.sha256(data).hexdigest(), "flags": _check_attachment(fname or "", data)})
        elif ctype in ("text/plain", "text/html"):
            try:
                content = part.get_content()
            except Exception:
                content = (part.get_payload(decode=True) or b"").decode(errors="ignore")
            (text_parts if ctype == "text/plain" else html_parts).append(content)

    urls, mismatches, html_text = [], [], ""
    for h in html_parts:
        soup = BeautifulSoup(h, "html.parser")
        for t in soup(["script", "style"]):
            t.decompose()
        for a in soup.find_all("a", href=True):
            href, shown = a["href"].strip(), a.get_text(" ", strip=True)
            if href.lower().startswith(("http://", "https://")):
                urls.append(_clean_url(href))
                if re.match(r"(?i)^(https?://)?[\w.-]+\.[a-z]{2,}(/\S*)?$", shown) and _root(_host(shown)) != _root(_host(href)):
                    mismatches.append(f"Link text shows '{shown[:60]}' but points to {_host(href)}")
        html_text += soup.get_text("\n", strip=True) + "\n"

    body = "\n".join(text_parts).strip() or html_text.strip()
    for u in URL_RE.findall("\n".join(text_parts)):
        urls.append(_clean_url(u))
    urls = list(dict.fromkeys(urls))

    return {
        "subject": str(msg.get("Subject", "")),
        "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "auth": str(msg.get("Authentication-Results", "")),
        "body": body,
        "urls": urls,
        "attachments": attachments,
        "link_mismatches": mismatches,
    }
