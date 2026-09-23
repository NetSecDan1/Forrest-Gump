"""Manifest signature verification (authenticity), mirroring collector Protect-ADHealthManifest."""

import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from adhealth_agent.config import IntegrityConfig
from adhealth_agent.ingest import BundleError, open_bundle
from conftest import make_bundle

MAX = 50 * 1024 * 1024


def _cert(key, days_valid=(-1, 30)):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "adhealth-test-signing")])
    now = datetime.now(timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now + timedelta(days=days_valid[0]))
            .not_valid_after(now + timedelta(days=days_valid[1])).sign(key, hashes.SHA256()))


def sign_bundle(bundle: Path, key, cert) -> str:
    """Same format the collector writes."""
    data = (bundle / "manifest.json").read_bytes()
    if isinstance(key, rsa.RSAPrivateKey):
        sig, alg = key.sign(data, padding.PKCS1v15(), hashes.SHA256()), "RSA-PKCS1v15-SHA256"
    else:
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
        n = (key.curve.key_size + 7) // 8
        sig, alg = r.to_bytes(n, "big") + s.to_bytes(n, "big"), "ECDSA-P1363-SHA256"
    der = cert.public_bytes(serialization.Encoding.DER)
    thumb = hashlib.sha1(der).hexdigest().upper()
    (bundle / "manifest.sig.json").write_text(json.dumps({
        "algorithm": alg, "signature": base64.b64encode(sig).decode(), "certificate": base64.b64encode(der).decode(),
        "thumbprint": thumb, "subject": "CN=adhealth-test-signing", "signedUtc": "2026-09-01T02:00:00Z"}), encoding="utf-8")
    return thumb


@pytest.fixture
def rsa_signed(tmp_path):
    b = make_bundle(tmp_path, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return b, sign_bundle(b, key, _cert(key))


def test_pinned_rsa_signature_is_trusted(rsa_signed):
    b, thumb = rsa_signed
    res = open_bundle(b, MAX, IntegrityConfig(require_signature=True, trusted_signer_thumbprints=[thumb.lower()]))
    assert res.signer == {"thumbprint": thumb, "subject": "CN=adhealth-test-signing", "trusted": True}


def test_thumbprint_pinning_accepts_windows_formatting(rsa_signed):
    b, thumb = rsa_signed
    spaced = " ".join(thumb[i:i + 2] for i in range(0, 40, 2))  # as copied from certlm.msc
    assert open_bundle(b, MAX, IntegrityConfig(True, [spaced])).signer["trusted"]


def test_ecdsa_p1363_signature_verifies(tmp_path):
    b = make_bundle(tmp_path, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    key = ec.generate_private_key(ec.SECP256R1())
    thumb = sign_bundle(b, key, _cert(key))
    assert open_bundle(b, MAX, IntegrityConfig(True, [thumb])).signer["trusted"]


def test_untrusted_signer_rejected(rsa_signed):
    b, _ = rsa_signed
    with pytest.raises(BundleError, match="untrusted certificate"):
        open_bundle(b, MAX, IntegrityConfig(True, ["00" * 20]))


def test_forgery_by_share_writer_rejected(rsa_signed):
    """Attacker edits report.json and re-hashes the manifest: hashes pass, signature must fail."""
    b, thumb = rsa_signed
    r = json.loads((b / "report.json").read_text(encoding="utf-8"))
    r["findings"] = []  # hide everything
    (b / "report.json").write_text(json.dumps(r), encoding="utf-8")
    from conftest import rehash
    rehash(b)
    with pytest.raises(BundleError, match="signature is INVALID"):
        open_bundle(b, MAX, IntegrityConfig(True, [thumb]))


def test_unsigned_bundle_rejected_when_required(tmp_path):
    b = make_bundle(tmp_path, "2026-09-01T02:00:00Z")
    with pytest.raises(BundleError, match="not signed"):
        open_bundle(b, MAX, IntegrityConfig(True, ["AB" * 20]))
    assert open_bundle(b, MAX, IntegrityConfig()).signer is None  # not required -> accepted, signer None


def test_certificate_must_be_valid_at_collection_time(tmp_path):
    b = make_bundle(tmp_path, "2020-01-01T00:00:00Z")  # collected long before the cert existed
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    thumb = sign_bundle(b, key, _cert(key))
    with pytest.raises(BundleError, match="not valid at collection time"):
        open_bundle(b, MAX, IntegrityConfig(True, [thumb]))


def test_require_without_pins_is_a_config_error():
    with pytest.raises(ValueError, match="trusted_signer_thumbprints is empty"):
        IntegrityConfig(require_signature=True).validate()


@pytest.mark.skipif(not os.environ.get("ADHEALTH_SMOKE_RESULT"), reason="set by CI after the PowerShell smoke test")
def test_powershell_signed_bundle_verifies_in_python():
    """Cross-implementation check: collector (PowerShell/.NET) signs, agent (Python/cryptography) verifies."""
    res = json.loads(Path(os.environ["ADHEALTH_SMOKE_RESULT"]).read_text(encoding="utf-8-sig"))
    b = open_bundle(Path(res["bundle"]), MAX, IntegrityConfig(True, [res["thumbprint"]]))
    assert b.signer["trusted"]
