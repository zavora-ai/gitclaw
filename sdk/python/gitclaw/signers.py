"""
Cryptographic signers for GitClaw SDK.

Supports Ed25519 and ECDSA P-256 signing algorithms.
"""

from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


class Signer(ABC):
    """Abstract base class for cryptographic signers."""

    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        """Sign a message and return the signature bytes."""
        pass

    @abstractmethod
    def public_key(self) -> str:
        """Return the public key in base64 format with type prefix."""
        pass

    @classmethod
    @abstractmethod
    def from_pem_file(cls, path: str | Path) -> "Signer":
        """Load a signer from a PEM file."""
        pass

    @classmethod
    @abstractmethod
    def from_pem(cls, pem_string: str) -> "Signer":
        """Load a signer from a PEM string."""
        pass

    @classmethod
    @abstractmethod
    def generate(cls) -> tuple["Signer", str]:
        """Generate a new keypair, returning (signer, public_key)."""
        pass


class Ed25519Signer(Signer):
    """Ed25519 digital signature implementation."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey) -> None:
        """
        Initialize with an Ed25519 private key.

        Args:
            private_key: Ed25519 private key from cryptography library
        """
        self._private_key = private_key
        self._public_key = private_key.public_key()

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message using Ed25519.

        Args:
            message: The message bytes to sign

        Returns:
            64-byte Ed25519 signature
        """
        return self._private_key.sign(message)

    def public_key(self) -> str:
        """
        Return the public key as base64 with ed25519: prefix.

        Returns:
            String in format "ed25519:<base64_public_key>"
        """
        import base64

        public_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return f"ed25519:{base64.b64encode(public_bytes).decode()}"

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte public key."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_key_pem(self) -> str:
        """Return the public key in PEM format."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def private_key_pem(self) -> str:
        """Return the private key in PEM format (for storage)."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    @classmethod
    def from_pem_file(cls, path: str | Path) -> "Ed25519Signer":
        """
        Load an Ed25519 signer from a PEM file.

        Args:
            path: Path to PEM file containing Ed25519 private key

        Returns:
            Ed25519Signer instance
        """
        path = Path(path)
        pem_data = path.read_bytes()
        private_key = serialization.load_pem_private_key(pem_data, password=None)

        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TypeError(f"Expected Ed25519 private key, got {type(private_key).__name__}")

        return cls(private_key)

    @classmethod
    def from_pem(cls, pem_string: str) -> "Ed25519Signer":
        """
        Load an Ed25519 signer from a PEM string.

        Args:
            pem_string: PEM-encoded Ed25519 private key

        Returns:
            Ed25519Signer instance
        """
        private_key = serialization.load_pem_private_key(
            pem_string.encode(), password=None
        )

        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TypeError(f"Expected Ed25519 private key, got {type(private_key).__name__}")

        return cls(private_key)

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> "Ed25519Signer":
        """
        Load an Ed25519 signer from raw 32-byte private key.

        Args:
            key_bytes: 32-byte Ed25519 private key seed

        Returns:
            Ed25519Signer instance
        """
        if len(key_bytes) != 32:
            raise ValueError(f"Ed25519 private key must be 32 bytes, got {len(key_bytes)}")

        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
        return cls(private_key)

    @classmethod
    def generate(cls) -> tuple["Ed25519Signer", str]:
        """
        Generate a new Ed25519 keypair.

        Returns:
            Tuple of (signer, public_key_string)
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        signer = cls(private_key)
        return signer, signer.public_key()

    def verify(self, signature: bytes, message: bytes) -> bool:
        """
        Verify a signature (for testing purposes).

        Args:
            signature: The signature to verify
            message: The original message

        Returns:
            True if valid, raises exception otherwise
        """
        try:
            self._public_key.verify(signature, message)
            return True
        except Exception:
            return False



class EcdsaSigner(Signer):
    """ECDSA P-256 digital signature implementation."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        """
        Initialize with an ECDSA P-256 private key.

        Args:
            private_key: ECDSA P-256 private key from cryptography library
        """
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise TypeError(
                f"Expected P-256 curve, got {type(private_key.curve).__name__}"
            )
        self._private_key = private_key
        self._public_key = private_key.public_key()

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message using ECDSA P-256 with SHA-256.

        Args:
            message: The message bytes to sign

        Returns:
            DER-encoded ECDSA signature
        """
        return self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def public_key(self) -> str:
        """
        Return the public key as base64 with ecdsa: prefix.

        Returns:
            String in format "ecdsa:<base64_compressed_public_key>"
        """
        import base64

        # Use compressed point format (33 bytes)
        public_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )
        return f"ecdsa:{base64.b64encode(public_bytes).decode()}"

    def public_key_bytes(self) -> bytes:
        """Return the compressed public key bytes."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

    def public_key_pem(self) -> str:
        """Return the public key in PEM format."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def private_key_pem(self) -> str:
        """Return the private key in PEM format (for storage)."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    @classmethod
    def from_pem_file(cls, path: str | Path) -> "EcdsaSigner":
        """
        Load an ECDSA signer from a PEM file.

        Args:
            path: Path to PEM file containing ECDSA P-256 private key

        Returns:
            EcdsaSigner instance
        """
        path = Path(path)
        pem_data = path.read_bytes()
        private_key = serialization.load_pem_private_key(pem_data, password=None)

        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise TypeError(
                f"Expected ECDSA private key, got {type(private_key).__name__}"
            )

        return cls(private_key)

    @classmethod
    def from_pem(cls, pem_string: str) -> "EcdsaSigner":
        """
        Load an ECDSA signer from a PEM string.

        Args:
            pem_string: PEM-encoded ECDSA P-256 private key

        Returns:
            EcdsaSigner instance
        """
        private_key = serialization.load_pem_private_key(
            pem_string.encode(), password=None
        )

        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise TypeError(
                f"Expected ECDSA private key, got {type(private_key).__name__}"
            )

        return cls(private_key)

    @classmethod
    def generate(cls) -> tuple["EcdsaSigner", str]:
        """
        Generate a new ECDSA P-256 keypair.

        Returns:
            Tuple of (signer, public_key_string)
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        signer = cls(private_key)
        return signer, signer.public_key()

    def verify(self, signature: bytes, message: bytes) -> bool:
        """
        Verify a signature (for testing purposes).

        Args:
            signature: The DER-encoded signature to verify
            message: The original message

        Returns:
            True if valid, False otherwise
        """
        try:
            self._public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
