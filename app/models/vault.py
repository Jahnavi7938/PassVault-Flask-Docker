from app import db
from .user import utcnow


class VaultItem(db.Model):
    __tablename__ = "vault_items"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    title = db.Column(db.String(120), nullable=False)
    website_url = db.Column(db.String(500))
    username = db.Column(db.String(255))
    encrypted_password = db.Column(db.Text, nullable=False)   # Fernet token, never plaintext
    notes = db.Column(db.Text)                                  # also a Fernet token when set
    category = db.Column(db.String(30), nullable=False, default="Other")
    # Strength is computed once, when the password is saved, so lists don't need to decrypt.
    strength = db.Column(db.String(10), nullable=False, default="weak")
    strength_score = db.Column(db.Integer, nullable=False, default=0)
    password_changed_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    last_accessed = db.Column(db.DateTime)

    owner = db.relationship("User", back_populates="vault_items")

    def to_dict(self):
        """Safe representation: never includes the password or notes."""
        iso = lambda d: d.isoformat() + "Z" if d else None  # noqa: E731
        return {
            "id": self.id,
            "title": self.title,
            "website_url": self.website_url,
            "username": self.username,
            "category": self.category,
            "strength": self.strength,
            "strength_score": self.strength_score,
            "password_changed_at": iso(self.password_changed_at),
            "created_at": iso(self.created_at),
            "updated_at": iso(self.updated_at),
            "last_accessed": iso(self.last_accessed),
        }
