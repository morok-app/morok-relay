# ============================================================================
# BURNER INBOX (Day 7)
# ============================================================================

BURNER_LABEL_MAX_LEN = 64
BURNER_SENDER_LABEL_MAX_LEN = 64


class BurnerCreate(BaseModel):
    """Owner creates a new burner link."""
    ttl_seconds: int | None = Field(default=None, ge=3600, le=30 * 86400)
    label: str | None = Field(default=None, max_length=BURNER_LABEL_MAX_LEN)


class BurnerInfo(BaseModel):
    """Returned to the owner."""
    token: str
    owner_pubkey_hex: str
    label: str | None
    created_at: int
    expires_at: int
    message_count: int


class BurnerList(BaseModel):
    tokens: list[BurnerInfo]


class BurnerTokenRevoked(BaseModel):
    token: str
    revoked: bool


class BurnerPublicInfo(BaseModel):
    """
    Returned to anyone with the burner URL — minimal info so they can
    encrypt for the owner. Does NOT reveal anything else about the owner
    (no username, no last-seen, etc).
    """
    owner_pubkey_hex: str
    label: str | None
    expires_at: int


class BurnerSend(BaseModel):
    """
    Payload submitted by an anonymous sender via the public burner endpoint.
    """
    ephemeral_pubkey_hex: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    blob_b64: str = Field(..., description="base64 ciphertext")
    sender_label: str | None = Field(
        default=None, max_length=BURNER_SENDER_LABEL_MAX_LEN,
    )


class BurnerSendAck(BaseModel):
    envelope_id: str
    queued: bool
    expires_at: int | None = None
    message_count: int | None = None
