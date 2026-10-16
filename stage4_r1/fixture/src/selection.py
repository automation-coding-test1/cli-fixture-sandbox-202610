"""Synthetic comma/range selection parser — intentionally incomplete fixture."""

def parse_selection(text: str) -> list[int]:
    """Return sorted, unique nonnegative IDs from comma-separated numbers/ranges.

    Examples: "3,1-2,3" -> [1, 2, 3]. An ascending range includes endpoints.
    Malformed/empty/negative/reversed input raises ValueError.
    """
    return [int(piece.strip()) for piece in text.split(",")]
