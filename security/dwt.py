from PIL import Image
import numpy as np
import struct


# ============================================================
# MediSecure Steganography
# ============================================================
#
# Hides an arbitrary byte payload inside the BLUE channel of
# a color PNG, one bit per 2x2 block (LSB of the top-left
# pixel of each block).
#
# Stored stream:
#     [MAGIC (4)] [payload_len (4, BE)] [payload]
#
# For this application the payload is an encrypted envelope:
#     [rsa_key_len (4, BE)] [rsa_key] [aes_payload]
#
# ============================================================

MAGIC = b"MSD1"
HEADER_SIZE = 8
ENVELOPE_KEY_LEN_SIZE = 4


# ============================================================
# INTERNAL HELPERS
# ============================================================

def _bytes_to_bits(data):
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bits_to_bytes(bits):
    if len(bits) % 8 != 0:
        raise ValueError(
            "Bit stream length is not a multiple of 8."
        )

    out = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        for bit in bits[i:i + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def _capacity_in_bits(width, height):
    return (width // 2) * (height // 2)


# ============================================================
# EMBED DATA
# ============================================================

def embed_data(cover_image_path, secret_data, output_path):
    """
    Hide secret_data inside a color medical-themed cover image.

    Data is embedded into the BLUE channel.
    One pixel from every 2x2 block is used.
    """

    # --------------------------------------------------------
    # Open cover image
    # --------------------------------------------------------

    image = Image.open(
        cover_image_path
    ).convert("RGB")

    image_array = np.array(image)

    height, width, channels = image_array.shape

    # --------------------------------------------------------
    # Make dimensions even
    # --------------------------------------------------------

    if width % 2 != 0:
        width -= 1

    if height % 2 != 0:
        height -= 1

    image_array = image_array[:height, :width]

    # --------------------------------------------------------
    # Check secret data
    # --------------------------------------------------------

    if isinstance(secret_data, str):
        secret_data = secret_data.encode("utf-8")

    secret_data = bytes(secret_data)

    # --------------------------------------------------------
    # Create header
    #
    # 4 bytes = MAGIC
    # 4 bytes = payload length
    # --------------------------------------------------------

    payload_length = len(secret_data)

    header = (
        MAGIC +
        struct.pack(">I", payload_length)
    )

    complete_data = header + secret_data

    # --------------------------------------------------------
    # Convert bytes to bits
    # --------------------------------------------------------

    data_bits = []

    for byte in complete_data:

        for bit_position in range(7, -1, -1):

            bit = (
                byte >> bit_position
            ) & 1

            data_bits.append(bit)

    required_bits = len(data_bits)

    # --------------------------------------------------------
    # Calculate capacity
    # --------------------------------------------------------

    capacity = _capacity_in_bits(width, height)

    if required_bits > capacity:

        raise ValueError(
            "Data is too large for this cover image. "
            f"Required: {required_bits} bits, "
            f"Available: {capacity} bits."
        )

    # --------------------------------------------------------
    # Blue channel
    # --------------------------------------------------------

    blue_channel = (
        image_array[:, :, 2].copy()
    )

    bit_index = 0

    # --------------------------------------------------------
    # Embed one bit per 2x2 block
    # --------------------------------------------------------

    for y in range(0, height, 2):

        for x in range(0, width, 2):

            if bit_index >= required_bits:
                break

            value = int(
                blue_channel[y, x]
            )

            # Clear LSB
            value = value & 0xFE

            # Insert secret bit
            value = (
                value |
                data_bits[bit_index]
            )

            blue_channel[y, x] = value

            bit_index += 1

        if bit_index >= required_bits:
            break

    # --------------------------------------------------------
    # Put blue channel back
    # --------------------------------------------------------

    image_array[:, :, 2] = blue_channel

    # --------------------------------------------------------
    # Create RGB stego image
    # --------------------------------------------------------

    stego_image = Image.fromarray(
        image_array.astype(np.uint8),
        "RGB"
    )

    # --------------------------------------------------------
    # Save as PNG
    # --------------------------------------------------------

    stego_image.save(
        output_path,
        format="PNG"
    )

    return output_path


# ============================================================
# EXTRACT DATA
# ============================================================

def extract_data(stego_image_path):
    """
    Extract hidden data from a MediSecure stego image.

    IMPORTANT:
        This function accepts ONLY ONE argument:
            stego_image_path

    Returns
    -------
    bytes
        The exact payload that was passed to embed_data().
        For this application that is the encrypted envelope:
            [rsa_key_len][rsa_key][aes_payload]
    """

    # --------------------------------------------------------
    # Open stego image
    # --------------------------------------------------------

    image = Image.open(
        stego_image_path
    ).convert("RGB")

    image_array = np.array(image)

    height, width, channels = image_array.shape

    # --------------------------------------------------------
    # Blue channel
    # --------------------------------------------------------

    blue_channel = (
        image_array[:, :, 2]
    )

    # --------------------------------------------------------
    # Capacity
    # --------------------------------------------------------

    capacity = _capacity_in_bits(width, height)

    # --------------------------------------------------------
    # Header requires 64 bits
    # --------------------------------------------------------

    if capacity < 64:

        raise ValueError(
            "Stego image is too small to contain "
            "a MediSecure payload."
        )

    # --------------------------------------------------------
    # Extract first 64 bits
    # --------------------------------------------------------

    header_bits = []

    for y in range(0, height, 2):

        for x in range(0, width, 2):

            bit = (
                int(
                    blue_channel[y, x]
                ) & 1
            )

            header_bits.append(bit)

            if len(header_bits) >= 64:
                break

        if len(header_bits) >= 64:
            break

    # --------------------------------------------------------
    # Convert 64 bits to 8 bytes
    # --------------------------------------------------------

    header_bytes = bytearray()

    for i in range(0, 64, 8):

        byte_value = 0

        for bit in header_bits[i:i + 8]:

            byte_value = (
                byte_value << 1
            ) | bit

        header_bytes.append(
            byte_value
        )

    header_bytes = bytes(
        header_bytes
    )

    # --------------------------------------------------------
    # Verify MAGIC
    # --------------------------------------------------------

    if header_bytes[:4] != MAGIC:

        raise ValueError(
            "Invalid stego image. "
            "MediSecure data was not found."
        )

    # --------------------------------------------------------
    # Read payload length
    # --------------------------------------------------------

    payload_length = struct.unpack(
        ">I",
        header_bytes[4:8]
    )[0]

    # --------------------------------------------------------
    # Validate payload length
    # --------------------------------------------------------

    total_bits = (
        HEADER_SIZE +
        payload_length
    ) * 8

    if total_bits > capacity:

        raise ValueError(
            "Invalid payload length in stego image."
        )

    # --------------------------------------------------------
    # Extract complete payload
    # --------------------------------------------------------

    extracted_bits = []

    for y in range(0, height, 2):

        for x in range(0, width, 2):

            bit = (
                int(
                    blue_channel[y, x]
                ) & 1
            )

            extracted_bits.append(bit)

            if len(extracted_bits) >= total_bits:
                break

        if len(extracted_bits) >= total_bits:
            break

    # --------------------------------------------------------
    # Convert bits to bytes
    # --------------------------------------------------------

    extracted_bytes = bytearray()

    for i in range(
        0,
        total_bits,
        8
    ):

        byte_value = 0

        for bit in extracted_bits[i:i + 8]:

            byte_value = (
                byte_value << 1
            ) | bit

        extracted_bytes.append(
            byte_value
        )

    # --------------------------------------------------------
    # Remove header
    # --------------------------------------------------------

    secret_data = bytes(
        extracted_bytes[
            HEADER_SIZE:
        ]
    )

    # --------------------------------------------------------
    # Verify length
    # --------------------------------------------------------

    if len(secret_data) != payload_length:

        raise ValueError(
            "Extracted data length does not match "
            "the stored payload length."
        )

    return secret_data


# ============================================================
# EXTRACT ENVELOPE  (NEW CONVENIENCE HELPER)
# ============================================================

def extract_envelope(stego_image_path):
    """
    Extract and unpack the encrypted envelope hidden in a
    stego image.

    The sender stores:

        [rsa_key_len (4 bytes BE)] [rsa_key] [aes_payload]

    This helper calls extract_data() internally (so it still
    takes only ONE argument) and returns the two parts
    separately.

    Returns
    -------
    (bytes, bytes)
        (rsa_encrypted_aes_key, aes_encrypted_payload)
    """

    envelope = extract_data(stego_image_path)

    if len(envelope) < ENVELOPE_KEY_LEN_SIZE:
        raise ValueError("Stego envelope is too short.")

    rsa_key_len = struct.unpack(
        ">I",
        envelope[:ENVELOPE_KEY_LEN_SIZE]
    )[0]

    expected_min = ENVELOPE_KEY_LEN_SIZE + rsa_key_len
    if len(envelope) < expected_min:
        raise ValueError("Stego envelope is truncated.")

    rsa_key = envelope[
        ENVELOPE_KEY_LEN_SIZE:
        ENVELOPE_KEY_LEN_SIZE + rsa_key_len
    ]

    aes_payload = envelope[
        ENVELOPE_KEY_LEN_SIZE + rsa_key_len:
    ]

    return rsa_key, aes_payload