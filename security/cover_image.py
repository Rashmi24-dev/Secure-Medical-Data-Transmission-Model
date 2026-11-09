import os
import math
from PIL import Image, ImageDraw, ImageFilter


def generate_medical_cover(output_path, payload_size):
    """
    Automatically generates a color medical-themed
    cover image for MediSecure.

    The sender does NOT upload the cover image.
    """

    # ---------------------------------------------------------
    # 1. Calculate required image size
    # ---------------------------------------------------------

    header_size = 8

    total_bytes = payload_size + header_size
    required_bits = total_bytes * 8

    # Current DWT capacity:
    # approximately 1 bit per 4 pixels
    required_pixels = required_bits * 4

    minimum_side = math.ceil(math.sqrt(required_pixels))

    # Minimum cover size
    side = max(1024, minimum_side)

    # Keep dimensions even
    if side % 2 != 0:
        side += 1

    # Safety limit
    max_side = 12000

    if side > max_side:
        raise ValueError(
            "The medical data is too large for the current "
            "steganography capacity."
        )

    width = side
    height = side

    # ---------------------------------------------------------
    # 2. Create medical blue/white background
    # ---------------------------------------------------------

    image = Image.new(
        "RGB",
        (width, height),
        (225, 242, 250)
    )

    draw = ImageDraw.Draw(image)

    # ---------------------------------------------------------
    # 3. Main rounded medical panel
    # ---------------------------------------------------------

    margin = width // 12

    draw.rounded_rectangle(
        [
            margin,
            margin,
            width - margin,
            height - margin
        ],
        radius=width // 30,
        fill=(235, 248, 253),
        outline=(90, 170, 205),
        width=max(3, width // 300)
    )

    # ---------------------------------------------------------
    # 4. Decorative blue circles
    # ---------------------------------------------------------

    center_x = width // 2
    center_y = height // 2

    radius1 = width // 3
    radius2 = width // 5
    radius3 = width // 10

    draw.ellipse(
        [
            center_x - radius1,
            center_y - radius1,
            center_x + radius1,
            center_y + radius1
        ],
        outline=(170, 215, 235),
        width=max(3, width // 300)
    )

    draw.ellipse(
        [
            center_x - radius2,
            center_y - radius2,
            center_x + radius2,
            center_y + radius2
        ],
        outline=(130, 195, 225),
        width=max(3, width // 350)
    )

    # ---------------------------------------------------------
    # 5. Large medical cross
    # ---------------------------------------------------------

    cross_width = width // 14
    cross_length = width // 4

    draw.rounded_rectangle(
        [
            center_x - cross_width // 2,
            center_y - cross_length // 2,
            center_x + cross_width // 2,
            center_y + cross_length // 2
        ],
        radius=10,
        fill=(45, 150, 190)
    )

    draw.rounded_rectangle(
        [
            center_x - cross_length // 2,
            center_y - cross_width // 2,
            center_x + cross_length // 2,
            center_y + cross_width // 2
        ],
        radius=10,
        fill=(45, 150, 190)
    )

    # ---------------------------------------------------------
    # 6. ECG / heartbeat line
    # ---------------------------------------------------------

    ecg_y = int(height * 0.73)

    points = [
        (int(width * 0.12), ecg_y),
        (int(width * 0.22), ecg_y),
        (int(width * 0.27), ecg_y - height * 0.04),
        (int(width * 0.31), ecg_y),
        (int(width * 0.37), ecg_y),
        (int(width * 0.42), ecg_y + height * 0.08),
        (int(width * 0.47), ecg_y - height * 0.15),
        (int(width * 0.52), ecg_y + height * 0.04),
        (int(width * 0.57), ecg_y),
        (int(width * 0.68), ecg_y),
        (int(width * 0.72), ecg_y - height * 0.04),
        (int(width * 0.76), ecg_y),
        (int(width * 0.88), ecg_y)
    ]

    draw.line(
        points,
        fill=(30, 130, 180),
        width=max(4, width // 250),
        joint="curve"
    )

    # ---------------------------------------------------------
    # 7. Stethoscope-style design
    # ---------------------------------------------------------

    sx = int(width * 0.20)
    sy = int(height * 0.30)

    sr = width // 15

    # Upper tube
    draw.arc(
        [
            sx - sr,
            sy - sr,
            sx + sr,
            sy + sr
        ],
        start=20,
        end=160,
        fill=(40, 115, 150),
        width=max(5, width // 250)
    )

    # Lower tube
    draw.arc(
        [
            sx - sr * 2,
            sy,
            sx + sr * 2,
            sy + sr * 3
        ],
        start=0,
        end=180,
        fill=(40, 115, 150),
        width=max(5, width // 250)
    )

    # Chest piece
    chest_x = sx
    chest_y = sy + sr * 2

    draw.ellipse(
        [
            chest_x - sr // 2,
            chest_y - sr // 2,
            chest_x + sr // 2,
            chest_y + sr // 2
        ],
        fill=(70, 150, 185),
        outline=(30, 100, 140),
        width=max(2, width // 350)
    )

    # ---------------------------------------------------------
    # 8. DNA-style pattern
    # ---------------------------------------------------------

    dna_x = int(width * 0.80)
    dna_top = int(height * 0.15)
    dna_bottom = int(height * 0.48)

    dna_points_left = []
    dna_points_right = []

    steps = 40

    for i in range(steps + 1):

        y = dna_top + (
            dna_bottom - dna_top
        ) * i / steps

        angle = i / steps * math.pi * 2

        offset = math.sin(angle) * width * 0.035

        left_x = dna_x - width * 0.045 + offset
        right_x = dna_x + width * 0.045 - offset

        dna_points_left.append((left_x, y))
        dna_points_right.append((right_x, y))

        # DNA connection lines
        if i % 4 == 0:
            draw.line(
                [
                    (left_x, y),
                    (right_x, y)
                ],
                fill=(120, 190, 215),
                width=max(2, width // 400)
            )

    draw.line(
        dna_points_left,
        fill=(50, 145, 185),
        width=max(4, width // 300)
    )

    draw.line(
        dna_points_right,
        fill=(50, 145, 185),
        width=max(4, width // 300)
    )

    # ---------------------------------------------------------
    # 9. Small medical crosses
    # ---------------------------------------------------------

    small_cross = width // 45

    positions = [
        (int(width * 0.15), int(height * 0.52)),
        (int(width * 0.82), int(height * 0.55)),
        (int(width * 0.30), int(height * 0.18)),
        (int(width * 0.70), int(height * 0.18))
    ]

    for x, y in positions:

        draw.rectangle(
            [
                x - small_cross // 7,
                y - small_cross // 2,
                x + small_cross // 7,
                y + small_cross // 2
            ],
            fill=(80, 170, 205)
        )

        draw.rectangle(
            [
                x - small_cross // 2,
                y - small_cross // 7,
                x + small_cross // 2,
                y + small_cross // 7
            ],
            fill=(80, 170, 205)
        )

    # ---------------------------------------------------------
    # 10. Digital-security pattern
    # ---------------------------------------------------------

    security_x = int(width * 0.15)
    security_y = int(height * 0.18)

    for row in range(4):

        for col in range(5):

            x = security_x + col * width // 35
            y = security_y + row * width // 35

            draw.rounded_rectangle(
                [
                    x,
                    y,
                    x + width // 100,
                    y + width // 100
                ],
                radius=4,
                fill=(120, 190, 215)
            )

    # ---------------------------------------------------------
    # 11. Soft blur
    # ---------------------------------------------------------

    image = image.filter(
        ImageFilter.GaussianBlur(radius=0.4)
    )

    # ---------------------------------------------------------
    # 12. Create output directory
    # ---------------------------------------------------------

    output_directory = os.path.dirname(output_path)

    if output_directory:
        os.makedirs(
            output_directory,
            exist_ok=True
        )

    # ---------------------------------------------------------
    # 13. Save color medical cover
    # ---------------------------------------------------------

    image.save(
        output_path,
        format="PNG"
    )

    return output_path