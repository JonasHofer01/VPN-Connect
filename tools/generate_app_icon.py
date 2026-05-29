from pathlib import Path
import struct

from PyQt6.QtCore import QBuffer, QIODevice, Qt
from PyQt6.QtGui import QColor, QImage, QPainter, QPen, QBrush, QLinearGradient


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
ICON_PATH = ASSETS / "app_icon.ico"
PNG_PATH = ASSETS / "app_icon.png"
SIZES = (16, 24, 32, 48, 64, 128, 256)


def render_icon(size: int) -> QImage:
    image = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(Qt.GlobalColor.transparent)

    p = QPainter(image)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.scale(size / 256, size / 256)

    bg = QLinearGradient(0, 0, 256, 256)
    bg.setColorAt(0.0, QColor("#102033"))
    bg.setColorAt(0.55, QColor("#123b4a"))
    bg.setColorAt(1.0, QColor("#0f766e"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(bg))
    p.drawRoundedRect(10, 10, 236, 236, 54, 54)

    p.setBrush(QColor(34, 211, 238, 42))
    p.drawEllipse(142, 24, 88, 88)
    p.setBrush(QColor(52, 211, 153, 36))
    p.drawEllipse(34, 150, 96, 96)

    net_pen = QPen(QColor("#67e8f9"), 12)
    net_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(net_pen)
    p.drawLine(128, 128, 76, 178)
    p.drawLine(128, 128, 180, 178)
    p.drawLine(128, 128, 128, 74)

    node_border = QPen(QColor("#0b1222"), 8)
    p.setPen(node_border)
    p.setBrush(QColor("#e5ecf5"))
    p.drawEllipse(60, 162, 34, 34)
    p.drawEllipse(162, 162, 34, 34)
    p.drawEllipse(111, 57, 34, 34)

    house_pen = QPen(QColor("#e5ecf5"), 14)
    house_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    house_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(house_pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawLine(76, 126, 128, 78)
    p.drawLine(128, 78, 180, 126)
    p.drawRoundedRect(88, 116, 80, 62, 12, 12)

    p.setPen(QPen(QColor("#0b1222"), 8))
    p.setBrush(QColor("#34d399"))
    p.drawEllipse(108, 108, 40, 40)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#e5ecf5"))
    p.drawEllipse(121, 121, 14, 14)

    p.end()
    return image


def png_bytes(image: QImage) -> bytes:
    buffer = QBuffer()
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    if not image.save(buffer, "PNG"):
        raise RuntimeError("PNG export failed")
    return bytes(buffer.data())


def write_ico(path: Path) -> None:
    images = [(size, png_bytes(render_icon(size))) for size in SIZES]
    offset = 6 + 16 * len(images)
    entries = []

    for size, data in images:
        width = 0 if size == 256 else size
        height = 0 if size == 256 else size
        entries.append(
            struct.pack(
                "<BBBBHHII",
                width,
                height,
                0,
                0,
                1,
                32,
                len(data),
                offset,
            )
        )
        offset += len(data)

    with path.open("wb") as fh:
        fh.write(struct.pack("<HHH", 0, 1, len(images)))
        for entry in entries:
            fh.write(entry)
        for _, data in images:
            fh.write(data)


def main() -> None:
    ASSETS.mkdir(exist_ok=True)
    render_icon(256).save(str(PNG_PATH), "PNG")
    write_ico(ICON_PATH)
    print(f"Wrote {ICON_PATH}")
    print(f"Wrote {PNG_PATH}")


if __name__ == "__main__":
    main()
