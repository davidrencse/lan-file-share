"""Visual design tokens and the global stylesheet for the LANShare GUI.

One dark, purpose-built theme -- a small, calm color system (neutral surfaces,
a single accent, and semantic success/danger/warning colors), a restrained
type scale, and a consistent 4px spacing/radius rhythm. Every widget is styled
through this sheet plus the dynamic ``class`` property (e.g.
``widget.setProperty("class", "primary")``) rather than one-off inline styles,
so the whole app reads as one system.
"""

from __future__ import annotations

from dataclasses import dataclass

FONT_FAMILY = (
    '"Segoe UI Variable Text","Segoe UI","Inter","Noto Sans","Cantarell",'
    '"Helvetica Neue",Arial,sans-serif'
)
FONT_MONO = (
    '"Cascadia Mono","Consolas","JetBrains Mono","DejaVu Sans Mono",'
    '"Liberation Mono",monospace'
)

# 4px rhythm used throughout for margins/paddings/gaps.
SP_1, SP_2, SP_3, SP_4, SP_5, SP_6, SP_8 = 4, 8, 12, 16, 20, 24, 32

RADIUS_SM = 8
RADIUS_MD = 12
RADIUS_LG = 16
RADIUS_PILL = 999


@dataclass(frozen=True)
class Palette:
    bg: str = "#0c0e12"
    bg_elevated: str = "#111319"
    surface: str = "#161922"
    surface_hover: str = "#1b1f2a"
    surface_alt: str = "#0f1117"
    border: str = "#242a35"
    border_strong: str = "#323a48"

    text: str = "#eef1f6"
    text_secondary: str = "#a2acbd"
    text_muted: str = "#6b7486"
    text_on_accent: str = "#0a0f1c"

    accent: str = "#5b8cff"
    accent_hover: str = "#7099ff"
    accent_pressed: str = "#4676e6"
    accent_soft: str = "rgba(91, 140, 255, 0.14)"
    accent_border: str = "rgba(91, 140, 255, 0.38)"

    success: str = "#34d399"
    success_soft: str = "rgba(52, 211, 153, 0.14)"
    danger: str = "#f87171"
    danger_hover: str = "#ff8a8a"
    danger_soft: str = "rgba(248, 113, 113, 0.14)"
    warning: str = "#fbbf5e"
    warning_soft: str = "rgba(251, 191, 94, 0.14)"

    focus_ring: str = "rgba(91, 140, 255, 0.55)"


PALETTE = Palette()


# Extension -> (label, background, foreground) for the file-badge widget.
FILE_BADGE_GROUPS = {
    "image": (("png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "heic", "tiff"),
              "#7c9bff", "#0a0f1c"),
    "video": (("mp4", "mov", "mkv", "avi", "webm", "m4v", "wmv"),
              "#ff9f7c", "#1c0f08"),
    "audio": (("mp3", "wav", "flac", "aac", "ogg", "m4a"),
              "#ffd166", "#1c1608"),
    "archive": (("zip", "rar", "7z", "tar", "gz", "xz", "bz2"),
                "#c792ea", "#150f1c"),
    "doc": (("pdf", "doc", "docx", "txt", "md", "rtf", "odt"),
            "#7cd6ff", "#08161c"),
    "sheet": (("xls", "xlsx", "csv", "ods"),
              "#7cffb0", "#081c11"),
    "code": (("py", "js", "ts", "json", "html", "css", "c", "cpp", "java",
              "go", "rs", "sh", "yml", "yaml", "xml"),
             "#a7ff7c", "#111c08"),
}


def badge_for_extension(ext: str) -> tuple:
    """Return (label, bg_color, fg_color) for a file extension badge."""
    ext = ext.lower().lstrip(".")
    for group, (exts, bg, fg) in FILE_BADGE_GROUPS.items():
        if ext in exts:
            return (ext.upper()[:4] or "FILE", bg, fg)
    return (ext.upper()[:4] if ext else "FILE", "#8a93a6", "#0c0e12")


def build_stylesheet(p: Palette = PALETTE) -> str:
    return f"""
    * {{
        font-family: {FONT_FAMILY};
        outline: none;
    }}

    QWidget {{
        background: transparent;
        color: {p.text};
        font-size: 13px;
        selection-background-color: {p.accent};
        selection-color: {p.text_on_accent};
    }}

    QMainWindow, #AppRoot {{
        background: {p.bg};
    }}

    QScrollArea {{
        border: none;
        background: transparent;
    }}

    QScrollBar:vertical {{
        background: transparent;
        width: 10px;
        margin: 2px;
    }}
    QScrollBar::handle:vertical {{
        background: {p.border_strong};
        border-radius: 4px;
        min-height: 28px;
    }}
    QScrollBar::handle:vertical:hover {{ background: {p.text_muted}; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: none; }}

    /* ---- Sidebar ---------------------------------------------------- */
    #Sidebar {{
        background: {p.bg_elevated};
        border-right: 1px solid {p.border};
    }}
    #SidebarBrand {{
        color: {p.text};
        font-size: 15px;
        font-weight: 600;
        letter-spacing: 0.2px;
    }}
    #SidebarSub {{
        color: {p.text_muted};
        font-size: 11px;
    }}
    QPushButton[class="navitem"] {{
        text-align: left;
        padding: 9px 12px;
        border-radius: {RADIUS_SM}px;
        border: 1px solid transparent;
        background: transparent;
        color: {p.text_secondary};
        font-size: 13px;
        font-weight: 500;
    }}
    QPushButton[class="navitem"]:hover {{
        background: {p.surface_hover};
        color: {p.text};
    }}
    QPushButton[class="navitem"][active="true"] {{
        background: {p.accent_soft};
        color: {p.text};
        border: 1px solid {p.accent_border};
    }}

    #StatusDotOn {{ background: {p.success}; border-radius: 4px; }}
    #StatusDotOff {{ background: {p.text_muted}; border-radius: 4px; }}

    /* ---- Cards / surfaces -------------------------------------------- */
    QFrame[class="card"] {{
        background: {p.surface};
        border: 1px solid {p.border};
        border-radius: {RADIUS_LG}px;
    }}
    QFrame[class="card-flat"] {{
        background: {p.surface_alt};
        border: 1px solid {p.border};
        border-radius: {RADIUS_MD}px;
    }}
    QFrame[class="divider"] {{
        background: {p.border};
        max-height: 1px;
        min-height: 1px;
    }}

    /* ---- Typography ---------------------------------------------------*/
    QLabel[class="h1"] {{ font-size: 22px; font-weight: 650; color: {p.text}; }}
    QLabel[class="h2"] {{ font-size: 16px; font-weight: 650; color: {p.text}; }}
    QLabel[class="h3"] {{ font-size: 13px; font-weight: 650; color: {p.text}; }}
    QLabel[class="body"] {{ font-size: 13px; color: {p.text}; }}
    QLabel[class="secondary"] {{ font-size: 12.5px; color: {p.text_secondary}; }}
    QLabel[class="muted"] {{ font-size: 12px; color: {p.text_muted}; }}
    QLabel[class="mono"] {{
        font-family: {FONT_MONO};
        font-size: 11.5px;
        color: {p.text_secondary};
    }}
    QLabel[class="eyebrow"] {{
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 1.1px;
        color: {p.text_muted};
    }}
    QLabel[class="tag-success"] {{
        color: {p.success}; background: {p.success_soft};
        border-radius: {RADIUS_SM}px; padding: 3px 8px; font-size: 11px; font-weight: 600;
    }}
    QLabel[class="tag-danger"] {{
        color: {p.danger}; background: {p.danger_soft};
        border-radius: {RADIUS_SM}px; padding: 3px 8px; font-size: 11px; font-weight: 600;
    }}
    QLabel[class="tag-warning"] {{
        color: {p.warning}; background: {p.warning_soft};
        border-radius: {RADIUS_SM}px; padding: 3px 8px; font-size: 11px; font-weight: 600;
    }}
    QLabel[class="tag-neutral"] {{
        color: {p.text_secondary}; background: {p.surface_hover};
        border-radius: {RADIUS_SM}px; padding: 3px 8px; font-size: 11px; font-weight: 600;
    }}

    /* ---- Buttons ------------------------------------------------------*/
    QPushButton {{
        font-size: 13px;
        font-weight: 600;
        border-radius: {RADIUS_SM}px;
        padding: 9px 16px;
        border: 1px solid transparent;
    }}
    QPushButton[class="primary"] {{
        background: {p.accent};
        color: {p.text_on_accent};
    }}
    QPushButton[class="primary"]:hover {{ background: {p.accent_hover}; }}
    QPushButton[class="primary"]:pressed {{ background: {p.accent_pressed}; }}
    QPushButton[class="primary"]:disabled {{ background: {p.border_strong}; color: {p.text_muted}; }}

    QPushButton[class="secondary"] {{
        background: {p.surface};
        color: {p.text};
        border: 1px solid {p.border_strong};
    }}
    QPushButton[class="secondary"]:hover {{ background: {p.surface_hover}; }}
    QPushButton[class="secondary"]:pressed {{ background: {p.surface_alt}; }}
    QPushButton[class="secondary"]:disabled {{ color: {p.text_muted}; }}

    QPushButton[class="danger"] {{
        background: {p.danger_soft};
        color: {p.danger};
        border: 1px solid rgba(248, 113, 113, 0.35);
    }}
    QPushButton[class="danger"]:hover {{ background: rgba(248, 113, 113, 0.22); color: {p.danger_hover}; }}

    QPushButton[class="ghost"] {{
        background: transparent;
        color: {p.text_secondary};
        border: 1px solid transparent;
        padding: 7px 10px;
    }}
    QPushButton[class="ghost"]:hover {{ background: {p.surface_hover}; color: {p.text}; }}

    QPushButton[class="icon"] {{
        background: {p.surface_alt};
        border: 1px solid {p.border};
        border-radius: {RADIUS_SM}px;
        padding: 6px;
    }}
    QPushButton[class="icon"]:hover {{ background: {p.surface_hover}; border-color: {p.border_strong}; }}

    /* ---- Inputs ---------------------------------------------------- */
    QLineEdit, QSpinBox, QComboBox {{
        background: {p.surface_alt};
        border: 1px solid {p.border_strong};
        border-radius: {RADIUS_SM}px;
        padding: 8px 10px;
        color: {p.text};
        font-size: 13px;
        selection-background-color: {p.accent};
    }}
    QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
        border: 1px solid {p.accent};
    }}
    QLineEdit:disabled {{ color: {p.text_muted}; }}
    QLineEdit[class="mono"] {{ font-family: {FONT_MONO}; font-size: 12px; }}
    QComboBox::drop-down {{ border: none; width: 24px; }}
    QComboBox QAbstractItemView {{
        background: {p.surface};
        border: 1px solid {p.border_strong};
        selection-background-color: {p.accent_soft};
        selection-color: {p.text};
        outline: none;
        padding: 4px;
        border-radius: {RADIUS_SM}px;
    }}
    QSpinBox::up-button, QSpinBox::down-button {{ width: 16px; border: none; }}

    /* ---- Progress ---------------------------------------------------- */
    QProgressBar {{
        background: {p.surface_alt};
        border: 1px solid {p.border};
        border-radius: {RADIUS_SM}px;
        text-align: center;
        color: {p.text_secondary};
        font-size: 11px;
        min-height: 8px;
        max-height: 8px;
    }}
    QProgressBar::chunk {{
        background: {p.accent};
        border-radius: {RADIUS_SM}px;
    }}
    QProgressBar[state="success"]::chunk {{ background: {p.success}; }}
    QProgressBar[state="danger"]::chunk {{ background: {p.danger}; }}
    QProgressBar[indeterminate="true"]::chunk {{ background: {p.accent}; }}

    /* ---- Lists --------------------------------------------------------*/
    QListWidget {{
        background: transparent;
        border: none;
    }}
    QListWidget::item {{ border: none; padding: 0; margin: 0 0 8px 0; }}
    QListWidget::item:selected {{ background: transparent; }}

    /* ---- Dialogs ------------------------------------------------------*/
    QDialog {{
        background: {p.bg_elevated};
    }}

    QToolTip {{
        background: {p.surface};
        color: {p.text};
        border: 1px solid {p.border_strong};
        padding: 6px 8px;
        border-radius: {RADIUS_SM}px;
    }}

    QCheckBox {{ spacing: 8px; color: {p.text_secondary}; }}
    QCheckBox::indicator {{
        width: 16px; height: 16px;
        border-radius: 5px;
        border: 1px solid {p.border_strong};
        background: {p.surface_alt};
    }}
    QCheckBox::indicator:checked {{
        background: {p.accent};
        border-color: {p.accent};
    }}
    """
