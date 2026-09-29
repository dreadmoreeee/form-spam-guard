"""Honeypot field: a hidden input that real people never fill in."""

from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class Honeypot:
    """Renders a hidden decoy field and checks that it came back empty.

    ``field_name`` should look like a real field (``website``, ``url``,
    ``company``). The field is hidden with an off-screen CSS class rather than
    ``display:none`` or ``type=hidden``, because simple bots skip those.
    """

    field_name: str = "website"
    css_class: str = "fsg-hp"
    label: str = "Website"

    def css(self) -> str:
        """CSS rule that moves the decoy off-screen. Put it in your stylesheet."""
        return (
            "." + self.css_class + "{position:absolute!important;left:-10000px;"
            "top:auto;width:1px;height:1px;overflow:hidden}"
        )

    def render(self) -> str:
        """HTML for the decoy field. Include it inside the <form>."""
        name = html.escape(self.field_name, quote=True)
        cls = html.escape(self.css_class, quote=True)
        label = html.escape(self.label)
        return (
            '<div class="' + cls + '" aria-hidden="true">'
            '<label for="fsg-' + name + '">' + label + "</label>"
            '<input type="text" id="fsg-' + name + '" name="' + name + '" value="" '
            'tabindex="-1" autocomplete="off">'
            "</div>"
        )

    def is_filled(self, form: Mapping[str, Any]) -> bool:
        """True when the decoy field carries any non-blank value."""
        value = form.get(self.field_name)
        if value is None:
            return False
        return str(value).strip() != ""
