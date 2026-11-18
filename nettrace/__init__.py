from __future__ import annotations

import logging
import warnings

# Suppress benign Scapy runtime warnings on Windows (e.g., missing live libpcap provider,
# ISAKMP dissection boundary padding) and Cryptography deprecation notices.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

warnings.filterwarnings("ignore", message=".*Diffie-Hellman over finite fields.*")

__version__ = "1.0.0"
