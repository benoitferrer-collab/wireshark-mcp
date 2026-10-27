"""
Index d'offsets des paquets d'un fichier PCAP classique.

Permet de lire le paquet n°N par seek() direct au lieu de re-scanner le
fichier depuis le début à chaque consultation (O(1) au lieu de O(N)).

- L'index est construit en parcourant uniquement les en-têtes d'enregistrement
  (16 octets par paquet, sans dissection scapy) puis persisté en binaire
  (uint64 little-endian) à côté des résultats.
- Format PCAPNG non supporté (structure en blocs) : les appelants doivent
  prévoir un fallback en scan linéaire.
"""

import struct
import threading
from array import array
from pathlib import Path
from typing import Optional, Tuple

from app.core.logging_config import get_logger

logger = get_logger(__name__)

# Magic numbers PCAP classique -> (endianness struct, résolution nanoseconde)
_PCAP_MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', False),  # little-endian, microsecondes
    b'\xa1\xb2\xc3\xd4': ('>', False),  # big-endian, microsecondes
    b'\x4d\x3c\xb2\xa1': ('<', True),   # little-endian, nanosecondes
    b'\xa1\xb2\x3c\x4d': ('>', True),   # big-endian, nanosecondes
}

_GLOBAL_HEADER_LEN = 24
_RECORD_HEADER_LEN = 16

# Un seul thread construit l'index d'un fichier donné à la fois
_build_lock = threading.Lock()


def _read_global_header(f) -> Optional[Tuple[str, bool, int]]:
    """Retourne (endianness, nanoseconde, linktype) ou None si non-PCAP classique"""
    header = f.read(_GLOBAL_HEADER_LEN)
    if len(header) < _GLOBAL_HEADER_LEN:
        return None
    magic_info = _PCAP_MAGICS.get(header[:4])
    if magic_info is None:
        return None  # PCAPNG ou format inconnu
    endian, nano = magic_info
    linktype = struct.unpack(f'{endian}I', header[20:24])[0]
    return endian, nano, linktype


def _index_path_for(results_dir: Path) -> Path:
    return results_dir / 'packet_offsets.u64'


def build_offset_index(pcap_path: str, results_dir: Path,
                       max_packets: int = 500_000) -> Optional[array]:
    """
    Construit (ou charge) l'index des offsets d'enregistrement.
    Retourne un array('Q') d'offsets, ou None si le format n'est pas indexable.
    """
    index_path = _index_path_for(results_dir)

    # Index déjà construit ?
    if index_path.exists():
        try:
            offsets = array('Q')
            offsets.frombytes(index_path.read_bytes())
            return offsets
        except Exception as e:
            logger.warning("packet_index_load_error", error=str(e))

    with _build_lock:
        # Un autre thread a pu finir la construction pendant l'attente
        if index_path.exists():
            try:
                offsets = array('Q')
                offsets.frombytes(index_path.read_bytes())
                return offsets
            except Exception:
                pass

        try:
            with open(pcap_path, 'rb') as f:
                header_info = _read_global_header(f)
                if header_info is None:
                    return None  # PCAPNG: fallback scan linéaire côté appelant
                endian = header_info[0]

                offsets = array('Q')
                pos = _GLOBAL_HEADER_LEN
                unpack_incl = struct.Struct(f'{endian}I').unpack

                while len(offsets) < max_packets:
                    record = f.read(_RECORD_HEADER_LEN)
                    if len(record) < _RECORD_HEADER_LEN:
                        break
                    incl_len = unpack_incl(record[8:12])[0]
                    offsets.append(pos)
                    pos += _RECORD_HEADER_LEN + incl_len
                    f.seek(pos)

            index_path.write_bytes(offsets.tobytes())
            logger.info("packet_index_built", packets=len(offsets), path=str(index_path))
            return offsets
        except Exception as e:
            logger.warning("packet_index_build_error", error=str(e))
            return None


def read_packet_at(pcap_path: str, offset: int):
    """
    Lit et dissèque le paquet situé à `offset` (début de l'en-tête
    d'enregistrement). Retourne un paquet scapy ou None.
    """
    try:
        from scapy.all import conf
        from scapy.layers.l2 import Ether

        with open(pcap_path, 'rb') as f:
            header_info = _read_global_header(f)
            if header_info is None:
                return None
            endian, nano, linktype = header_info

            f.seek(offset)
            record = f.read(_RECORD_HEADER_LEN)
            if len(record) < _RECORD_HEADER_LEN:
                return None
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(f'{endian}IIII', record)
            data = f.read(incl_len)
            if len(data) < incl_len:
                return None

        # Classe de dissection selon le linktype (Ether par défaut)
        cls = conf.l2types.get(linktype, Ether)
        pkt = cls(data)
        pkt.time = ts_sec + ts_frac / (1e9 if nano else 1e6)
        return pkt
    except Exception as e:
        logger.warning("packet_read_at_error", offset=offset, error=str(e))
        return None


def get_packet_by_index(pcap_path: str, packet_num: int, results_dir: Path):
    """
    Accès direct au paquet n°packet_num via l'index d'offsets.
    Retourne un paquet scapy, ou None si non indexable (l'appelant
    doit alors faire un scan linéaire).
    """
    offsets = build_offset_index(pcap_path, results_dir)
    if offsets is None or packet_num < 0 or packet_num >= len(offsets):
        return None
    return read_packet_at(pcap_path, offsets[packet_num])
