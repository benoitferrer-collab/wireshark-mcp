"""Strict TLS secret validation. No user material belongs in errors or logs."""
import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

LIMITS={'rsa':65536,'keylog':2097152}
LABELS={'CLIENT_RANDOM':(96,), 'CLIENT_EARLY_TRAFFIC_SECRET':(64,96),
        'CLIENT_HANDSHAKE_TRAFFIC_SECRET':(64,96),'SERVER_HANDSHAKE_TRAFFIC_SECRET':(64,96),
        'CLIENT_TRAFFIC_SECRET_0':(64,96),'SERVER_TRAFFIC_SECRET_0':(64,96),
        'EARLY_EXPORTER_SECRET':(64,96),'EXPORTER_SECRET':(64,96)}

def validate_secret(kind,body,password=''):
    if kind not in LIMITS or not body or len(body)>LIMITS[kind]:
        raise ValueError('Format ou taille du fichier de secrets invalide (RSA : 64 Kio ; keylog : 2 Mio).')
    if len(password)>512:raise ValueError('Mot de passe trop long.')
    if kind=='rsa':
        try:
            key=serialization.load_pem_private_key(body,password.encode() if password else None)
        except (ValueError,TypeError):raise ValueError('Clé PEM invalide ou mot de passe incorrect.') from None
        if not isinstance(key,RSAPrivateKey):raise ValueError('Une clé privée RSA serveur est requise ; les clés EC ne conviennent pas.')
        return key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    try:lines=body.decode('ascii').splitlines()
    except UnicodeDecodeError:raise ValueError('Le keylog doit être un fichier texte SSLKEYLOGFILE.') from None
    count=0
    for line in lines:
        line=line.strip()
        if not line or line.startswith('#'):continue
        fields=line.split()
        if (len(fields)!=3 or fields[0] not in LABELS or len(fields[1])!=64
            or len(fields[2]) not in LABELS[fields[0]] or not re.fullmatch('[0-9a-fA-F]+',fields[1]+fields[2])):
            raise ValueError('Ligne SSLKEYLOGFILE invalide ou type de secret non pris en charge.')
        count+=1
    if not count:raise ValueError('Aucun secret de session dans ce fichier.')
    return body
