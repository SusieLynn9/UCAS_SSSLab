"""Private local JSON configuration and verified TLS contexts."""
import json
from pathlib import Path
import ssl

def load(path):
    path=Path(path).resolve()
    if path.stat().st_size>65536:raise ValueError('Configuration too large')
    config=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(config,dict):raise ValueError('Configuration object required')
    for key in ('cafile','certfile','keyfile','root'):
        if key in config:
            p=Path(config[key]);config[key]=str(p if p.is_absolute() else path.parent/p)
    return config

def context(config,server=False):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) if server else ssl.create_default_context(cafile=config['cafile'])
    ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(config['certfile'],config['keyfile'])
    if server:ctx.load_verify_locations(config['cafile']);ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20')
    return ctx
