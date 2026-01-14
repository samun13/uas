import streamlit as st
import qrcode
from rsa_utils import *
from io import BytesIO
import hashlib
import json

# ===============================
# KONFIGURASI HALAMAN
# ===============================
st.set_page_config(page_title="UAS Kriptografi", layout="centered")

st.title("🔐 Digital Signature RSA + QRIS")
st.caption("NPM: 20221310083")

menu = st.sidebar.selectbox(
    "Pilih Menu",
    ["Pengirim Pesan", "Penerima Pesan"]
)

# ===============================
# LOAD / GENERATE KEY (PERSISTENT)
# ===============================
if "keypair" not in st.session_state:
    st.session_state.private_key, st.session_state.public_key = (
        npm_20221310083_load_or_generate_key()
    )
    st.session_state.keypair = True

# ===============================
# PENGIRIM
# ===============================
if menu == "Pengirim Pesan":
    st.subheader("📤 Antarmuka Pengirim Pesan")

    message = st.text_area("Masukkan Pesan Digital")

    if st.button("Buat Digital Signature"):
        if message.strip() == "":
            st.error("Pesan tidak boleh kosong")
        else:
            # HASH PESAN
            message_hash = hashlib.sha256(message.encode()).hexdigest()

            # SIGN PESAN
            signature = npm_20221310083_sign_message(
                st.session_state.private_key,
                message
            )

            # PAYLOAD QR
            payload = {
                "message": message,
                "hash": message_hash,
                "signature": signature
            }

            payload_str = json.dumps(payload)

            # BUAT QR CODE
            qr = qrcode.make(payload_str)
            buf = BytesIO()
            qr.save(buf, format="PNG")
            buf.seek(0)

            st.success("✅ Digital Signature berhasil dibuat")

            st.markdown("### 📦 Payload QR Code")
            st.json(payload)

            st.image(buf, caption="QR Code Digital Signature")
            st.info("QR Code berisi pesan, hash SHA-256, dan signature RSA")

# ===============================
# PENERIMA
# ===============================
if menu == "Penerima Pesan":
    st.subheader("📥 Antarmuka Penerima Pesan")

    st.info(
        "Scan QR Code menggunakan aplikasi eksternal (HP / website), "
        "lalu paste hasilnya (JSON) di bawah ini"
    )

    qr_payload = st.text_area(
        "Isi QR Code (JSON)",
        height=220
    )

    if qr_payload.strip() != "":
        try:
            data = json.loads(qr_payload)

            original_message = data["message"]
            original_hash = data["hash"]
            signature = data["signature"]

            st.markdown("### 📄 Pesan dari QR Code")
            message_input = st.text_area(
                "Pesan",
                value=original_message
            )

            st.markdown("### 🔑 Hash dari QR Code")
            hash_input = st.text_input(
                "Hash Pesan",
                value=original_hash
            )

            # HITUNG ULANG HASH
            recalculated_hash = hashlib.sha256(
                message_input.encode()
            ).hexdigest()

            st.markdown("### 🔁 Hash Pesan Saat Ini")
            st.code(recalculated_hash)

            if st.button("Verifikasi Signature"):
                if hash_input != recalculated_hash:
                    st.error("❌ Hash tidak cocok — pesan telah diubah")
                else:
                    valid = npm_20221310083_verify_signature(
                        st.session_state.public_key,
                        message_input,
                        signature
                    )

                    if valid:
                        st.success(
                            "✅ Signature VALID\n"
                            "Pesan ASLI, utuh, dan tidak dimodifikasi"
                        )
                    else:
                        st.error("❌ Signature TIDAK VALID")

        except Exception:
            st.error("Format QR Code tidak valid (bukan JSON yang benar)")
