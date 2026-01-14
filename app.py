import streamlit as st
import qrcode
from rsa_utils import *
from io import BytesIO
import hashlib

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

            # SIMPAN KE SESSION
            st.session_state.message = message
            st.session_state.signature = signature
            st.session_state.message_hash = message_hash

            st.success("✅ Digital Signature berhasil dibuat")

            st.markdown("### 🔑 Hash Pesan (SHA-256)")
            st.code(message_hash)

            # BUAT QR CODE DARI SIGNATURE
            qr = qrcode.make(signature)
            buf = BytesIO()
            qr.save(buf, format="PNG")
            buf.seek(0)

            st.image(buf, caption="QR Code Digital Signature")
            st.info("QR Code ini berisi Digital Signature")

# ===============================
# PENERIMA
# ===============================
if menu == "Penerima Pesan":
    st.subheader("📥 Antarmuka Penerima Pesan")

    st.info(
        "Masukkan Digital Signature yang diterima dari QR Code "
        "(hasil scan manual / tools eksternal)"
    )

    signature = st.text_area(
        "Digital Signature",
        height=150,
        value=st.session_state.get("signature", "")
    )

    message = st.text_area(
        "Pesan dari Pengirim (jika diubah → signature tidak valid)",
        value=st.session_state.get("message", "")
    )

    if st.button("Verifikasi Signature"):
        if signature.strip() == "" or message.strip() == "":
            st.error("Pesan dan Signature harus diisi")
        else:
            valid = npm_20221310083_verify_signature(
                st.session_state.public_key,
                message,
                signature
            )

            if valid:
                st.success("✅ Signature VALID\nPesan ASLI & tidak berubah")
            else:
                st.error("❌ Signature TIDAK VALID\nPesan telah dimodifikasi")
