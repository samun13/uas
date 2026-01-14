import streamlit as st
import qrcode
from rsa_utils import *
from io import BytesIO
from PIL import Image
from pyzbar.pyzbar import decode
import hashlib
import base64

st.set_page_config(page_title="UAS Kriptografi", layout="centered")

st.title("🔐 Digital Signature RSA + QRIS")
st.caption("NPM: 20221310083")

menu = st.sidebar.selectbox(
    "Pilih Menu",
    ["Pengirim Pesan", "Penerima Pesan"]
)

# =====================================
# LOAD / GENERATE KEY (PERSISTENT)
# =====================================
if "keypair" not in st.session_state:
    st.session_state.private_key, st.session_state.public_key = \
        npm_20221310083_load_or_generate_key()
    st.session_state.keypair = True

# ===============================
# PENGIRIM
# ===============================
if menu == "Pengirim Pesan":
    st.subheader("📤 Antarmuka Pengirim Pesan")

    message = st.text_area("Masukkan Pesan Digital")

    if st.button("Buat Digital Signature"):
        # HASH PESAN
        message_hash = hashlib.sha256(message.encode()).hexdigest()

        # SIGN MESSAGE
        signature = npm_20221310083_sign_message(
            st.session_state.private_key,
            message
        )

        # SIMPAN KE SESSION
        st.session_state.message = message
        st.session_state.signature = signature
        st.session_state.message_hash = message_hash

        st.success("Digital Signature berhasil dibuat")

        st.markdown("### 🔑 Hash Pesan (SHA-256)")
        st.code(message_hash)

        # BUAT QR CODE
        qr = qrcode.make(signature)
        buf = BytesIO()
        qr.save(buf, format="PNG")
        buf.seek(0)

        st.image(buf, caption="QRIS Digital Signature")
        st.info("QR Code ini dikirim ke penerima")

# ===============================
# PENERIMA
# ===============================
if menu == "Penerima Pesan":
    st.subheader("📥 Antarmuka Penerima Pesan")

    uploaded_file = st.file_uploader(
        "Upload QR Code dari Pengirim",
        type=["png", "jpg", "jpeg"]
    )

    if uploaded_file is not None:
        image = Image.open(uploaded_file)
        st.image(image, caption="QR Code diterima")

        decoded_objects = decode(image)

        if decoded_objects:
            signature = decoded_objects[0].data.decode("utf-8")
            st.success("QR Code berhasil dibaca")

            # HASH SIGNATURE (DARI QR)
            signature_hash = hashlib.sha256(
                base64.b64decode(signature)
            ).hexdigest()

            st.markdown("### 🔐 Hash Signature (dari QR Code)")
            st.code(signature_hash)

            # PESAN OTOMATIS (BOLEH DIUBAH)
            message = st.text_area(
                "Pesan dari Pengirim (Jika diubah → Signature TIDAK VALID)",
                value=st.session_state.get("message", "")
            )

            # HASH PESAN PENERIMA
            message_hash = hashlib.sha256(message.encode()).hexdigest()
            st.markdown("### 🔑 Hash Pesan Saat Ini (SHA-256)")
            st.code(message_hash)

            if st.button("Verifikasi Signature"):
                valid = npm_20221310083_verify_signature(
                    st.session_state.public_key,
                    message,
                    signature
                )

                if valid:
                    st.success("✅ Signature VALID\nPesan ASLI & tidak berubah")
                else:
                    st.error("❌ Signature TIDAK VALID\nPesan telah dimodifikasi")
        else:
            st.error("QR Code tidak valid atau tidak terbaca")
