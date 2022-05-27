import datetime

from cryptography import x509
from cryptography.hazmat._oid import NameOID, ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from button import Button
from helpers import *
from textbox import Textbox


class App:
    def __init__(self):
        self.window = pygame.display.set_mode((900, 440))
        self.icon = pygame.image.load("icon.jpg")
        self.font = pygame.font.SysFont("Arial", 16)

        self.verify_file = None
        self.certificate = None
        self.certificate_path = None
        self.sign_file = None
        self.sign_key = None
        self.key_path = None
        self.text_content = None
        self.verify_message = ""
        self.verify_message_color = (0, 200, 0)
        self.sign_message = ""
        self.sign_message_color = (0, 200, 0)

        button1 = Button(self.window, 20, 160, 130, 30, "select file", self.chosen_verification_file)
        button2 = Button(self.window, 470, 160, 130, 30, "select file", self.chosen_signing_file)
        button3 = Button(self.window, 20, 280, 130, 30, "select certificate", self.chosen_certificate)
        button4 = Button(self.window, 470, 280, 130, 30, "select key", self.chosen_signing_key)
        button5 = Button(self.window, 610, 280, 130, 30, "generate key", self.generate_key)
        button6 = Button(self.window, 20, 360, 400, 30, "verify", self.verify)
        button7 = Button(self.window, 470, 360, 400, 30, "sign", self.sign)
        self.textbox = Textbox(self.window, 470, 320, 400, 30)
        self.buttons = [button1, button2, button3, button4, button5, button6, button7]

    def run(self):
        pygame.display.set_caption("File signature project")
        pygame.display.set_icon(self.icon)
        while True:
            self.window.fill((30, 30, 30))
            self.draw_buttons()
            self.textbox.draw()
            self.draw_verification()
            self.draw_signing()
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    quit()
                if event.type == pygame.MOUSEBUTTONDOWN:
                    self.click()
                if event.type == pygame.KEYDOWN:
                    self.type(event)
            pygame.display.update()

    def shorter_file_format(self, filepath):
        index = filepath.rfind('/')
        filename = filepath[index + 1:]
        return filename

    def draw_verification(self):
        title_box = pygame.Rect(20, 10, 400, 70)
        file_box = pygame.Rect(20, 80, 400, 70)
        key_box = pygame.Rect(20, 200, 400, 70)

        draw_text(self.window, title_box, "Verify a document", pygame.font.SysFont("Arial", 30))
        pygame.draw.rect(self.window, (70, 70, 70), file_box)
        pygame.draw.rect(self.window, (70, 70, 70), key_box)
        draw_text(self.window, file_box, self.shorter_file_format(self.verify_file) if self.verify_file else
        "No file selected", self.font)
        draw_text(self.window, key_box, self.shorter_file_format(self.certificate_path) if self.certificate else
        "No certificate selected", self.font)
        draw_text(self.window, pygame.Rect(20, 200, 100, 30), "Certificate:", self.font)
        draw_text(self.window, pygame.Rect(20, 400, 400, 30), self.verify_message, self.font, self.verify_message_color)

    def draw_signing(self):
        title_box = pygame.Rect(470, 10, 400, 70)
        file_box = pygame.Rect(470, 80, 400, 70)
        key_box = pygame.Rect(470, 200, 400, 70)

        draw_text(self.window, title_box, "Sign a document", pygame.font.SysFont("Arial", 30))
        pygame.draw.rect(self.window, (70, 70, 70), file_box)
        pygame.draw.rect(self.window, (70, 70, 70), key_box)
        draw_text(self.window, file_box, self.shorter_file_format(self.sign_file) if self.sign_file else
        "No file selected", self.font)
        draw_text(self.window, key_box, self.shorter_file_format(self.key_path) if self.sign_key else
        "No key selected", self.font)
        draw_text(self.window, pygame.Rect(470, 200, 100, 30), "Private key:", self.font)
        draw_text(self.window, pygame.Rect(470, 320, 70, 30), "Name:", self.font)
        draw_text(self.window, pygame.Rect(470, 400, 400, 30), self.sign_message, self.font, self.sign_message_color)

    def draw_buttons(self):
        for button in self.buttons:
            if button.mouse_over(pygame.mouse.get_pos()):
                button.hover = True
            else:
                button.hover = False
            button.draw()

    def click(self):
        for button in self.buttons:
            if button.mouse_over(pygame.mouse.get_pos()):
                button.func()
        if self.textbox.mouse_over(pygame.mouse.get_pos()):
            self.textbox.active = True
        else:
            self.textbox.active = False

    def type(self, event):
        if self.textbox.active:
            if event.key == pygame.K_BACKSPACE:
                self.textbox.text = self.textbox.text[:-1]
            elif (event.unicode.isalnum() or event.unicode == ' ' or event.unicode == '-') and len(
                    self.textbox.text) <= 30:
                self.textbox.text += event.unicode
            self.text_content = self.textbox.text

    def create_certificate(self, key):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.text_content)
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).sign(key, hashes.SHA256())
        with open("certificate.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def sign(self):
        if self.sign_key and self.text_content:
            key = load_pem_private_key(self.sign_key, password=None)
            if isinstance(key, rsa.RSAPrivateKey):
                self.create_certificate(key)
                content = bytes(open(self.sign_file, "r").read(), "utf-8")
                signature = key.sign(
                    content,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                file1 = open("signed_file.sgn", "wb")
                file1.write(bytes("-----BEGIN SIGNATURE-----\n", "utf-8"))
                file1.write(signature)
                file1.write(bytes("\n-----END SIGNATURE-----\n", "utf-8"))
                file1.write(content)
                file1.close()
                self.sign_message = "File signed."
                self.sign_message_color = (0, 200, 0)
            else:
                self.sign_message = "Choose a valid private key."
                self.sign_message_color = (200, 0, 0)

    def verify(self):
        if self.certificate:
            try:
                cert = x509.load_pem_x509_certificate(self.certificate)
                valid = True
                cert_usage = str(cert.extensions.get_extension_for_oid(oid=ExtensionOID.KEY_USAGE).value)
                if cert_usage != "<KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, " \
                                 "data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, " \
                                 "encipher_only=False, decipher_only=False)>":
                    valid = False  # We assume that key should only be used in digital signature
                key = cert.public_key()
                if isinstance(key, rsa.RSAPublicKey) and valid:
                    content = open(self.verify_file, "rb").read()
                    end_index = content.index(b'\n-----END SIGNATURE-----')
                    signature = content[26:end_index]
                    content = content[end_index + 25:]
                    try:
                        key.verify(
                            signature,
                            content,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                        name = cert.issuer.get_attributes_for_oid(oid=NameOID.COMMON_NAME).pop().value
                        self.verify_message = "Signature is valid. Signed by: " + str(name)
                        self.verify_message_color = (0, 200, 0)
                    except:
                        self.verify_message = "Signature is invalid."
                        self.verify_message_color = (200, 0, 0)
                else:
                    raise Exception
            except:
                self.verify_message = "Invalid certificate."
                self.verify_message_color = (200, 0, 0)

    def chosen_verification_file(self):
        self.verify_file = chosen_file((("sgn", "*.sgn"),))

    def chosen_signing_file(self):
        self.sign_file = chosen_file()

    def chosen_certificate(self):
        result = chosen_file((("pem", "*.pem"),))
        if result:
            self.certificate = open(result, "rb").read()
            self.certificate_path = result

    def chosen_signing_key(self):
        result = chosen_file((("pvk", "*.pvk"),))
        if result:
            self.sign_key = open(result, "rb").read()
            self.key_path = result

    def generate_key(self):
        key = rsa.generate_private_key(
            backend=default_backend(),
            public_exponent=65537,
            key_size=2048
        )
        private_key = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        file_out = open("generated_private_key.pvk", "wb")
        file_out.write(private_key)
        file_out.close()
        self.sign_message = "Key generated."
        self.sign_message_color = (0, 200, 0)
        #self.sign_key = private_key
