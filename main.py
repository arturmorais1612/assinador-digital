import os
import sys
import platform
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog,
    QComboBox, QMessageBox, QGroupBox, QTabWidget, QSpinBox
)
from PySide6.QtGui import QIcon
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers, fields, pkcs11
from pyhanko.stamp import TextStampStyle


def caminho_recurso(relativo):
    """Localiza a logo tanto no VS Code quanto empacotada no .exe/.deb/.rpm."""
    base = getattr(sys, "_MEIPASS", os.path.abspath("."))
    return os.path.join(base, relativo)


def detectar_biblioteca_pkcs11():
    sistema = platform.system()
    if sistema == "Linux":
        caminhos = [
            "/usr/lib/libaetpkss.so",
            "/usr/lib/libaetpkss.so.3",
            "/usr/lib/x86_64-linux-gnu/libaetpkss.so",
            "/usr/lib64/libaetpkss.so",
            "/usr/lib64/opensc-pkcs11.so",
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
            "/usr/lib/libeToken.so",
            "/usr/lib64/libeToken.so",
        ]
    else:
        caminhos = [
            r"C:\Windows\System32\aetpkss1.dll",
            r"C:\Windows\System32\eTPKCS11.dll",
            r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
        ]
    for caminho in caminhos:
        if os.path.isfile(caminho):
            return caminho
    return ""


class AssinadorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dedé Assinador Digital")
        self.setMinimumWidth(560)
        self.setAcceptDrops(True)

        icone = caminho_recurso("jujuba.webp")
        if os.path.isfile(icone):
            self.setWindowIcon(QIcon(icone))

        self.setup_ui()

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                if url.toLocalFile().lower().endswith(".pdf"):
                    event.acceptProposedAction()
                    return

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            caminho = url.toLocalFile()
            if caminho.lower().endswith(".pdf"):
                self.txt_pdf.setText(caminho)
                break

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # 1. Documento PDF
        grp_pdf = QGroupBox("1. Documento PDF (ou arraste o arquivo aqui)")
        lay_pdf = QHBoxLayout(grp_pdf)
        self.txt_pdf = QLineEdit()
        self.txt_pdf.setPlaceholderText("Selecione o arquivo PDF para assinar...")
        btn_pdf = QPushButton("Procurar PDF")
        btn_pdf.clicked.connect(self.selecionar_pdf)
        lay_pdf.addWidget(self.txt_pdf)
        lay_pdf.addWidget(btn_pdf)
        layout.addWidget(grp_pdf)

        # 2. Certificado Digital
        grp_cert = QGroupBox("2. Certificado Digital")
        lay_cert_main = QVBoxLayout(grp_cert)
        self.tabs_cert = QTabWidget()

        # Aba A1
        tab_a1 = QWidget()
        lay_a1 = QVBoxLayout(tab_a1)
        row_pfx = QHBoxLayout()
        self.txt_pfx = QLineEdit()
        self.txt_pfx.setPlaceholderText("Selecione o arquivo .pfx ou .p12...")
        btn_pfx = QPushButton("Procurar Certificado")
        btn_pfx.clicked.connect(self.selecionar_pfx)
        row_pfx.addWidget(self.txt_pfx)
        row_pfx.addWidget(btn_pfx)

        row_senha_a1 = QHBoxLayout()
        row_senha_a1.addWidget(QLabel("Senha do Arquivo:"))
        self.txt_senha_a1 = QLineEdit()
        self.txt_senha_a1.setEchoMode(QLineEdit.Password)
        self.txt_senha_a1.setPlaceholderText("Digite a senha...")
        row_senha_a1.addWidget(self.txt_senha_a1)

        lay_a1.addLayout(row_pfx)
        lay_a1.addLayout(row_senha_a1)
        self.tabs_cert.addTab(tab_a1, "Certificado Arquivo (A1)")

        # Aba A3
        tab_a3 = QWidget()
        lay_a3 = QVBoxLayout(tab_a3)
        row_lib = QHBoxLayout()
        self.txt_lib_pkcs11 = QLineEdit()
        self.txt_lib_pkcs11.setText(detectar_biblioteca_pkcs11())
        self.txt_lib_pkcs11.setPlaceholderText("Caminho do driver PKCS#11...")
        btn_lib = QPushButton("Driver (.so/.dll)")
        btn_lib.clicked.connect(self.selecionar_lib)
        row_lib.addWidget(self.txt_lib_pkcs11)
        row_lib.addWidget(btn_lib)

        row_pin = QHBoxLayout()
        row_pin.addWidget(QLabel("PIN do Token/Cartão:"))
        self.txt_pin_a3 = QLineEdit()
        self.txt_pin_a3.setEchoMode(QLineEdit.Password)
        self.txt_pin_a3.setPlaceholderText("Digite o PIN...")
        row_pin.addWidget(self.txt_pin_a3)

        lay_a3.addLayout(row_lib)
        lay_a3.addLayout(row_pin)
        self.tabs_cert.addTab(tab_a3, "Token / Smartcard (A3)")

        lay_cert_main.addWidget(self.tabs_cert)
        layout.addWidget(grp_cert)

        # 3. Página e Posição
        grp_pos = QGroupBox("3. Página e Posição do Carimbo")
        lay_pos = QHBoxLayout(grp_pos)

        lay_pos.addWidget(QLabel("Página:"))
        self.cmb_pagina = QComboBox()
        self.cmb_pagina.addItems(["Última página", "Primeira página", "Página específica"])
        self.cmb_pagina.currentIndexChanged.connect(lambda idx: self.spin_pagina.setEnabled(idx == 2))
        lay_pos.addWidget(self.cmb_pagina)

        self.spin_pagina = QSpinBox()
        self.spin_pagina.setRange(1, 9999)
        self.spin_pagina.setEnabled(False)
        lay_pos.addWidget(self.spin_pagina)

        lay_pos.addWidget(QLabel("Posição:"))
        self.cmb_posicao = QComboBox()
        self.cmb_posicao.addItems([
            "Inferior Esquerdo",
            "Inferior Direito",
            "Superior Direito",
            "Assinatura Invisível"
        ])
        lay_pos.addWidget(self.cmb_posicao)
        layout.addWidget(grp_pos)

        # Botão Assinar
        self.btn_assinar = QPushButton("Assinar Documento")
        self.btn_assinar.setStyleSheet("font-weight: bold; padding: 10px; font-size: 14px;")
        self.btn_assinar.clicked.connect(self.assinar_documento)
        layout.addWidget(self.btn_assinar)

    def selecionar_pdf(self):
        caminho, _ = QFileDialog.getOpenFileName(self, "Selecionar PDF", "", "Arquivos PDF (*.pdf)")
        if caminho:
            self.txt_pdf.setText(caminho)

    def selecionar_pfx(self):
        caminho, _ = QFileDialog.getOpenFileName(self, "Selecionar Certificado A1", "", "Certificados (*.pfx *.p12)")
        if caminho:
            self.txt_pfx.setText(caminho)

    def selecionar_lib(self):
        caminho, _ = QFileDialog.getOpenFileName(self, "Selecionar Biblioteca PKCS#11", "/usr/lib", "Bibliotecas (*.so *.dll)")
        if caminho:
            self.txt_lib_pkcs11.setText(caminho)

    def executar_assinatura(self, pdf_path, out_path, signer):
        with open(pdf_path, "rb") as inf:
            reader = PdfFileReader(inf)
            total_paginas = len(reader.root["/Pages"]["/Kids"])

            modo_pag = self.cmb_pagina.currentIndex()
            if modo_pag == 0:
                pagina_alvo = total_paginas - 1
            elif modo_pag == 1:
                pagina_alvo = 0
            else:
                pagina_alvo = max(0, min(self.spin_pagina.value() - 1, total_paginas - 1))

            opcao_pos = self.cmb_posicao.currentIndex()
            box = None
            if opcao_pos == 0:
                box = (40, 40, 280, 100)
            elif opcao_pos == 1:
                box = (315, 40, 555, 100)
            elif opcao_pos == 2:
                box = (315, 740, 555, 800)

            w = IncrementalPdfFileWriter(inf)
            nome_campo = f"Assinatura_{os.urandom(3).hex()}"
            fields.append_signature_field(
                w,
                sig_field_spec=fields.SigFieldSpec(
                    sig_field_name=nome_campo,
                    on_page=pagina_alvo,
                    box=box
                )
            )

            meta = signers.PdfSignatureMetadata(field_name=nome_campo)
            stamp = None
            if box is not None:
                stamp = TextStampStyle(
                    stamp_text="Assinado digitalmente por:\n%(signer)s\nData: %(ts)s"
                )

            pdf_signer = signers.PdfSigner(meta, signer=signer, stamp_style=stamp)
            with open(out_path, "wb") as outf:
                pdf_signer.sign_pdf(w, output=outf)

    def assinar_documento(self):
        pdf_path = self.txt_pdf.text().strip()
        if not os.path.isfile(pdf_path):
            QMessageBox.warning(self, "Aviso", "Selecione um arquivo PDF válido.")
            return

        aba_ativa = self.tabs_cert.currentIndex()
        if aba_ativa == 0 and not os.path.isfile(self.txt_pfx.text().strip()):
            QMessageBox.warning(self, "Aviso", "Selecione um certificado .pfx/.p12 válido.")
            return
        if aba_ativa == 1:
            if not os.path.isfile(self.txt_lib_pkcs11.text().strip()):
                QMessageBox.warning(self, "Aviso", "Driver PKCS#11 não encontrado.")
                return
            if not self.txt_pin_a3.text():
                QMessageBox.warning(self, "Aviso", "Digite o PIN do Token/Cartão.")
                return

        base, ext = os.path.splitext(pdf_path)
        out_path, _ = QFileDialog.getSaveFileName(
            self, "Salvar PDF Assinado", f"{base}_assinado{ext}", "Arquivos PDF (*.pdf)"
        )
        if not out_path:
            return

        try:
            if aba_ativa == 0:
                signer = signers.SimpleSigner.load_pkcs12(
                    pfx_file=self.txt_pfx.text().strip(),
                    passphrase=self.txt_senha_a1.text().encode("utf-8")
                )
                self.executar_assinatura(pdf_path, out_path, signer)
            else:
                sessao = pkcs11.open_pkcs11_session(
                    lib_location=self.txt_lib_pkcs11.text().strip(),
                    user_pin=self.txt_pin_a3.text()
                )
                try:
                    signer = pkcs11.PKCS11Signer(pkcs11_session=sessao)
                    self.executar_assinatura(pdf_path, out_path, signer)
                finally:
                    sessao.close()

            QMessageBox.information(self, "Sucesso", f"Documento assinado e salvo em:\n{out_path}")
        except Exception as e:
            QMessageBox.critical(self, "Erro ao Assinar", f"Falha na assinatura:\n{str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    janela = AssinadorApp()
    janela.show()
    sys.exit(app.exec())