import os
import sys
import platform
import datetime
import tempfile
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog,
    QComboBox, QMessageBox, QGroupBox, QTabWidget, QSpinBox,
    QDialog, QGraphicsView, QGraphicsScene, QGraphicsRectItem,
    QGraphicsSimpleTextItem, QGraphicsItem, QCheckBox
)
from PyQt5.QtGui import QIcon, QPen, QBrush, QColor, QFont, QPainter
from PyQt5.QtCore import Qt
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers, fields, pkcs11
from pyhanko.stamp import TextStampStyle


def caminho_recurso(relativo):
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


def criar_assinante_personalizado(nome_pessoa, complemento=""):
    chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    atributos = [x509.NameAttribute(NameOID.COMMON_NAME, nome_pessoa)]
    if complemento.strip():
        atributos.append(x509.NameAttribute(NameOID.TITLE, complemento.strip()))

    sujeito = emissor = x509.Name(atributos)
    agora = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(sujeito)
        .issuer_name(emissor)
        .public_key(chave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(agora - datetime.timedelta(minutes=5))
        .not_valid_after(agora + datetime.timedelta(days=3650))
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False
        ), critical=True)
        .sign(chave, hashes.SHA256())
    )

    pfx_bytes = serialization.pkcs12.serialize_key_and_certificates(
        name=nome_pessoa.encode("utf-8"),
        key=chave,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.NoEncryption()
    )

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".p12")
    tmp.write(pfx_bytes)
    tmp.close()

    try:
        signer = signers.SimpleSigner.load_pkcs12(pfx_file=tmp.name, passphrase=None)
    finally:
        if os.path.exists(tmp.name):
            os.remove(tmp.name)

    return signer


class CaixaAssinaturaArrastavel(QGraphicsRectItem):
    def __init__(self, w, h, limite_w, limite_h):
        super().__init__(0, 0, w, h)
        self.limite_w = limite_w
        self.limite_h = limite_h
        self.setBrush(QBrush(QColor(0, 120, 215, 70)))
        self.setPen(QPen(QColor(0, 90, 180), 2, Qt.DashLine))
        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)
        self.setCursor(Qt.OpenHandCursor)

        texto = QGraphicsSimpleTextItem("Assinatura Digital\n(Arraste para posicionar)", self)
        texto.setBrush(QBrush(QColor(0, 50, 120)))
        fonte = QFont()
        fonte.setPointSize(8)
        fonte.setBold(True)
        texto.setFont(fonte)
        texto.setPos(8, 12)

    def mousePressEvent(self, event):
        self.setCursor(Qt.ClosedHandCursor)
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        self.setCursor(Qt.OpenHandCursor)
        super().mouseReleaseEvent(event)

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionChange:
            x = max(0.0, min(value.x(), self.limite_w - self.rect().width()))
            y = max(0.0, min(value.y(), self.limite_h - self.rect().height()))
            return value.__class__(x, y)
        return super().itemChange(change, value)


class DialogoPosicionarAssinatura(QDialog):
    def __init__(self, pdf_path, pagina_idx, box_atual=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Posicionar Assinatura - Página {pagina_idx + 1}")
        self.resize(620, 780)
        self.box_resultado = box_atual

        layout = QVBoxLayout(self)
        instrucao = QLabel("Arraste o quadro azul com o mouse até o local da folha onde deseja assinar:")
        instrucao.setStyleSheet("font-weight: bold;")
        layout.addWidget(instrucao)

        with open(pdf_path, "rb") as f:
            reader = PdfFileReader(f)
            pagina_obj = reader.root["/Pages"]["/Kids"][pagina_idx].get_object()
            mediabox = pagina_obj.get("/MediaBox") or [0, 0, 595, 842]
            self.pdf_w = float(mediabox[2]) - float(mediabox[0])
            self.pdf_h = float(mediabox[3]) - float(mediabox[1])

        self.escala_render = 1.05
        img_w = int(self.pdf_w * self.escala_render)
        img_h = int(self.pdf_h * self.escala_render)

        self.scene = QGraphicsScene(0, 0, img_w, img_h)
        # Desenha a folha branca com margens guia
        folha = self.scene.addRect(0, 0, img_w, img_h, QPen(QColor(150, 150, 150), 2), QBrush(QColor(255, 255, 255)))
        self.scene.addRect(40 * self.escala_render, 40 * self.escala_render,
                           img_w - 80 * self.escala_render, img_h - 80 * self.escala_render,
                           QPen(QColor(225, 225, 225), 1, Qt.DotLine))

        carimbo_w = 240 * self.escala_render
        carimbo_h = 60 * self.escala_render
        self.caixa = CaixaAssinaturaArrastavel(carimbo_w, carimbo_h, img_w, img_h)

        if box_atual:
            x1, y1, x2, y2 = box_atual
            pos_x = x1 * self.escala_render
            pos_y = (self.pdf_h - y2) * self.escala_render
            self.caixa.setPos(pos_x, pos_y)
        else:
            self.caixa.setPos((img_w - carimbo_w) / 2, img_h - carimbo_h - 60)

        self.scene.addItem(self.caixa)

        self.view = QGraphicsView(self.scene)
        self.view.setBackgroundBrush(QBrush(QColor(210, 214, 220)))
        self.view.setRenderHint(QPainter.Antialiasing)
        layout.addWidget(self.view)

        botoes = QHBoxLayout()
        btn_cancelar = QPushButton("Cancelar")
        btn_cancelar.clicked.connect(self.reject)
        btn_confirmar = QPushButton("Confirmar Posição")
        btn_confirmar.setStyleSheet("font-weight: bold; padding: 6px 16px;")
        btn_confirmar.clicked.connect(self.confirmar)
        botoes.addStretch()
        botoes.addWidget(btn_cancelar)
        botoes.addWidget(btn_confirmar)
        layout.addLayout(botoes)

    def confirmar(self):
        pos = self.caixa.pos()
        rect = self.caixa.rect()
        x1 = pos.x() / self.escala_render
        x2 = (pos.x() + rect.width()) / self.escala_render
        topo_tela = pos.y() / self.escala_render
        base_tela = (pos.y() + rect.height()) / self.escala_render

        y2 = self.pdf_h - topo_tela
        y1 = self.pdf_h - base_tela
        self.box_resultado = (round(x1, 1), round(y1, 1), round(x2, 1), round(y2, 1))
        self.accept()


class AssinadorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dedé Assinador Digital")
        self.setMinimumWidth(590)
        self.setAcceptDrops(True)
        self.box_personalizada = None

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
                self.carregar_pdf(caminho)
                break

    def carregar_pdf(self, caminho):
        self.txt_pdf.setText(caminho)
        self.box_personalizada = None
        self.lbl_status_pos.setText("Posição padrão (Inferior Direito) — clique ao lado para ajustar")

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

        # 2. Método de Assinatura
        grp_cert = QGroupBox("2. Método de Assinatura")
        lay_cert_main = QVBoxLayout(grp_cert)
        self.tabs_cert = QTabWidget()

        # Aba 0: A1
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

        # Aba 1: A3 (Token)
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

        # Aba 2: Personalizada (Sem Token)
        tab_pers = QWidget()
        lay_pers = QVBoxLayout(tab_pers)

        row_nome = QHBoxLayout()
        row_nome.addWidget(QLabel("Nome na Assinatura:"))
        self.txt_nome_pers = QLineEdit()
        self.txt_nome_pers.setPlaceholderText("Ex.: Artur Morais Silva")
        row_nome.addWidget(self.txt_nome_pers)

        row_comp = QHBoxLayout()
        row_comp.addWidget(QLabel("Cargo / Info (opcional):"))
        self.txt_comp_pers = QLineEdit()
        self.txt_comp_pers.setPlaceholderText("Ex.: Administrativo / CPF / Setor")
        row_comp.addWidget(self.txt_comp_pers)

        lay_pers.addLayout(row_nome)
        lay_pers.addLayout(row_comp)
        self.tabs_cert.addTab(tab_pers, "Personalizada (Sem Token)")

        lay_cert_main.addWidget(self.tabs_cert)
        layout.addWidget(grp_cert)

        # 3. Página e Posição Visual
        grp_pos = QGroupBox("3. Página e Local da Assinatura")
        lay_pos_main = QVBoxLayout(grp_pos)

        row_pag = QHBoxLayout()
        row_pag.addWidget(QLabel("Página:"))
        self.cmb_pagina = QComboBox()
        self.cmb_pagina.addItems(["Última página", "Primeira página", "Página específica"])
        self.cmb_pagina.currentIndexChanged.connect(lambda idx: self.spin_pagina.setEnabled(idx == 2))
        row_pag.addWidget(self.cmb_pagina)

        self.spin_pagina = QSpinBox()
        self.spin_pagina.setRange(1, 9999)
        self.spin_pagina.setEnabled(False)
        row_pag.addWidget(self.spin_pagina)

        self.chk_invisivel = QCheckBox("Assinatura Invisível (sem carimbo)")
        self.chk_invisivel.toggled.connect(self.alternar_invisivel)
        row_pag.addWidget(self.chk_invisivel)
        lay_pos_main.addLayout(row_pag)

        row_visual = QHBoxLayout()
        self.lbl_status_pos = QLabel("Posição padrão (Inferior Direito) — clique ao lado para ajustar")
        self.btn_posicionar = QPushButton("Escolher Local na Página...")
        self.btn_posicionar.clicked.connect(self.abrir_posicionador)
        row_visual.addWidget(self.lbl_status_pos, 1)
        row_visual.addWidget(self.btn_posicionar)
        lay_pos_main.addLayout(row_visual)

        layout.addWidget(grp_pos)

        # Botão Assinar
        self.btn_assinar = QPushButton("Assinar Documento")
        self.btn_assinar.setStyleSheet("font-weight: bold; padding: 10px; font-size: 14px;")
        self.btn_assinar.clicked.connect(self.assinar_documento)
        layout.addWidget(self.btn_assinar)

    def alternar_invisivel(self, invisivel):
        self.btn_posicionar.setEnabled(not invisivel)
        if invisivel:
            self.lbl_status_pos.setText("Assinatura criptográfica oculta (sem desenho na página)")
        elif self.box_personalizada:
            self.lbl_status_pos.setText(f"Posição definida manualmente: {self.box_personalizada}")
        else:
            self.lbl_status_pos.setText("Posição padrão (Inferior Direito) — clique ao lado para ajustar")

    def obter_indice_pagina(self, total_paginas):
        modo_pag = self.cmb_pagina.currentIndex()
        if modo_pag == 0:
            return total_paginas - 1
        elif modo_pag == 1:
            return 0
        return max(0, min(self.spin_pagina.value() - 1, total_paginas - 1))

    def abrir_posicionador(self):
        pdf_path = self.txt_pdf.text().strip()
        if not os.path.isfile(pdf_path):
            QMessageBox.warning(self, "Aviso", "Selecione primeiro um arquivo PDF válido.")
            return

        with open(pdf_path, "rb") as f:
            reader = PdfFileReader(f)
            total_paginas = len(reader.root["/Pages"]["/Kids"])

        pagina_idx = self.obter_indice_pagina(total_paginas)
        dlg = DialogoPosicionarAssinatura(pdf_path, pagina_idx, self.box_personalizada, self)
        if dlg.exec_() == QDialog.Accepted and dlg.box_resultado:
            self.box_personalizada = dlg.box_resultado
            self.lbl_status_pos.setText(
                f"Local definido na página {pagina_idx + 1} (X={int(self.box_personalizada[0])}, Y={int(self.box_personalizada[1])})"
            )

    def selecionar_pdf(self):
        caminho, _ = QFileDialog.getOpenFileName(self, "Selecionar PDF", "", "Arquivos PDF (*.pdf)")
        if caminho:
            self.carregar_pdf(caminho)

    def selecionar_pfx(self):
        caminho, _ = QFileDialog.getOpenFileName(self, "Selecionar Certificado A1", "", "Certificados (*.pfx *.p12)")
        if caminho:
            self.txt_pfx.setText(caminho)

    def selecionar_lib(self):
        caminho, _ = QFileDialog.getOpenFileName(self, "Selecionar Biblioteca PKCS#11", "/usr/lib", "Bibliotecas (*.so *.dll)")
        if caminho:
            self.txt_lib_pkcs11.setText(caminho)

    def executar_assinatura(self, pdf_path, out_path, signer, texto_extra=""):
        with open(pdf_path, "rb") as inf:
            reader = PdfFileReader(inf)
            total_paginas = len(reader.root["/Pages"]["/Kids"])
            pagina_alvo = self.obter_indice_pagina(total_paginas)

            if self.chk_invisivel.isChecked():
                box = None
            elif self.box_personalizada:
                box = self.box_personalizada
            else:
                box = (315, 40, 555, 100)

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
                linha_extra = f"\n{texto_extra}" if texto_extra.strip() else ""
                stamp = TextStampStyle(
                    stamp_text=f"Assinado digitalmente por:\n%(signer)s{linha_extra}\nData: %(ts)s"
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
        if aba_ativa == 2 and not self.txt_nome_pers.text().strip():
            QMessageBox.warning(self, "Aviso", "Digite o nome que deve aparecer na assinatura.")
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
            elif aba_ativa == 1:
                sessao = pkcs11.open_pkcs11_session(
                    lib_location=self.txt_lib_pkcs11.text().strip(),
                    user_pin=self.txt_pin_a3.text()
                )
                try:
                    signer = pkcs11.PKCS11Signer(pkcs11_session=sessao)
                    self.executar_assinatura(pdf_path, out_path, signer)
                finally:
                    sessao.close()
            else:
                nome = self.txt_nome_pers.text().strip()
                comp = self.txt_comp_pers.text().strip()
                signer = criar_assinante_personalizado(nome, comp)
                self.executar_assinatura(pdf_path, out_path, signer, texto_extra=comp)

            QMessageBox.information(self, "Sucesso", f"Documento assinado e salvo em:\n{out_path}")
        except Exception as e:
            QMessageBox.critical(self, "Erro ao Assinar", f"Falha na assinatura:\n{str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    janela = AssinadorApp()
    janela.show()
    sys.exit(app.exec_())