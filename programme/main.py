# -*- coding: utf-8 -*-
import sys
from shutil import copy
from os import remove
from glob import glob
import time

import binascii
import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyotp

from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar,
                             QInputDialog, QMessageBox, QStyleFactory)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtWinExtras import QWinTaskbarButton


class Dialogue(QMessageBox):
    def __init__(self, master, titre, message, icone=QMessageBox.Information):
        super().__init__(master)
        self.setWindowTitle(titre)
        self.setIcon(icone)
        self.setText(message)


class Question(QMessageBox):
    def __init__(self, master, titre, message, icone=QMessageBox.Question):
        super().__init__(master)
        self.setWindowTitle(titre)
        self.setIcon(icone)
        self.setText(message)
        self.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        self.setDefaultButton(QMessageBox.Yes)

    def resultat(self):
        if self.result() == 0x4000:
            return True
        return False


class Fenetre(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Authentification")
        self.setWindowIcon(QIcon("icone.ico"))
        self.setAttribute(Qt.WA_DeleteOnClose)
        QApplication.setStyle(QStyleFactory.create("fusion"))
        QApplication.setPalette(QApplication.style().standardPalette())
        self.motdepasse = None

        # Gestion de l'icone dans la barre des tâches mais ça marche pas
        self.tbouton = QWinTaskbarButton(self)
        self.tbouton.setWindow(self.windowHandle())
        self.progression = self.tbouton.progress()
        self.progression.setRange(0, 100)

        self.frame_actions = QVBoxLayout(self)
        self.setLayout(self.frame_actions)

        self.bouton_connection = QPushButton("Se connecter", self)
        self.frame_actions.addWidget(self.bouton_connection)
        self.bouton_connection.clicked.connect(self.connection)

        self.bouton_nouveau = QPushButton("Nouveau compte", self)
        self.frame_actions.addWidget(self.bouton_nouveau)
        self.bouton_nouveau.clicked.connect(self.nouveau_compte)

        self.barre = QProgressBar()
        self.frame_actions.addWidget(self.barre)
        self.barre.setMaximum(0)
        self.barre.setFormat("")

        self.affichage = QLabel("", self)
        self.frame_actions.addWidget(self.affichage)

        self.mesure_temps = pyotp.TOTP("base32secret3232")

    def extraire_cle(self):
        entree, ok = QInputDialog.getText(self, "Connection", "Mot de passe :")
        if not ok:
            return
        mdp = entree.encode()
        if not self.verifier_mdp(mdp):
            Dialogue(self, "Erreur", "Mot de passe erronné", QMessageBox.Critical).exec()
            return
        self.motdepasse = hashlib.sha256(mdp).hexdigest()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"selsuper",
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(mdp))
        return key

    def verifier_mdp(self, mdp):
        if self.motdepasse is None:
            return True
        return self.motdepasse == hashlib.sha256(mdp).hexdigest()

    def connection(self):
        fichier, ok = QInputDialog.getItem(self, "Connection", "Nom d'utilisateur :", glob("*.txt"))
        if not ok:
            return
        if fichier not in glob("*.txt"):
            Dialogue(self, "Erreur", "Compte inconnu", QMessageBox.Critical).exec()
            return
        key = self.extraire_cle()
        if not key:
            return
        f = Fernet(key)

        with open(fichier, encoding="utf-8") as file:
            chiffre = file.read().encode()
        try:
            clair = f.decrypt(chiffre)
        except InvalidToken:
            Dialogue(self, "Erreur", "Mot de passe erroné", QMessageBox.Critical).exec()
            self.motdepasse = None
            return

        jetons = clair.split()
        for i in range(len(jetons)):
            jetons[i] = jetons[i].decode()
            jetons[i] = jetons[i].split("/")
            jetons[i][1] = pyotp.TOTP(jetons[i][1])
        self.jetons = jetons
        self.fichier = fichier

        self.bouton_connection.hide()
        self.bouton_nouveau.hide()
        self.frame_actions.removeWidget(self.bouton_connection)
        self.frame_actions.removeWidget(self.bouton_nouveau)
        boutons = QHBoxLayout(self)
        nouveau = QPushButton("Nouveau", self)
        nouveau.setStyleSheet("background-color: #C0EEC0")
        nouveau.clicked.connect(self.nouveau)
        boutons.addWidget(nouveau)
        supprimer = QPushButton("Supprimer", self)
        supprimer.setStyleSheet("background-color: #FFCCCB")
        supprimer.clicked.connect(self.supprimer)
        boutons.addWidget(supprimer)
        self.frame_actions.addLayout(boutons)
        quitter = QPushButton("Quitter", self)
        quitter.clicked.connect(self.close)
        self.frame_actions.addWidget(quitter)

        self.progression.setVisible(True)
        self.barre.setMaximum(100)
        self.barre_v = time.time()%30*100/30
        self.ancien = self.mesure_temps.now()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.rafraichir)
        self.timer.start(300)

    def nouveau_compte(self):
        nom, _ = QInputDialog.getText(self, "Création (1/3)", "Nom d'utilisateur :")
        if not nom: return
        if nom+".txt" in glob("*.txt"):
            Dialogue(self, "Erreur", "Le nom d'utilisateur existe déjà.", QMessageBox.Critical).exec()
            return
        mdp, _ = QInputDialog.getText(self, "Création (2/3)", "Mot de passe :")
        if not mdp: return
        mdp2, _ = QInputDialog.getText(self, "Création (3/3)", "Mot de passe (confirmation) :")
        if not mdp2: return
        if mdp != mdp2:
            Dialogue(self, "Erreur", "Les deux mots de passe ne correspondent pas.", QMessageBox.Critical).exec()
            return
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"selsuper",
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(mdp.encode()))
        fichier = nom+".txt"
        f = Fernet(key)
        with open(fichier, "w", encoding="utf-8") as file:
            file.write(f.encrypt(b"").decode())
        Dialogue(self, "Réussi", "Le compte a été créé !").exec()

    def nouveau(self):
        nom, _ = QInputDialog.getText(self, "Nouveau", "Nom :")
        if not nom: return
        for c in nom:
            if c not in tuple(chr(i) for i in list(range(48, 58)) + list(range(65, 91)) + list(range(97, 123))) + ("_", ",", "."):
                Dialogue(self, "Erreur", f"Le caractère \"{c}\" est interdit.", QMessageBox.Critical).exec()
                return
        cle, _ = QInputDialog.getText(self, "Nouveau", "Clé :")
        if not cle: return

        njeton = pyotp.TOTP(cle)
        try:
            print(njeton.now())
        except TypeError:
            Dialogue(self, "Erreur", "Clé invalide", QMessageBox.Critical).exec()
            return
        except binascii.Error:
            Dialogue(self, "Erreur", "Clé invalide", QMessageBox.Critical).exec()
            return
        key = self.extraire_cle()
        if not key:
            return
        f = Fernet(key)

        with open(self.fichier, encoding="utf-8") as file:
            chiffre = file.read().encode()
        clair = f.decrypt(chiffre)
        clair += b" " + nom.encode() + b"/" + cle.encode()

        copy(self.fichier, self.fichier+".sav")
        try:
            with open(self.fichier, "w", encoding="utf-8") as file:
                file.write(f.encrypt(clair).decode())
        except:
            dialogue = Question(self, "Erreur", "Une erreur est survenue lors de l'enregistrement. Restaurer le fichier pour éviter la corruption de données ?")
            if dialogue.resultat():
                remove(self.fichier)
                copy(self.fichier+".sav", self.fichier)
                remove(self.fichier+".sav")
                Dialogue(self, "Succès", "Oppération réussie !")
            else:
                remove(self.fichier+".sav")
            return
        remove(self.fichier+".sav")

        self.jetons.append([nom, njeton])

    def supprimer(self):
        supprimer, ok = QInputDialog.getItem(self, "Connection", "Clé à supprimer définitivement :", list(zip(*self.jetons))[0])
        if not ok or not supprimer in list(zip(*self.jetons))[0]:
            return
        nb = list(zip(*self.jetons))[0].index(supprimer)

        key = self.extraire_cle()
        if not key:
            return
        f = Fernet(key)

        with open(self.fichier, encoding="utf-8") as file:
            chiffre = file.read().encode()
        clair = f.decrypt(chiffre)

        jetons = clair.split()
        del jetons[nb]
        nclair = b" ".join(jetons)

        copy(self.fichier, self.fichier+".sav")
        try:
            with open(self.fichier, "w", encoding="utf-8") as file:
                file.write(f.encrypt(nclair).decode())
        except:
            dialogue = Question(self, "Erreur", "Une erreur est survenue lors de l'enregistrement. Restaurer le fichier pour éviter la corruption de données ?")
            if dialogue.resultat():
                remove(self.fichier)
                copy(self.fichier+".sav", self.fichier)
                remove(self.fichier+".sav")
                Dialogue(self, "Succès", "Oppération réussie !")
            else:
                remove(self.fichier+".sav")
            return
        remove(self.fichier+".sav")

        del self.jetons[nb]

    def rafraichir(self):
        if self.mesure_temps.now() != self.ancien:
            self.barre_v = 0.0
            self.ancien = self.mesure_temps.now()
        texte = []
        for jeton in self.jetons:
            texte.append(f"{jeton[0]} : {jeton[1].now()}")
        self.affichage.setText("\n".join(texte))
        self.barre_v += 1
        self.barre.setValue(round(self.barre_v))
        self.progression.setValue(round(self.barre_v))

    def closeEvent(self, event):
        try:
            self.timer.stop()
        except AttributeError:
            pass
        event.accept()


app = QApplication.instance() 
if not app:
    app = QApplication(sys.argv)

fen = Fenetre()
fen.show()

app.exec()
