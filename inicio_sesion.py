import os
import json
import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from gestion_archivos import GestionArchivos
from gestion_firmas import GestionFirmas

class InicioSesion:
    def __init__(self, usuario, password):
        self.__usuario = usuario
        self.__password = password

    def __str__(self):
        json_info = {
            "usuario": self.__usuario
        }
        return "SesiónIniciada:" + json_info.__str__()

    def cargar_salt(self):
        """
        Carga el archivo de salt o lo genera si no existe.
        """
        salt_file = f"{self.__usuario}_salt.bin"
        if not os.path.exists(salt_file):
            print(f"Salt no encontrado para el usuario {self.__usuario}. Generando uno nuevo.")
            salt = os.urandom(16)  # Genera un salt aleatorio de 16 bytes
            with open(salt_file, 'wb') as sf:
                sf.write(salt)
        else:
            with open(salt_file, 'rb') as sf:
                salt = sf.read()
        return salt

    def derivar_clave(self, password):
        # Cargar el salt para el usuario
        salt = self.cargar_salt()

        # Derivar la clave
        # usamos  PBKDF2 (Password-Based Key Derivation Function 2) para generar la clave a partir de la contraseña de cada usuario
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def iniciar_sesión(self) -> bool:
        sesion_iniciada = False #inicialización de la variable

        # abrir json de nuestros usuarios
        if os.path.exists('usuarios.json'): #verifica que existe
            with open('usuarios.json', 'r') as file: #abre en modo lectura
                datos = json.load(file) #carga los datos en un diccionario

        # Buscamos al usuario en nuestra base de datos. Lo haremos con una flag
        user_found = False
        correct_password = False
        for usuario, info in datos["usuarios"].items():
            if usuario == self.__usuario:
                user_found = True
                if bcrypt.checkpw(self.__password.encode(), info["password_hash"].encode()):
                    #comprueba que la contraseña ingresada sea la misma que el hash almacenado
                    #convierte tanto la contraseña almacenada, como el hash, en bytes para comparar
                    correct_password = True

        if not user_found:
            print("\nUsuario no registrado. Por favor, regístrese primero.\n")
        elif not correct_password:
            print("\nContraseña incorrecta\n")
        else:
            sesion_iniciada = True
            print("\nSesión iniciada correctamente\n")
            clave = self.derivar_clave(self.__password)


        return sesion_iniciada, clave