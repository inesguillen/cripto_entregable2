import os
import json
import bcrypt

class InicioSesion:
    def __init__(self, usuario, password):
        self.__usuario = usuario
        self.__password = password

    def __str__(self):
        json_info = {
            "usuario": self.__usuario
        }
        return "SesiónIniciada:" + json_info.__str__()

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

        return sesion_iniciada