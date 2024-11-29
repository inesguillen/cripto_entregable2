import os
import json
import re
import bcrypt

class RegistroUsuario:
    def __init__(self, usuario, password, password2, nombre, apellido1, apellido2, mail, centro_medico):
        self.__usuario = usuario
        self.__password = password
        self.__password2 = password2
        self.__nombre = nombre
        self.__apellido1 = apellido1
        self.__apellido2 = apellido2
        self.__mail = mail
        self.__centro_medico = centro_medico

    def __str__(self):
        json_info = {
            "usuario": self.__usuario,
            #"password": self.__password,
            "nombre": self.__nombre,
            "apellido1": self.__apellido1,
            "apellido2": self.__apellido2,
            "mail": self.__mail,
            "centro_medico": self.__centro_medico
        }
        return "RegistroUsuario:" + json_info.__str__() #lo que sse ve en pantalla

    def cargar_datos(self, usuarios):
        #carga los datos del usuario desde el JSON
        #recibe como parametro el archivo json de usuarios almacenados
        if os.path.exists(usuarios): #comprueba que existan los datos
            with open(usuarios, 'r') as file: #abre los datos en modo lectura(por eso esta la r)
                return json.load(file) #carga los datos a un diccionario
        else:
            return {"usuarios": {}} #si no existen datos, devuelve el diccionario vacio de usuarios

    def guardar_datos(self, usuarios, datos): #actualiza el contenido de un archivo en JSON con los datos proporcionados
        with open(usuarios, 'w') as file: #abre usuarios en modo escritura
            json.dump(datos, file, indent=4)
            #guarda el diccionario datos en el archivo JSON usuarios con identacion de 4 espacios

    def validar_datos(self) -> bool:
        # Validar contraseñas
        if self.__password != self.__password2:
            print("\nERROR: Las contraseñas no coinciden\n")
            return False

        # Cargar usuarios existentes
        datos = self.cargar_datos('usuarios.json')

        # Comprobar si el usuario ya existe
        for usuario, info in datos["usuarios"].items():
            if usuario == self.__usuario:
                print("\nERROR: Usuario ya registrado.\n")
                return False

        # Validar formato del correo
        if not self.validar_mail(self.__mail):
            print("\nERROR: El correo debe estar en formato usuario@dominio.com\n")
            return False

        # Comprobar si el correo ya existe
        for info in datos["usuarios"].values():
            if info["mail"] == self.__mail:

                print("\nERROR: Correo ya existente en la base de datos.\n")
                return False

        return True

    def registrar_usuario(self):
        if not self.validar_datos():
            return #si los datos no son validos, no hace nada

        #variable para almacenar el hash de la contraseña, toma la password y la convierte en bytes usando encode()
        #(bcrypt trabaja con bytes), genera un salt aleatorio para agregarlo a la password (es para que sea un hash
        #diferente a pesar de que dos usuarios tengan la misma contraseña).
        #hashpw crea el hash de la contraseña+salt y lo transforma de nuevo de bytes a str con .decode()
        password_hash = bcrypt.hashpw(self.__password.encode(), bcrypt.gensalt()).decode()
        datos = self.cargar_datos('usuarios.json')
        if "usuarios" not in datos:
            datos["usuarios"] = {}

        if self.__usuario in datos["usuarios"]:
            raise ValueError("El usuario ya está registrado, por favor inicie sesión")
            return #para salir

        nuevo_usuario = {
            "password_hash": password_hash,
            "nombre": self.__nombre,
            "apellido1": self.__apellido1,
            "apellido2": self.__apellido2,
            "mail": self.__mail,
            "centro_medico": self.__centro_medico
        } #crea el usuario con el hash de la contraseña
        #agregamos el nuevo usuario al diccionario en usuarios
        datos["usuarios"][self.__usuario] = nuevo_usuario
        #guardamos los datos actualizados en usuarios.json
        self.guardar_datos('usuarios.json', datos)

        # LE CREAMOS UNA CARPETA AL NUEVO USUARIO
        self.crear_directorio_usuario()

        print("Registro exitoso.")
        print("Datos del nuevo usuario:", nuevo_usuario)

    @staticmethod
    def validar_mail(mail) -> bool:
        regex = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w+$' #regex que valida el correo en formato usuario@dominio.ext
        validation = re.match(regex, mail) is not None
        return validation #devuelve False si el formato no es válido

    def crear_directorio_usuario(self):
        carpeta_user = os.path.join("archivos_usuarios", self.__usuario)
        os.makedirs(carpeta_user, exist_ok=True)

        # Crear JSON para gestionar las carpetas de cada usuario
        file_json_archivos = self.cargar_datos('datos_archivos_usuarios.json')

        json_archivos_nuevo_usuario = {
            "usuario": self.__usuario,
            "directorio_madre": carpeta_user,
            "archivos": []
        }

        file_json_archivos["datos_archivos_usuarios"].append(json_archivos_nuevo_usuario)
        self.guardar_datos('datos_archivos_usuarios.json', file_json_archivos)