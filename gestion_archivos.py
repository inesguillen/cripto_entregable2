import os
import json

from MAC import MAC
from Crypto.Cipher import AES


class GestionArchivos:
    def __init__(self, usuario, clave): #), key):
        self.__clave = clave
        self.__usuario = usuario

        self.__archivo_json = 'datos_archivos_usuarios.json'
        self.__ruta_usuario = os.path.join("archivos_usuarios", self.__usuario) #una carpeta para cada usuario

        #self.key = self.cargar_clave() #creamos una clave distinta para cada usuario

        self.mac = MAC(clave=self.__clave) #esa misma clave del usuario es la que se usa para el mac
        os.makedirs(self.__ruta_usuario, exist_ok=True)

    def cargar_datos_json(self): #similar a cargar datos de usuarios pero esta vez con los archivos pdf
        if os.path.exists(self.__archivo_json):
            with open(self.__archivo_json, 'r') as file:
                return json.load(file)
        else:
            return {"datos_archivos_usuarios": []}  # Estructura inicial si no existe

    def guardar_datos_json(self, data):
        with open(self.__archivo_json, 'w') as file:
            json.dump(data, file, indent=4)




    def ver_archivos(self):
        data = self.cargar_datos_json()
        archivos_usuario = None #variable para almacenar archivos del usuario

        # Recorremos cada usuario hasta encontrar el que corresponde al actual
        for usuario_data in data["datos_archivos_usuarios"]:
            if usuario_data["usuario"] == self.__usuario:
                archivos_usuario = usuario_data["archivos"] #asigna los archivos

        if archivos_usuario:
            print("\nArchivos guardados:")
            #te muestra todos los archivos de ese usuario
            contador = 1  # Inicializamos el contador
            for archivo in archivos_usuario:
                print(f"{contador}. {archivo}")
                contador += 1
        else:
            print("No tienes archivos guardados.")

    def subir_archivos(self):
        ruta_archivo = input("Indique la ruta completa del archivo PDF: ")

        if not os.path.exists(ruta_archivo) or not ruta_archivo.endswith('.pdf'): #busca ruta y que corresponda a .pdf
            print("No existe/No es un PDF")
            return

        data = self.cargar_datos_json()
        nombre_archivo = os.path.basename(ruta_archivo)
        #basename extrae el la parte final de una ruta, es para quedarse con el nombre y no la ruta completa

        ruta_destino = os.path.join(self.__ruta_usuario, nombre_archivo + '.encrypted')  # Agregamos '.encrypted' al nombre
        #join junta la ruta del archivo que se está subiendo(nombre_archivo), con la carpeta del usuario que a su vez
        # ha juntado la carpeta archivos_usuarios con el nombre del usuario.
        # Añade encrypted porque se usa al cifrar el archivo.

        # Generar MAC del archivo
        mac_generado = self.mac.generar_mac(self.__clave, ruta_archivo)
        print(f"MAC generado al subir: {mac_generado}")

        #cifra y lo guarda en ruta_destino
        self.cifrar_archivo(ruta_archivo, ruta_destino, self.__clave)

        usuario_data = None
        # Iteramos por cada usuario en la lista de datos de usuarios
        for user in data["datos_archivos_usuarios"]:
            if user["usuario"] == self.__usuario:
                usuario_data = user

        if usuario_data:
            if nombre_archivo in usuario_data["archivos"]: #si el archivo ya esta en la lista de archivos
                print("El archivo ya está guardado en la carpeta.") #archivo ya esta guardado
                return
            else:
                usuario_data["archivos"].append(nombre_archivo)
                usuario_data["macs"] = usuario_data.get("macs", {})
                usuario_data["macs"][nombre_archivo] = mac_generado
        else: #esto es en caso de que el usuario sea nuevo y aun no tenga nada subido
            data["datos_archivos_usuarios"].append({
                "usuario": self.__usuario,
                "archivos": [nombre_archivo],
                "macs": {nombre_archivo: mac_generado}
            })

        print(f"Archivo '{nombre_archivo}' guardado correctamente.")
        self.guardar_datos_json(data)

    def eliminar_archivo(self):
        pdf_eliminar = input("Nombre PDF a eliminar: ")
        ruta_pdf_eliminar = os.path.join(self.__ruta_usuario, pdf_eliminar + '.encrypted')
        #juntamos la ruta del archivo con la del usuario (encriptado porque lo tenemos guardado ya cifrado)

        if not os.path.exists(ruta_pdf_eliminar):
            print(ruta_pdf_eliminar + " no coincide con ningún archivo existente")
            return

        data = self.cargar_datos_json()
        usuario_data = None  # Inicializamos la variable para almacenar el usuario si se encuentra

        for user in data["datos_archivos_usuarios"]:
            if user["usuario"] == self.__usuario:
                usuario_data = user #si lo encuentra se actualiza user_data

        if usuario_data and pdf_eliminar in usuario_data["archivos"]:
            usuario_data["archivos"].remove(pdf_eliminar) #eliminamos pdf
            del usuario_data["macs"][pdf_eliminar] #eliminamos su mac
            os.remove(ruta_pdf_eliminar) #eliminamos la ruta el archivo cifrado
            print(f"Archivo '{pdf_eliminar}' eliminado con éxito.")
            self.guardar_datos_json(data) #se guarda la actualización en el JSONe
        else:
            print("El archivo no se encontró en los registros del usuario.")

    def abrir_archivo(self):
        pdf = input("Nombre PDF: ")
        ruta_pdf = os.path.join(self.__ruta_usuario, pdf + '.encrypted')

        if not os.path.exists(ruta_pdf):
            print("Archivo no encontrado.")
            return

        data = self.cargar_datos_json() #similar a la funcion anterior hasta aquí
        usuario_data = next((u for u in data["datos_archivos_usuarios"] if u["usuario"] == self.__usuario), None)
        #con next obtenemos el primer registro que coincida con el usuario actual en data[data_archivos_usuarios]
        #va recorriendo cada elemento u en la lista de los datos de usuarios para encontrar al usuario actual
        #si no encuentra ningun usuario entonces devuelve None.

        if usuario_data and pdf in usuario_data["macs"]:
            mac_guardado = usuario_data["macs"][pdf] #si lo encuentra, extrae el mac guardado para ese archivo
            ruta_temporal = os.path.join(self.__ruta_usuario, pdf + "_descriptado.pdf")
            #crea una ruta temporal para el archivo descifrado ya que, antes de intentar abrirlo tenemos que descifrarlo
            #o sino dará error ya que el mac no será el mismo(porque con el archivo cifrado sale otro mac)
            self.descifrar_archivo(ruta_pdf, ruta_temporal)  #descifra y lo guarda en la ruta temporal

            #verificar el mac del pdf que se quiere abrir con el que está almacenado
            if self.mac.verificar_mac(self.__clave, ruta_temporal, mac_guardado):
                print("El MAC es igual, el archivo no ha sido alterado.")
                os.startfile(ruta_temporal) #abrir el archivo
            else:
                print("No se puede abrir el archivo debido a un fallo en la verificación MAC.")
        else:
            print("No se encontró un MAC para el archivo.")



    def cifrar_archivo(self, ruta_archivo, ruta_salida, clave): #ruta del archivo y ruta donde se guarda el archivo cifrado

        # Cifrar el archivo PDF
        cipher_encrypt = AES.new(clave, AES.MODE_CFB) #crear objeto cifrador con AES en modo CFB
        #CFB= Cipher Feedback, cifrado de bloques. Permite cifrar y descifr sin tamaño fijo
        with open(ruta_archivo, 'rb') as inputfile, open(ruta_salida, 'wb') as outputfile:
            #abre ruta_archivo en lectura binaria, y ruta_salida en escritura binaria

            outputfile.write(cipher_encrypt.iv)  # Escribe el IV al principio del archivo de salida (antes de cifrar)
            # es el vector de inicialización que es aleatorio

            buffer_size = 64 * 1024  # Tamaño del buffer para leer en bloques
            buffer = inputfile.read(buffer_size) #se lee el primer bloque de ese tamaño y se guarda en buffer

            while len(buffer) > 0: #mientras que haya datos en el buffer, esto se repite
                ciphered_bytes = cipher_encrypt.encrypt(buffer) #cifra el bloque actual con el objeto creado al principio
                outputfile.write(ciphered_bytes) #escribe datos cifrados en el archivo de salida
                buffer = inputfile.read(buffer_size) #actualiza el buffer para el siguiente bloque

        print(f"Cifrado completado: {ruta_salida}")

    def descifrar_archivo(self, ruta_archivo_encriptado, ruta_salida): #recibe la ruta del archivo y la ruta para guardar

        # Desencriptar el archivo PDF
        with open(ruta_archivo_encriptado, 'rb') as inputfile: #abrir en lectura binaria
            iv = inputfile.read(16)  # Leer el IV, es necesario para que el descifrado coincida con cifrado (simétrico)
            cipher_decrypt = AES.new(self.__clave, AES.MODE_CFB, iv) #crea objeto descifrador
            # se le pasa la key del usuario, el modo CFB y el IV

            with open(ruta_salida, 'wb') as outputfile: #abre ruta_salida en escritura binaria
                buffer_size = 64 * 1024  # Tamaño del buffer para leer en bloques
                buffer = inputfile.read(buffer_size) #lee el primer bloque (sin contar IV pq ha quitado los 16b antes)

                while len(buffer) > 0: #mientras el buffer contenga datos, esto se repite
                    decrypted_bytes = cipher_decrypt.decrypt(buffer) #descifra bloque actual usando el objeto creado
                    outputfile.write(decrypted_bytes) #escribe los datos descifrados en el archivo de salida
                    buffer = inputfile.read(buffer_size) #actualiza el buffer para que vaya por el siguiente bloque

        print(f"Descifrado completado: {ruta_salida}")
