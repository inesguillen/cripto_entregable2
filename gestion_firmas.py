
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


#generación, almacenamiento, firma y verificación de firmas usando claves asimétricas
#cada usuario tiene su clave pública y privada que se generan al iniciar sesión por primera vez
#la clave pública: para firmar documentos
#la clave privada: para verificar las firmas (si corresponde a la persona que lo ha subido)
#la privada se almacena cifrada con la clave derivada de la contraseña del usuario
#el motivo por el que la almacenamos es para mantener la misma siempre
# en teoría la pública no haría falta almacenarla porque se deduce a partir de la privada, pero es por si alguien externo
#quiere comprobar la firma, para que la pueda ver sin necesitar la privada.

class GestionFirmas:
    def __init__(self, usuario, clave_derivada): #recibe al usuario y la clave derivada en inicio de sesion
        #a partir de la contraseña del usuario
        self.usuario = usuario
        self.clave_derivada = clave_derivada
        self.public_key_file = f"{usuario}_public_key.pem" #aquí guardará la clave pública del usuario
        #formato PEM porque es lo que se usa en criptografía para las claves
        self.private_key_file = f"{usuario}_private_key.pem.enc" #se almacena la clave privada cifrada
        self.private_key = None #inicializa la clave privada porque al principio no existe
        #contiene la clave privada en memoria temporalmente, pero no se almacena directamente

        # Generar clave pública si no existe
        if not os.path.exists(self.public_key_file) or not os.path.exists(self.private_key_file):
            print("No se encontraron claves existentes. Generando nuevas claves...")
            self.generar_claves()

        print("Claves existentes encontradas. Cargando clave privada...")
        self.cargar_clave_privada(clave_derivada)


    def generar_claves(self):
        """
        Genera un par de claves (privada y pública), cifra la clave privada
        y guarda la clave pública en un archivo.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        ) #utiliza rsa para generar la clave privada del usuario con un tamaño de 2048 bits
        #rsa tiene métodos ya implementados para generar la clave privada y luego sacar la pública a partir de esa privada

        #-----------------------CLAVE PÚBLICA------serializar y generar
        # Serializar: convertir la clave a un formato que se pueda almacenar (PEM)
        public_key = private_key.public_key() #generar la pública a partir de la privada con un metodo de RSA

        with open(self.public_key_file, "wb") as public_file: #abrimos el archivo donde se guarda la clave pública del
            #usuario en forma de escritura binaria(wb)
            #public_file representa el archivo abierto en modo escitura binaria.

            #escribimos la clave pública en el archivo
            public_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )) #public_bytes() convierte la clave pública a un formato serializado
            #recibe como parámetros encoding que especifica el formato de codificación (PEM en Base 64)
            #y format que especifica el formato público de la clave
            #SubjectPublicKeyInfo: estñándar que define la estructura de la clave pública (contiene clave y tipo de algoritmo)

        #---------------------------CLAVE PRIVADA---- Serializar, cifrar y guardar

        with open(self.private_key_file, "wb") as private_file: #abrir el archivo de la clave privada del usuario en wb
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(self.clave_derivada)
            )#usamos la clave privada generada anteriormente para convertirla en bytes codificados en formato PEM
            #format: PKCS8(Public Key Cryptography Standards #8) define como se estructura la clave privada
            #incluye info del algortimo (RSA) usado y la clave privada
            #encryption_algorithm() especifica que se use el mejor algoritmo para cifrar la clave privada con la clave
            #derivada de la contraseña del usuario
            private_file.write(private_bytes) #guardar la clave privada cifrada en el archivo

        print(f"Claves generadas: {self.public_key_file} (pública), {self.private_key_file} (privada cifrada)")

        # cargamos la clave en self.private_key pero sin cifrar, RECORDEMOS QUE ES TEMPORAL
    def cargar_clave_privada(self, clave_derivada):
        if not os.path.exists(self.private_key_file):
            raise FileNotFoundError(f"No se encontró el archivo de clave privada: {self.private_key_file}")
        with open(self.private_key_file, "rb") as private_file:  # abre el archivo en lectura binaria
            self.private_key = serialization.load_pem_private_key(
                private_file.read(),
                password=clave_derivada,
            )  # serialization.load_pem_private_key() carga la clave privada desde el archivo PEM
            # recibe como parámetros la lectura del archivo
            # password: especifica la clave que se usará para descifrar
            if self.private_key is None:
                raise ValueError("No se pudo cargar la clave privada.")

    def firmar_archivo(self, ruta_archivo): #recibe la ruta del archivo que se va a firmar
        """
        Genera una firma digital para el archivo indicado y la guarda en un archivo .sig.
        """

        # Leer el contenido del archivo
        with open(ruta_archivo, "rb") as archivo: #lo abre en lectura binaria
            datos = archivo.read() #guarda su contenido binario en datos

        #generamos el hash del archivo para firmar con el hash ya que es más corto
        hash_archivo = hashes.Hash(hashes.SHA256()) #esto es para ir agregando datos en fragmentos del archivo grande
        #usa SHA-256 que genera un resumen de 256 bits
        hash_archivo.update(datos) #va agregando los datos en binario del archivo
        resumen = hash_archivo.finalize() #finaliza el proceso de generación del hash y guarda el reusltado final

        # Generar la firma del resumen
        #utilizamos PSS (Probabilistic Signature Scheme): esquema de firma digital diseñado para RSA (para padding)
        #se utiliza PSS para poder incluir el salt dentro del padding
        firma = self.private_key.sign( #utiliza el metodo sign de la clave privada almacenada en self.private_key
            resumen, #utiliza el resumen: versión condensada del archivo.
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), #genera el relleno con el algoritmo SHA-256
                salt_length=padding.PSS.MAX_LENGTH #salt aleatorio para la firma, de tamaño max permitido para la clave
            ),
            hashes.SHA256()
        )
        #por qué se usa padding en firma? porque la clave tiene 2048 bits mientras que el resumen solo tiene 256.
        #por que se usa salt? para que no se genere la misma firma si el archivo es el mismo

        # Guardar la firma en un archivo
        #QUE SE GUARDE CON EL NOMBRE EN VEZ DE CON LA RUTA
        archivo_firma = ruta_archivo + ".sig"
        with open(archivo_firma, "wb") as firma_file:
            firma_file.write(firma)

        print(f"Firma generada y guardada en: {archivo_firma}")

    def verificar_firma(self, ruta_archivo): #recibe el archivo para verificar su firma
        """
        Verifica la firma digital de un archivo utilizando la clave pública.
        """
        # Leer la clave pública, igual que se lee la privada
        with open(self.public_key_file, "rb") as public_file:
            public_key = serialization.load_pem_public_key(
                public_file.read(),
            ) #lo guarda en public_key

        # Leer el archivo y la firma
        #AQUI ESTARÍA BIEN QUE SEA CON EL NOMBRE DEL ARCHIVO EN VEZ DE UNA RUTA Y QUE SE CREE UN DIRECTORIO COMO EL
        # DE LOS DATOS DEL USUARIO PARA METER TODAS LAS FIRMAS EN LA MISMA CARPETA, CLAU HAZ TU MAGIA
        archivo_firma = ruta_archivo + ".sig"
        if not os.path.exists(archivo_firma):
            print("La firma no existe.")
            return False

        with open(ruta_archivo, "rb") as archivo, open(archivo_firma, "rb") as firma_file:
            #abrimos el archivo en lectura binaria para crear de nuevo su firma y comparar
            #abrimos también la firma en lectura binaria
            datos = archivo.read()
            firma = firma_file.read()

            # Generar el hash del archivo de nuevo, igual que antes
        hash_archivo = hashes.Hash(hashes.SHA256())
        hash_archivo.update(datos)
        resumen = hash_archivo.finalize()

        # Verificar la firma del hash con un metodo de rsa que recibe la firma original y el resumen con el padding
        # para crear de nuevo la firma y compararlas
        try:
            public_key.verify(
                firma,
                resumen,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Firma válida. El archivo no ha sido alterado.")
            return True
        except Exception:
            print("La firma no es válida o el archivo ha sido modificado.")
            return False






