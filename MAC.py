import hmac
import hashlib
import os

class MAC:
    def __init__(self, clave):
        self.clave = clave

    def generar_mac(self, clave, mensaje):  # recibe una clave y un mensaje para luego generar el MAC
        if os.path.isfile(mensaje):  # si es un archivo
            with open(mensaje, 'rb') as archivo: #abrir en lectura binaria
                mensaje = archivo.read()  # leer contenido del archivo
        elif isinstance(mensaje, str): #se podria quitar porque va a ser siempre un archivo pero lo dejo por si a caso
            mensaje = mensaje.encode()

        mac_objeto = hmac.new(clave, mensaje, hashlib.sha256)  # hashlib.sha256 se utiliza para indicar que queremos
        # crear el MAC usando SHA 256 como la funcion hash. Coge la clave y el mensaje y genera el MAC

        # Lo pasamos a hexadecimal
        mac = mac_objeto.hexdigest()
        print(f"MAC generado:{mac}")
        return mac  # devolvemos el mac para luego guardarlo

    def verificar_mac(self, clave, mensaje, mac):
        if os.path.isfile(mensaje):
            with open(mensaje, 'rb') as archivo:
                mensaje = archivo.read()
                #print(f"Contenido leído para verificar MAC: {mensaje}")
        elif isinstance(mensaje, str):
            mensaje = mensaje.encode()

        # se vuelve a generar el mac con lo mismo de antes
        mac_objeto_verificar = hmac.new(clave, mensaje, hashlib.sha256)

        # volvemos a pasarlo a hexadecimal para luego compararlo con el inicial
        mac_hexadecimal = mac_objeto_verificar.hexdigest()

        print(f"MAC almacenado: {mac}")
        print(f"MAC generado para verificación: {mac_hexadecimal}")  # Impresión del MAC generado para verificación

        if hmac.compare_digest(mac_hexadecimal, mac):
            #print("El MAC es igual, mensaje no alterado.")
            return True
        else:
            #print("El MAC no es igual, mensaje alterado.")
            return False



