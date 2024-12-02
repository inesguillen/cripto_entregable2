import os
import json
from registro import RegistroUsuario
from inicio_sesion import InicioSesion
from gestion_archivos import GestionArchivos
from gestion_firmas import GestionFirmas

def menu():
    print("Bienvenido a su gestor de archivos médicos. Por favor, seleccione una opción:")
    print("1. Iniciar Sesión\n2. Registro\n3. Salir")

salir = False

while not salir:
    menu()
    opcion = int(input("\nOpción: "))
    if opcion == 3:
        print("Saliendo...")
        salir = True

    elif opcion == 2:
        print("Regístrese en la base de datos")
        usuario = input("Nombre de usuario: ")
        password = input("Contraseña: ")
        password2 = input("Repita contraseña: ")
        nombre = input("Nombre: ")
        apellido1 = input("Primer apellido: ")
        apellido2 = input("Segundo apellido (opcional): ")
        mail = input("Correo electrónico: ")
        centro_medico = input("Centro médico: ")

        nuevo_usuario = RegistroUsuario(usuario, password, password2, nombre, apellido1, apellido2, mail, centro_medico)
        nuevo_usuario.registrar_usuario()
        #print(nuevo_usuario)

    elif opcion == 1:
        usuario = input("Nombre de usuario: ")
        password = input("Contraseña: ")

        # METER POSIBLE OPCIÓN DE OLVIDO DE CONTRASEÑA

        iniciar_sesion = InicioSesion(usuario, password)

        # a parte de checkear los datos, devuelve un bool que es True si se inicó sesión correctamente
        sesion_iniciada, clave = iniciar_sesion.iniciar_sesión()

        if sesion_iniciada:
            gestion_archivos = GestionArchivos(usuario, clave)
            gestion_firma = GestionFirmas(usuario, clave)

            if gestion_firma.private_key:
                print("Clave privada cargada correctamente.")
            else:
                print("Error: La clave privada no se cargó.")

            while True:
                print("\nBienvenido, " + usuario)
                print("\nPor favor, seleccione una opción:")
                print("1. Ver archivos PDF\n2. Abrir archivo\n3. Subir archivo PDF\n4. Eliminar archivo PDF\n5. Firmar "
                      "archivo.\n6.Verificar firma de un archivo.\n7.Salir.")
                select = int(input("Selección: "))

                if select == 1:
                    gestion_archivos.ver_archivos()
                elif select == 2:
                    gestion_archivos.abrir_archivo()
                elif select == 3:
                    gestion_archivos.subir_archivos()
                elif select == 4:
                    gestion_archivos.eliminar_archivo()
                elif select == 5:
                    archivo = input("Indique el archivo que desea firmar (incluyendo la ruta): ")
                    gestion_firma.firmar_archivo(archivo)
                elif select == 6:
                    archivo = input("Indique el archivo que desea verificar (incluyendo la ruta): ")
                    gestion_firma.verificar_firma(archivo)
                elif select == 7:
                    print("\nCerrando sesión...\n")
                    break
                else:
                    print("Opción no válida.")


    else:
        print("Opción no válida")