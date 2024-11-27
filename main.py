import os
import json
from registro import RegistroUsuario
from inicio_sesion import InicioSesion
from gestion_archivos import GestionArchivos

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
        sesion_iniciada = iniciar_sesion.iniciar_sesión()

        while sesion_iniciada:
            # abro json
            if os.path.exists('usuarios.json'):
                with open('usuarios.json', 'r') as file:
                    datos = json.load(file)

            print("\nBienvenido, " + usuario)
            print("\nPor favor, seleccione una opción:")
            print("1. Ver archivos PDF\n2. Abrir archivo\n3. Subir archivo PDF\n4. Eliminar archivo PDF PDF\n5.Salir")
            select = int(input("Selección: "))

            gestion_archivos = GestionArchivos(usuario)

            if select == 1:
                #ver_archivos = GestionArchivos(usuario).ver_archivos()
                gestion_archivos.ver_archivos()

            elif select == 2:
                #abrir_archivo = GestionArchivos(usuario).abrir_archivo()
                gestion_archivos.abrir_archivo()

            elif select == 3:
                #subir_archivos = GestionArchivos(usuario).subir_archivos()
                gestion_archivos.subir_archivos()

            elif select == 4:
                #eliminar_archivo = GestionArchivos(usuario).eliminar_archivo()
                gestion_archivos.eliminar_archivo()

            elif select == 5:
                print("\nCerrando sesion...\n")
                sesion_iniciada = False

            else:
                print("Opción no válida")

    else:
        print("Opción no válida")