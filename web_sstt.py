# coding=utf-8
#!/usr/bin/env python3

import socket
import selectors    #https://docs.python.org/3/library/selectors.html
import select
import types        # Para definir el tipo de datos data
import argparse     # Leer parametros de ejecución
import os           # Obtener ruta y extension
from datetime import datetime, timedelta # Fechas de los mensajes HTTP
import time         # Timeout conexión
import sys          # sys.exit
import re           # Analizador sintáctico
import logging      # Para imprimir logs


NOMBRE_DOMINIO = "clubdeajedrez7565.org"
EMAILS_VALIDOS = ["sebastian@" + NOMBRE_DOMINIO, "mikael@" + NOMBRE_DOMINIO]

BUFSIZE = 8192                          # Tamaño máximo del buffer que se puede utilizar
TIMEOUT_CONNECTION = 7 + 5 + 6 + 5 + 10 # Timeout para la conexión persistente
MAX_ACCESOS = 10
COOKIE_MAX_TIME = 2

# Extensiones admitidas (extension, name in HTTP)
filetypes = {"gif":"image/gif", "jpg":"image/jpg", "jpeg":"image/jpeg", "png":"image/png", "htm":"text/htm", 
             "html":"text/html", "css":"text/css", "js":"text/js"}

# Configuración de logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()


def enviar_mensaje(cs, data):
    """ Esta función envía datos (data) a través del socket cs
        Devuelve el número de bytes enviados.
    """
    try:
        """
        bData = cs.send(data.encode()) # Codificar data a binario antes de enviar
        return bData
        """
        total_sent = 0
        num_msg_sent = 0
        if isinstance(data, str):
            data = data.encode()  # Codificar data a binario antes de enviar
        while total_sent < len(data):
            sent = cs.send(data[total_sent:total_sent + BUFSIZE])
            if sent == 0:
                raise RuntimeError("Conexión cerrada inesperadamente")
            total_sent += sent
            num_msg_sent+=1
        logger.info("Mensajes enviados en la respuesta: {}".format(num_msg_sent))
        return total_sent
    except Exception as e:
        logger.error("Error enviando mensaje: {}".format(e))
        return 0


def recibir_mensaje(cs):
    """ Esta función recibe datos a través del socket cs
        Leemos la información que nos llega. recv() devuelve un string con los datos.
    """
    try:
        data = cs.recv(BUFSIZE)  # Leer hasta BUFSIZE bytes
        return data.decode()  # Decodificar a string
    except Exception as e:
        logger.error("Error recibiendo mensaje: {}".format(e))
        return None


def cerrar_conexion(cs):
    """ Esta función cierra una conexión activa.
    """
    try:
        cs.close()
        logger.info("Conexión cerrada correctamente.")
    except Exception as e:
        logger.error("Error cerrando la conexión: {}".format(e))


def process_cookies(headers,  cs):
    """ Esta función procesa la cookie cookie_counter
        1. Se analizan las cabeceras en headers para buscar la cabecera Cookie
        2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
        3. Si no se encuentra cookie_counter , se devuelve 1
        4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
        5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
    """
    cookie_value = 1  # Valor por defecto si no hay cookies
    for header in headers:
        if header.startswith("Cookie:"):
            cookies = header.split(":")[1].strip()
            match = re.search(r'cookie_counter_7565=(\d+)', cookies)
            if match:
                cookie_value = int(match.group(1))
                if cookie_value >= MAX_ACCESOS:
                    return MAX_ACCESOS
                else:
                    cookie_value += 1
    return cookie_value


def process_web_request(cs, webroot):
    """ Procesamiento principal de los mensajes recibidos.
        Típicamente se seguirá un procedimiento similar al siguiente (aunque el alumno puede modificarlo si lo desea)

        * Bucle para esperar hasta que lleguen datos en la red a través del socket cs con select()

            * Se comprueba si hay que cerrar la conexión por exceder TIMEOUT_CONNECTION segundos
              sin recibir ningún mensaje o hay datos. Se utiliza select.select

            * Si no es por timeout y hay datos en el socket cs.
                * Leer los datos con recv.
                * Analizar que la línea de solicitud y comprobar está bien formateada según HTTP 1.1
                    * Devuelve una lista con los atributos de las cabeceras.
                    * Comprobar si la versión de HTTP es 1.1
                    * Comprobar si es un método GET o POST. Si no devolver un error Error 405 "Method Not Allowed".
                    * Leer URL y eliminar parámetros si los hubiera
                    * Comprobar si el recurso solicitado es /, En ese caso el recurso es index.html
                    * Construir la ruta absoluta del recurso (webroot + recurso solicitado)
                    * Comprobar que el recurso (fichero) existe, si no devolver Error 404 "Not found"
                    * Analizar las cabeceras. Imprimir cada cabecera y su valor. Si la cabecera es Cookie comprobar
                      el valor de cookie_counter para ver si ha llegado a MAX_ACCESOS.
                      Si se ha llegado a MAX_ACCESOS devolver un Error "403 Forbidden"
                    * Obtener el tamaño del recurso en bytes.
                    * Extraer extensión para obtener el tipo de archivo. Necesario para la cabecera Content-Type
                    * Preparar respuesta con código 200. Construir una respuesta que incluya: la línea de respuesta y
                      las cabeceras Date, Server, Connection, Set-Cookie (para la cookie cookie_counter),
                      Content-Length y Content-Type.
                    * Leer y enviar el contenido del fichero a retornar en el cuerpo de la respuesta.
                    * Se abre el fichero en modo lectura y modo binario
                        * Se lee el fichero en bloques de BUFSIZE bytes (8KB)
                        * Cuando ya no hay más información para leer, se corta el bucle

            * Si es por timeout, se cierra el socket tras el período de persistencia.
                * NOTA: Si hay algún error, enviar una respuesta de error con una pequeña página HTML que informe del error.
    """
    try:
        while True:
            readable, _, _ = select.select([cs], [], [], TIMEOUT_CONNECTION)
            if not readable:
                logger.info("Timeout de conexión alcanzado.")
                cerrar_conexion(cs)
                break

            data = recibir_mensaje(cs)
            if not data:
                logger.info("Timeout de conexión alcanzado.")
                cerrar_conexion(cs)
                break

            request_lines = data.split("\r\n")
            method, url, version = request_lines[0].split(" ")

            if version != "HTTP/1.1":
                enviar_mensaje(cs, "HTTP/1.1 505 HTTP Version Not Supported\r\n\r\n")
                cerrar_conexion(cs)
                break
            #Comprobamos que el mét-odo esté comprendido en [GET, POST]
            #Sino: ERROR
            if method not in ["GET", "POST"]:
                enviar_mensaje(cs, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                cerrar_conexion(cs)
                break
            #Tratamiento del mét-odo POST
            if method == "POST":
                body = request_lines[-1]  # El cuerpo está en la última línea
                match = re.search(r'email=([^&]*)', body)
                email = match.group(1) if match else ""
                email = email.replace("+", " ").replace("%40", "@").strip() #URL Decode

                logger.info("Email recibido: '{}' -> {}".format(email, "Válido" if email in EMAILS_VALIDOS else "Inválido"))

                if email in EMAILS_VALIDOS:
                    response_body = "<html><body><h1>Email valido</h1></body></html>"
                    response_headers = [
                        "HTTP/1.1 200 OK",
                        "Date: {}".format(datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')),
                        "Server: {}".format(NOMBRE_DOMINIO),
                        "Content-Length: {}".format(len(response_body)),
                        "Content-Type: text/html",
                        "Connection: close",
                        "\r\n"
                    ]
                else:
                    response_body = "<html><body><h1>Email invalido</h1></body></html>"
                    response_headers = [
                        "HTTP/1.1 401 Unauthorized",
                        "Date: {}".format(datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')),
                        "Server: {}".format(NOMBRE_DOMINIO),
                        "Content-Length: {}".format(len(response_body)),
                        "Content-Type: text/html",
                        "Connection: close",
                        "\r\n"
                    ] 

                response = "\r\n".join(response_headers) + response_body
                enviar_mensaje(cs, response)
                cerrar_conexion(cs)
                break

            #Tratamiento del mét-odo GET: Si no es POST, es GET. Nos ahorranos la comprobación
            resource = "index.html" if url == "/" else url.lstrip("/")
            file_path = os.path.join(webroot, resource)
            logger.info("Recurso pedido: {}".format(resource))
            if not os.path.isfile(file_path):
                response_body = "<html><body><h1>404 Not Found</h1></body></html>"
                response_headers = [
                    "HTTP/1.1 404 Not Found",
                    "Date: {}".format(datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')),
                    "Server: {}".format(NOMBRE_DOMINIO),
                    "Content-Length: {}".format(len(response_body)),
                    "Content-Type: text/html",
                    "Connection: close"
                ]
                headerAndBody = [response_headers, response_body]
                response = "\r\n".join(headerAndBody) + "\r\n\r\n"
                enviar_mensaje(cs, response)
                logger.error("Recurso '{}' no encontrado".format(resource))
                cerrar_conexion(cs)
                break

            with open(file_path, "rb") as f:
                content = f.read()

            content_type = filetypes.get(resource.split(".")[-1], "application/octet-stream")
            response_headers = [
                "HTTP/1.1 200 OK",
                "Date: {}".format(datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')),
                "Server: {}".format(NOMBRE_DOMINIO), #Nombre del servidor
                "Content-Length: {}".format(len(content)),
                "Content-Type: {}".format(content_type),
                "Keep-Alive: timeout={}, max={}".format(TIMEOUT_CONNECTION, MAX_ACCESOS),
                "Connection: Keep-Alive",
                "\r\n"
            ]

            #Gestión de las cookies solo en el acceso
            if method == "GET" and resource == "index.html":
                cookie_value = process_cookies(request_lines, cs)
                if cookie_value >= MAX_ACCESOS:
                    response_body = "<html><body><h1>403 Forbidden</h1></body></html>"
                    response_headers = [
                        "HTTP/1.1 403 Forbidden",
                        "Date: {}".format(datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')),
                        "Server: {}".format(NOMBRE_DOMINIO),
                        "Content-Length: {}".format(len(response_body)),
                        "Content-Type: text/html",
                        "Connection: close"
                    ]
                    headerAndBody = [response_headers, response_body]
                    response = "\r\n".join(headerAndBody) + "\r\n\r\n"
                    enviar_mensaje(cs, response)
                    cerrar_conexion(cs)
                    break
                response_headers.insert(-1, "Set-Cookie: cookie_counter_7565={}; Path=/; Max-Age={}".format(cookie_value, COOKIE_MAX_TIME))

            response = "\r\n".join(response_headers).encode() + content # Convertir headers a bytes antes de concatenar
            enviar_mensaje(cs, response)
            """
            cs.sendall(response) #TODO: llamar a la función enviar_mensaje
            cerrar_conexion(cs)
            break
            """
    except Exception as e:
        response_body = "<html><body><h1>400 Bad Request</h1></body></html>"
        response_headers = [
            "HTTP/1.1 400 Bad Request",
            "Date: {}".format(datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')),
            "Server: {}".format(NOMBRE_DOMINIO),
            "Content-Length: {}".format(len(response_body)),
            "Content-Type: text/html",
            "Connection: close"
        ]
        headerAndBody = [response_headers, response_body]
        response = "\r\n".join(headerAndBody) + "\r\n\r\n"
        enviar_mensaje(cs, response)
        logger.error("Error procesando solicitud: {}".format(e))
        cerrar_conexion(cs)

def main():
    try:

        # Argument parser para obtener la ip y puerto de los parámetros de ejecución del programa. IP por defecto 0.0.0.0
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port", help="Puerto del servidor", type=int, required=True)
        parser.add_argument("-ip", "--host", help="Dirección IP del servidor o localhost", required=True)
        parser.add_argument("-wb", "--webroot", help="Directorio base desde donde se sirven los ficheros (p.ej. /home/user/mi_web)")
        parser.add_argument('--verbose', '-v', action='store_true', help='Incluir mensajes de depuración en la salida')
        args = parser.parse_args()


        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logger.info('Enabling server in address {} and port {}.'.format(args.host, args.port))

        logger.info("Serving files from {}".format(args.webroot))

        """ Funcionalidad a realizar
        * Crea un socket TCP (SOCK_STREAM)
        * Permite reusar la misma dirección previamente vinculada a otro proceso. Debe ir antes de sock.bind
        * Vinculamos el socket a una IP y puerto elegidos

        * Escucha conexiones entrantes

        * Bucle infinito para mantener el servidor activo indefinidamente
            - Aceptamos la conexión

            - Creamos un proceso hijo

            - Si es el proceso hijo se cierra el socket del padre y procesar la petición con process_web_request()

            - Si es el proceso padre cerrar el socket que gestiona el hijo.
        """
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((args.host, args.port))
        server_socket.listen()

        logger.info("Servidor escuchando en {}:{}".format(args.host, args.port))

        while True:
            client_socket, client_address = server_socket.accept()
            pid = os.fork()
            if pid == 0:
                server_socket.close()
                process_web_request(client_socket, args.webroot)
                sys.exit(0)
            else:
                client_socket.close()
    except KeyboardInterrupt:
        True

if __name__== "__main__":
    main()
