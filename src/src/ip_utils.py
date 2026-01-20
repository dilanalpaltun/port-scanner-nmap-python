import socket


def get_local_ip() -> str | None:
    try:
        host_name = socket.gethostname()
        local_ip = socket.gethostbyname(host_name)
        return local_ip
    except Exception as err:
        print("Could not detect local IP address:", err)
        return None
