import time
import board
import busio
from adafruit_espatcontrol.adafruit_espatcontrol import ESP_ATcontrol, OKError
from access_point import AccessPoint, ENCRYPTION_WPA2_PSK
from webserver import WebServer

# Get wifi details and more from a secrets.py file
try:
    from ap_secrets import secrets
except ImportError:
    print("All secret keys are kept in ap_secrets.py, please add them there!")
    raise

# Initialize UART connection to the ESP-01 WiFi Module.
RX = board.GP17
TX = board.GP16
# Use large buffer as we're not using hardware flow control.
uart = busio.UART(TX, RX, receiver_buffer_size=2048)

esp = ESP_ATcontrol(uart, 115200, debug=True)

print("Resetting ESP module")
esp.soft_reset()

ap = AccessPoint(esp)
server = None

running = True
while running:
    try:
        if server == None:
            print("Configuring AP...")
            ap.configure_ap(secrets, 5, ENCRYPTION_WPA2_PSK, 1, False)
            print("IP address:", ap.get_ip())
            server = WebServer(ap, debug=True)
            server.register_static_handler("/", "www")
            server.listen(80)

        server.do_receive_cycle()

    except (ValueError, RuntimeError, OKError) as e:
        print("Failed, closing\n", e)
        running = False
