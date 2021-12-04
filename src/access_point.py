import time
import gc
from adafruit_espatcontrol.adafruit_espatcontrol import ESP_ATcontrol

try:
    from typing import Tuple, Dict
except ImportError:
    pass

ENCRYPTION_OPEN = 0
ENCRYPTION_WPA_PSK = 1
ENCRYPTION_WPA2_PSK = 2
ENCRYPTION_WPA_WPA2_PSK = 3


class AccessPoint:

    MIN_CONN_LIMIT = 1
    MAX_CONN_LIMIT = 8

    SSID_PUBLIC = 0
    SSID_HIDDEN = 1

    def __init__(self, esp: ESP_ATcontrol) -> None:
        self._esp = esp

    def configure_ap(self, secrets: Dict[str, str], channel: int = 5, encryption: int = ENCRYPTION_OPEN, conn_limit: int = 1, hidden: bool = False) -> None:
        if "ssid" not in secrets:
            raise RuntimeError("missing secret: ssid")
        if "password" not in secrets and encryption != ENCRYPTION_OPEN:
            raise RuntimeError("missing secret: password")
        if encryption not in [ENCRYPTION_OPEN, ENCRYPTION_WPA_PSK, ENCRYPTION_WPA2_PSK, ENCRYPTION_WPA_WPA2_PSK]:
            raise RuntimeError("invalid encryption")
        if conn_limit < self.MIN_CONN_LIMIT or conn_limit > self.MAX_CONN_LIMIT:
            raise RuntimeError("conn_limit out of bounds")

        self._esp.mode = self._esp.MODE_SOFTAPSTATION

        hidden_arg = self.SSID_HIDDEN if hidden else self.SSID_PUBLIC
        cmd = 'AT+CWSAP_CUR="'+secrets["ssid"]+'","'+secrets["password"]+'"'
        cmd += ',%d' % channel
        cmd += ',%d' % encryption
        cmd += ',%d' % conn_limit
        cmd += ',%d' % hidden_arg

        self._esp.at_response(cmd)
        self._esp.at_response("AT+CIPMUX=1")

    def get_ip(self) -> bytearray:
        return self._esp.at_response("AT+CIFSR").strip(b"\r\n")

    def start_listen(self, port: int = 80) -> None:
        self._port = port
        # AT+CIPDINFO = 1
        cmd = 'AT+CIPSERVER=1,%d' % port
        self._esp.at_response(cmd)

    def stop_listen(self) -> None:
        cmd = 'AT+CIPSERVER=0,%d' % self._port
        self._esp.at_response(cmd)

    def socket_receive(self, timeout: int = 5) -> Tuple[int, bytearray]:
        # pylint: disable=too-many-nested-blocks, too-many-branches
        """Check for incoming data over the open socket, returns bytes"""
        link_id = -1
        incoming_bytes = None
        bundle = []
        toread = 0
        gc.collect()
        i = 0  # index into our internal packet
        stamp = time.monotonic()
        ipd_start = b"+IPD,"
        while (time.monotonic() - stamp) < timeout:
            if self._esp._uart.in_waiting:
                stamp = time.monotonic()  # reset timestamp when there's data!
                if not incoming_bytes:
                    self._esp.hw_flow(False)  # stop the flow
                    # read one byte at a time
                    self._esp._ipdpacket[i] = self._esp._uart.read(1)[0]
                    if chr(self._esp._ipdpacket[0]) != "+":
                        i = 0  # keep goin' till we start with +
                        continue
                    i += 1
                    # look for the IPD message
                    if (ipd_start in self._esp._ipdpacket) and chr(
                        self._esp._ipdpacket[i - 1]
                    ) == ":":
                        try:
                            ipd = str(
                                self._esp._ipdpacket[5: i - 1], "utf-8")
                            meta = ipd.split(',')
                            link_id = int(meta[0])
                            incoming_bytes = int(meta[1])
                            if self._esp._debug:
                                print("Receiving:", incoming_bytes)
                        except ValueError as err:
                            raise RuntimeError(
                                "Parsing error during receive", ipd
                            ) from err
                        i = 0  # reset the input buffer now that we know the size
                    elif i > 20:
                        i = 0  # Hmm we somehow didnt get a proper +IPD packet? start over

                else:
                    self._esp.hw_flow(False)  # stop the flow
                    # read as much as we can!
                    toread = min(incoming_bytes - i,
                                 self._esp._uart.in_waiting)
                    # print("i ", i, "to read:", toread)
                    self._esp._ipdpacket[i: i +
                                         toread] = self._esp._uart.read(toread)
                    i += toread
                    if i == incoming_bytes:
                        # print(self._ipdpacket[0:i])
                        gc.collect()
                        bundle.append(self._esp._ipdpacket[0:i])
                        gc.collect()
                        i = incoming_bytes = 0
                        # We've received all the data. Don't wait until timeout.
                        break
            else:  # no data waiting
                self._esp.hw_flow(True)  # start the floooow
        totalsize = sum([len(x) for x in bundle])
        ret = bytearray(totalsize)
        i = 0
        for x in bundle:
            for char in x:
                ret[i] = char
                i += 1
        for x in bundle:
            del x
        gc.collect()
        return (link_id, ret)

    def socket_send(self, link_id: int, buffer: bytes, timeout: int = 1) -> bool:
        """Send data over the already-opened socket, buffer must be bytes"""
        cmd = "AT+CIPSEND=%d" % link_id
        cmd += ",%d" % len(buffer)
        self._esp.at_response(cmd, timeout=5, retries=1)
        prompt = b""
        stamp = time.monotonic()
        while (time.monotonic() - stamp) < timeout:
            if self._esp._uart.in_waiting:
                prompt += self._esp._uart.read(1)
                self._esp.hw_flow(False)
                # print(prompt)
                if prompt[-1:] == b">":
                    break
            else:
                self._esp.hw_flow(True)
        if not prompt or (prompt[-1:] != b">"):
            raise RuntimeError("Didn't get data prompt for sending")
        self._esp._uart.reset_input_buffer()
        self._esp._uart.write(buffer)
        stamp = time.monotonic()
        response = b""
        while (time.monotonic() - stamp) < timeout:
            if self._esp._uart.in_waiting:
                response += self._esp._uart.read(self._esp._uart.in_waiting)
                if response[-9:] == b"SEND OK\r\n":
                    break
                if response[-7:] == b"ERROR\r\n":
                    break
        if self._esp._debug:
            print("<---", response)
        # Get newlines off front and back, then split into lines
        return True

    def socket_disconnect(self, link_id: int) -> None:
        cmd = "AT+CIPCLOSE=%d" % link_id
        self._esp.at_response(cmd, retries=1)

    def udp_listen(self, port: int) -> None:
        cmd = 'AT+CIPSTART=0,"UDP","0.0.0.0",%d' % port
        cmd += ',%d,2' % port
        self._esp.at_response(cmd, retries=1)

    def udp_close(self) -> None:
        cmd = "AT+CIPCLOSE=0"
        self._esp.at_response(cmd, retries=1)
