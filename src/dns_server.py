import binascii
from access_point import AccessPoint

try:
    from typing import Tuple
except ImportError:
    pass


def get_bits(src: int, mask: int, shift_back: int) -> int:
    return (src & mask) >> shift_back


def get_bit(src: int, pos: int) -> int:
    mask = 1 << pos
    return get_bits(src, mask, pos)


def set_bits(src: int, value: int, shift_back: int) -> int:
    return src | (value << shift_back)


def to_uint8(val: int) -> bytes:
    return val.to_bytes(1, "big")


def from_uint16(val: bytes) -> int:
    return int.from_bytes(bytes(val[:2]), "big", False)


def to_uint16(val: int) -> bytes:
    return val.to_bytes(2, "big")


def from_uint32(val: bytes) -> int:
    return int.from_bytes(bytes(val[:4]), "big", False)


def to_uint32(val: int) -> bytes:
    return val.to_bytes(4, "big")


class DnsHeader:
    BYTE_LENGTH = 12

    def __init__(self) -> None:
        self.ID = bytes(2)
        self.QR = 0
        self.OPCODE = 0
        self.AA = 0
        self.TC = 0
        self.RD = 0
        self.RA = 0
        self.RCODE = 0
        self.QUESTION_C = 0
        self.ANSWER_C = 0
        self.AUTH_C = 0
        self.ADD_C = 0

    def parse(self, header_bytes: bytes) -> None:
        self.ID = bytes(header_bytes[:2])
        self.QR = get_bit(header_bytes[2], 7)
        self.OPCODE = get_bits(header_bytes[2], 0b01111000, 3)
        self.AA = get_bit(header_bytes[2], 2)
        self.TC = get_bit(header_bytes[2], 1)
        self.RD = get_bit(header_bytes[2], 0)
        self.RA = get_bit(header_bytes[3], 7)
        self.RCODE = get_bits(header_bytes[3], 0b00001111, 0)
        self.QUESTION_C = from_uint16(header_bytes[4:6])
        self.ANSWER_C = from_uint16(header_bytes[6:8])
        self.AUTH_C = from_uint16(header_bytes[8:10])
        self.ADD_C = from_uint16(header_bytes[10:12])

    def serialize(self) -> bytes:
        flags_0 = 0
        flags_0 = set_bits(flags_0, self.QR, 7)
        flags_0 = set_bits(flags_0, self.OPCODE, 3)
        flags_0 = set_bits(flags_0, self.AA, 2)
        flags_0 = set_bits(flags_0, self.TC, 1)
        flags_0 = set_bits(flags_0, self.RD, 0)

        flags_1 = 0
        flags_1 = set_bits(flags_1, self.RA, 7)
        flags_1 = set_bits(flags_1, self.RCODE, 0)

        return b"".join([
            self.ID,
            to_uint8(flags_0),
            to_uint8(flags_1),
            to_uint16(self.QUESTION_C),
            to_uint16(self.ANSWER_C),
            to_uint16(self.AUTH_C),
            to_uint16(self.ADD_C)
        ])

    def __str__(self) -> str:
        str_rep = "DnsHeader\n"
        str_rep += "ID: " + str(binascii.hexlify(self.ID)) + "\n"
        str_rep += "QR: %d\n" % self.QR
        str_rep += "OPCODE: " + str(self.OPCODE) + "\n"
        str_rep += "AA: %d\n" % self.AA
        str_rep += "TC: %d\n" % self.TC
        str_rep += "RD: %d\n" % self.RD
        str_rep += "RA: %d\n" % self.RA
        str_rep += "RCODE: " + str(self.RCODE) + "\n"
        str_rep += "QUESTION_C: %d\n" % self.QUESTION_C
        str_rep += "ANSWER_C: %d\n" % self.ANSWER_C
        str_rep += "AUTH_C: %d\n" % self.AUTH_C
        str_rep += "ADD_C: %d\n" % self.ADD_C
        return str_rep


class DnsQuestion:
    def __init__(self) -> None:
        self.NAME = bytes(1)
        self.TYPE = 0
        self.CLASS = 0

    def _get_name_length(self, question_bytes: bytes) -> int:
        ptr = 0
        while question_bytes[ptr] != 0:
            ptr += question_bytes[ptr] + 1
        return ptr + 1

    def parse(self, question_bytes: bytes) -> None:
        name_length = self._get_name_length(question_bytes)
        self.NAME = bytes(question_bytes[:name_length])
        self.TYPE = from_uint16(question_bytes[name_length:name_length+2])
        self.CLASS = from_uint16(question_bytes[name_length+2:])

    def serialize(self) -> bytes:
        return b"".join([self.NAME, to_uint16(self.TYPE), to_uint16(self.CLASS)])

    def get_name(self) -> str:
        ptr = 0
        ret = []
        while self.NAME[ptr] != 0:
            len = self.NAME[ptr]
            ret.append(self.NAME[ptr+1:ptr+1+len].decode("ascii"))
            ptr += len + 1
        return ".".join(ret)

    def set_name(self, name: str) -> None:
        byte_parts = []
        name_parts = name.split(".")
        for name_part in name_parts:
            byte_parts.append(to_uint8(len(name_part)))
            byte_parts.append(name_part.encode("ascii"))
        byte_parts.append(bytes(1))
        self.NAME = b"".join(byte_parts)

    def __str__(self) -> str:
        str_rep = "DnsHeader\n"
        str_rep += "NAME: " + self.get_name() + "\n"
        str_rep += "TYPE: %d\n" % self.TYPE
        str_rep += "CLASS: %d\n" % self.CLASS
        return str_rep


class DnsAnswer:
    def __init__(self) -> None:
        self.NAME = bytes(1)
        self.TYPE = 0
        self.CLASS = 0
        self.TTL = 0
        self.DATA = bytes(1)

    def _get_name_length(self, question_bytes: bytes) -> int:
        ptr = 0
        while question_bytes[ptr] != 0:
            ptr += question_bytes[ptr] + 1
        return ptr + 1

    def parse(self, question_bytes: bytes) -> None:
        name_length = 2
        self.NAME = bytes(question_bytes[:name_length])
        self.TYPE = from_uint16(question_bytes[name_length:name_length+2])
        self.CLASS = from_uint16(question_bytes[name_length+2:name_length+4])
        self.TTL = from_uint32(question_bytes[name_length+4:name_length+6])
        data_length = from_uint16(question_bytes[name_length+6:name_length+8])
        self.DATA = bytes(
            question_bytes[name_length+8:name_length+8+data_length])

    def serialize(self) -> bytes:
        return b"".join([
            self.NAME,
            to_uint16(self.TYPE),
            to_uint16(self.CLASS),
            to_uint32(self.TTL),
            to_uint16(len(self.DATA)),
            self.DATA
        ])

    def get_name_offset(self) -> int:
        return self.NAME[1]

    def set_name_offset(self, offset: int) -> None:
        byte_parts = [
            to_uint8(0xc0),
            to_uint8(offset)
        ]
        self.NAME = b"".join(byte_parts)

    def get_data(self) -> str:
        str_parts = []
        for data_byte in self.DATA:
            str_parts.append(str(int(data_byte)))
        return ".".join(str_parts)

    def set_data(self, data: str) -> None:
        data_parts = data.split(".")
        byte_data_parts = []
        for data_part in data_parts:
            byte_data_parts.append(to_uint8(int(data_part)))
        self.DATA = b"".join(byte_data_parts)

    def __str__(self) -> str:
        str_rep = "DnsAnswer\n"
        str_rep += "NAME OFFSET: %d \n" % self.get_name_offset()
        str_rep += "TYPE: %d\n" % self.TYPE
        str_rep += "CLASS: %d\n" % self.CLASS
        str_rep += "TTL: %d\n" % self.TTL
        str_rep += "DATA: " + self.get_data() + "\n"
        return str_rep


class DnsServer:

    def __init__(self, ap: AccessPoint, debug: bool = False) -> None:
        self._ap = ap
        self._debug = debug
        # To avoid link collision with TCP
        self._link_id = ap.conn_limit + 1
        self._local_ip = ap.get_ip()

    def listen(self, port: int) -> None:
        self._ap.udp_listen(port, self._link_id)
        if self._debug:
            print("DNSSERVER -> Listening on port: ", port)

    def close(self) -> None:
        self._ap.udp_close(self._link_id)
        if self._debug:
            print("DNSSERVER -> Closed")

    def do_recieve_cycle(self) -> None:
        if self._debug:
            print("DNSSERVER -> Waiting for request...")

        message = self._ap.socket_receive()
        self.handle_message(message)

    def handle_message(self, message: Tuple[int, bytearray]) -> None:
        (link_id, data) = message
        if len(data) > 16 and link_id == self._link_id:
            header = DnsHeader()
            header.parse(data[:DnsHeader.BYTE_LENGTH])
            question = DnsQuestion()
            question.parse(data[DnsHeader.BYTE_LENGTH:])

            if self._debug:
                print('DNSSERVER -> Request header: ', header)
                print('DNSSERVER -> Request question: ', question)

            header.QR = 1
            header.RA = 1
            header.ANSWER_C = 1

            answer = DnsAnswer()
            answer.set_name_offset(DnsHeader.BYTE_LENGTH)
            answer.TYPE = question.TYPE
            answer.CLASS = question.CLASS
            answer.TTL = 300

            answer.set_data(self._local_ip)

            if self._debug:
                print('DNSSERVER -> Reponse header: ', header)
                print('DNSSERVER -> Response question: ', question)
                print('DNSSERVER -> Response answer: ', answer)

            dns_response = b"".join([
                header.serialize(),
                question.serialize(),
                answer.serialize()
            ])
            self._ap.socket_send(link_id, dns_response)
