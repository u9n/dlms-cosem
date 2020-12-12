from typing import *
import attr

from dlms_cosem.protocol.ber import BER
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu
from dlms_cosem.protocol.xdlms.conformance import Conformance


@attr.s(auto_attribs=True)
class InitiateResponseApdu(AbstractXDlmsApdu):
    """
    InitiateResponse ::= SEQUENCE {
        negotiated-quality-of-service [0] IMPLICIT Integer8 OPTIONAL,
        negotiated-dlms-version-number  Unsigned8,
        negotiated-conformance  Conformance, -- Shall be encoded in BER
        server-max-receive-pdu-size   Unsigned16,
        vaa-name  ObjectName

    }
    When using LN referencing the value if vaa-name is always 0x0007
    """

    TAG: ClassVar[int] = 0x08

    object_map: ClassVar[List[Dict[str, Any]]] = [

        {
            "attr": "negotiated_quality_of_service",
            "encoding": "x-adr",
            "optional": False,
            "default": None,
            "class_ref": "int",
            "length": 1,
        },
        {
            "attr": "negotiated_dlms_version_number",
            "encoding": "x-adr",
            "optional": False,
            "default": None,
            "class_ref": "int",
            "length": 1,
        },
        {
            "attr": "negotiated_conformance",
            "encoding": "ber",
            "optional": False,
            "default": None,
            "class_ref": Conformance,
            "length": 7,
            "tag": b"\x5f\x1f",
        },
        # Might be 6 over HDLC because of compbility with old version.
        {
            "attr": "server_max_receive_pdu_size",
            "encoding": "x-adr",
            "optional": False,
            "default": None,
            "class_ref": "int",
            "length": 2,
        },

    ]

    negotiated_conformance: Conformance
    server_max_receive_pdu_size: int
    negotiated_dlms_version_number: int = attr.ib(default=6)  # Always 6
    negotiated_quality_of_service: int = attr.ib(default=0)  # not used in dlms.

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        # There is weird decoding here since it is mixed X-ADS and BER....
        if not source_bytes.endswith(b"\x00\x07"):
            raise ValueError("vaa-name in InitateResponse is not \x00\x07")
        data = bytearray(source_bytes)
        apdu_tag = data.pop(0)
        if apdu_tag != cls.TAG:
            raise ValueError(
                f"Data is not a InitiateResponse APDU, got apdu tag {apdu_tag}")
        object_dict = dict()

        for decoding_rule in InitiateResponseApdu.object_map:
            is_used = True
            is_default = False
            if decoding_rule["encoding"] == "x-adr":
                if decoding_rule["optional"]:
                    tag = data.pop(0)  # get the first byte in the array
                    if tag == 0x00:
                        # 0x00 indicates that the optinal element is not used.
                        is_used = False
                    elif tag == 0x01:
                        # 0x01 indicates that the optional elemnt is used.
                        is_used = True
                    else:
                        raise ValueError(
                            f"Not possible to byte: {tag} to be other than 0x00 or "
                            f"0x01 when optional is set.")
                if decoding_rule["default"] is not None:
                    tag = data.pop(0)  # get the first byte in the array
                    if tag == 0x00:
                        # 0x00 indicates that the default value is used.
                        is_default = True
                    elif tag == 0x01:
                        # 0x01 indicates that the default value is not used and
                        # we need to look for the real value.
                        is_default = False
                    else:
                        raise ValueError(
                            f"Not possible to byte: {tag} to be other than 0x00 or "
                            f"0x01 when default is set.")
                if is_default:
                    object_dict[decoding_rule["attr"]] = decoding_rule["default"]
                    continue
                if not is_used:
                    object_dict[decoding_rule["attr"]] = None
                    continue

                object_data = data[: decoding_rule["length"]]

            elif decoding_rule["encoding"] == "ber":
                tag, length, object_data = BER.decode(data[: decoding_rule["length"]],
                    tag_length=len(decoding_rule["tag"]), )

            else:
                raise ValueError(
                    f"No encoding handling for encoding {decoding_rule['encoding']}")
            data = data[decoding_rule["length"]:]

            object_instance: Any

            # TODO: this is not nice
            if decoding_rule["class_ref"] == "int":
                object_instance = int.from_bytes(object_data, "big")
            elif decoding_rule["class_ref"] == "bool":
                object_instance = bool(object_data)
            elif decoding_rule["class_ref"] == "str":
                object_instance = str(object_data)
            elif decoding_rule["class_ref"] == "bytes":
                object_instance = bytes(object_data)
            else:
                object_instance = decoding_rule["class_ref"].from_bytes(
                    bytes(object_data))
            object_dict[decoding_rule["attr"]] = object_instance

        return cls(**object_dict)


    def to_bytes(self) -> bytes:
        _bytes = bytearray()
        for decoding_rule in self.object_map:
            object_value = self.__getattribute__(decoding_rule["attr"])
            if decoding_rule["encoding"] == "x-adr":

                # is the object used?
                if object_value is None and decoding_rule["optional"] is True:
                    object_bytes = b"\x00"

                # is the object the default value?
                elif object_value == decoding_rule["default"]:
                    object_bytes = b"\x00"

                else:
                    if isinstance(object_value, int):
                        object_bytes = object_value.to_bytes(decoding_rule["length"],
                            "big")
                    elif isinstance(object_value, bytes):
                        object_bytes = object_value
                    elif isinstance(object_value, bool):
                        if object_value:
                            object_bytes = b"\x01"
                        else:
                            object_bytes = b"\x00"
                    elif isinstance(object_value, str):
                        object_bytes = object_value.encode()
                    else:
                        object_bytes = object_value.to_bytes()

                if object_value is not None and decoding_rule["optional"] is True:
                    # should add 0x01 infront of the data
                    object_bytes = b"\x01" + object_bytes

                _bytes.extend(object_bytes)

            elif decoding_rule["encoding"] == "ber":
                _bytes.extend(BER.encode(decoding_rule["tag"], object_value.to_bytes()))

        return b"\x08" + bytes(_bytes) + b"\x00\x07"

