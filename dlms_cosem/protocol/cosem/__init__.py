from enum import IntEnum, unique

import attr
from typing import *
import abc
from dlms_cosem.protocol.cosem.obis import Obis


class AbstractCosemInterface(abc.ABC):
    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        raise NotImplementedError()


@attr.s(auto_attribs=True)
class BaseCosemInterface(AbstractCosemInterface):

    INTERFACE_CLASS_ID: ClassVar[int] = 0

    def to_bytes(self) -> bytes:
        return self.INTERFACE_CLASS_ID.to_bytes(2, "big")


class Data(BaseCosemInterface):
    INTERFACE_CLASS_ID = 1


class Register(BaseCosemInterface):
    INTERFACE_CLASS_ID = 7

@unique
class CosemInterface(IntEnum):

    # Parameters and measurement data.
    DATA = 1
    REGISTER = 3
    EXTENDED_REGISTER = 4
    DEMAND_REGISTER = 5
    REGISTER_ACTIVATION = 6
    PROFILE_GENERIC = 7
    UTILITY_TABLES = 26
    REGISTER_TABLE = 61
    COMPACT_DATA = 62
    STATUS_MAPPING = 63

    # Access control and management
    ASSOCIATION_SN = 12
    ASSOCIATION_LN = 15
    SAP_ASSIGNMENT = 17
    IMAGE_TRANSFER = 18
    SECURITY_SETUP = 64
    PUSH = 40
    COSEM_DATA_PROTECTION = 30
    FUNCTION_CONTROL = 122
    ARRAY_MANAGER = 123
    COMMUNICATION_PORT_PROTECTION = 124

    # Time and event bound control
    CLOCK = 8
    SCRIPT_TABLE = 9
    SCHEDULE = 10
    SPECIAL_DAYS_TABLE = 11
    ACTIVITY_CALENDAR = 20
    REGISTER_MONITOR = 21
    SINGLE_ACTION_SCHEDULE = 22
    DISCONNECT_CONTROL = 70
    LIMITER = 71
    PARAMETER_MONITOR = 65
    SENSOR_MANAGER = 67
    ARBITRATOR = 68

    # Payment related interfaces
    ACCOUNT = 111
    CREDIT = 112
    CHARGE = 113
    TOKEN_GATEWAY = 115

    # Data exchange over local ports and modems
    IEC_LOCAL_PORT_SETUP = 19
    IEC_HDLC_SETUP = 23
    IEC_TWISTED_PAIR_SETUP = 24
    MODEM_CONFIGURATION = 27
    AUTO_ANSWER = 28
    AUTO_CONNECT = 29
    GPRS_MODEM_SETUP = 45
    GSM_DIAGNOSTICS = 47
    LTE_MONITORING = 151

    # Data exchange over M-Bus
    MBUS_SLAVE_PORT_SETUP = 25
    MBUS_CLIENT = 72
    MBUS_WIRELESS_MODE_Q_CHANNEL = 73
    MBUS_MASTER_PORT_SETUP = 74
    MBUS_PORT_SETUP_DLMS_COSEM_SERVER = 76
    MBUS_DIAGNOSTICS = 77

    # Data exchange over Internet
    TCP_UDP_SETUP = 41
    IPV4_SETUP = 42
    IPV6_SETUP = 48
    MAC_ADDRESS_SETUP = 43
    PPP_SETUP = 44
    SMTP_SETUP = 46
    NTP_SETUP = 100

    # Data exchange using S-FSK PLC
    S_FSK_PHY_MAC_SETUP = 50
    S_FSK_ACTIVE_INITIATOR = 51
    S_FSK_MAC_SYNCHRONISATION_TIMEOUTS = 52
    S_FSK_MAC_COUNTERS = 53
    S_FSK_IEC_61334_4_32_LLC_SETUP = 55
    S_FSK_REPORTING_SYSTEM_LIST = 56

    # LLC layers for IEC 8802-2
    IEC_8802_2_LLC_TYPE_1_SETUP = 57
    IEC_8802_2_LLC_TYPE_2_SETUP = 58
    IEC_8802_2_LLC_TYPE_3_SETUP = 59

    # Narrowband OFDM PLC profile for PRIME networks
    PRIME_61344_4_32_LLC_SSCS_SETUP = 80
    PRIME_OFDM_PLC_PHYSICAL_LAYER_COUNTERS = 81
    PRIME_OFDM_PLC_MAC_SETUP = 82
    PRIME_OFDM_PLC_MAC_FUNCTIONAL_PARAMETERS = 83
    PRIME_OFDM_PLC_MAC_COUNTERS = 84
    PRIME_OFDM_PLC_MAC_NETWORK_ADMINISTRATION_DATA = 85
    #PRIME_OFDM_PLC_MAC_ADDRESS_SETUP = 43
    PRIME_OFDM_PLC_MAC_APPLICATION_IDENTIFICATION = 86

    # Narrowband OFDM PLC profile for G3-PLC network
    G3_PLC_MAC_LAYER_COUNTERS = 90
    G3_PLC_MAC_SETUP = 91
    G3_PLC_6LOWPAN_ADAPTATION_LAYER_SETUP = 92

    # HS-PLC IEC 12139-1
    HS_PLC_IEC_12139_1_MAC_SETUP = 140
    HS_PLC_IEC_12139_1_CPAS_SETUP = 141
    HS_PLC_IEC_12139_1_IP_SSAS_SETUP = 142
    HS_PLC_IEC_12139_1_HDLC_SSAS_SETUP = 143

    # Zigbee
    ZIGBEE_SAS_STARTUP = 101
    ZIGBEE_SAS_JOIN = 102
    ZIGBEE_SAS_APS_FRAGMENTATION = 103
    ZIGBEE_NETWORK_CONTROL = 104
    ZIGBEE_TUNNEL_SETUP = 105

    # LPWAN networks
    SCHC_LPWAN = 126
    SCHC_LPWAN_DIAGNOSTICS = 127
    LORAWAN_SETUP = 128
    LORAWAN_DIAGNOSTICS = 129

    # Wi-SUN
    WISUN_SETUP = 95
    WISUM_DIAGNOSTICS = 96
    RPL_DIAGNOSTICS = 97
    MPL_DIAGNOSTICS = 98

    # IEC 14908 PLC
    IEC_14908_IDENTIFICATION = 130
    IEC_14908_PROTOCOL_SETUP = 131
    IEC_14908_PROTOCOL_STATUS = 132
    IEC_14908_DIAGNOSTICS = 133


    # TODO: how do we represent different versions of interface classes.
    #   I guess the python class representing the interface should have the versions
    #   Like ProfileGenericV1, ProfileGerericV2





@attr.s(auto_attribs=True)
class CosemObject:

    interface: CosemInterface
    instance: Obis
    attribute: int

    LENGTH: ClassVar[int] = 2 + 6 + 1

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        if len(source_bytes) != cls.LENGTH:
            raise ValueError(
                f"Data is not of correct lenght. Should be {cls.LENGTH} but is "
                f"{len(source_bytes)}"
            )
        interface = CosemInterface(int.from_bytes(source_bytes[:2]))
        instance = Obis.from_bytes(source_bytes[2:5])
        attribute = source_bytes[-1]
        return cls(interface, instance, attribute)

    def to_bytes(self) -> bytes:
        return b"".join([
            self.interface.to_bytes(2, 'big'),
            self.instance.to_bytes(),
            self.attribute.to_bytes(1, 'big')
        ])
