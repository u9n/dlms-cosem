from enum import IntEnum, unique


@unique
class DataAccessResult(IntEnum):
    SUCCESS = 0
    HARDWARE_FAULT = 1
    TEMPORARY_FAILURE = 2
    READ_WRITE_DENIED = 3
    OBJECT_UNDEFINED = 4
    OBJECT_CLASS_INCONSISTENT = 9
    OBJECT_UNAVAILABLE = 11
    TYPE_UNMATCHED = 12
    SCOPE_OF_ACCESS_VIOLATED = 13
    DATA_BLOCK_UNAVAILABLE = 14
    LONG_GET_ABORTED = 15
    NO_LONG_GET_IN_PROGRESS = 16
    LONG_SET_ABORTED = 17
    NO_LONG_SET_IN_PROGRESS = 18
    DATA_BLOCK_NUMBER_INVALID = 19
    OTHER_REASON = 250


class GetRequestType(IntEnum):
    NORMAL = 1
    NEXT = 2
    WITH_LIST = 3


class GetResponseType(IntEnum):
    NORMAL = 1
    WITH_BLOCK = 2
    WITH_LIST = 3


class SetRequestType(IntEnum):
    NORMAL = 1
    WITH_FIRST_BLOCK = 2
    WITH_BLOCK = 3
    WITH_LIST = 4
    FIRST_BLOCK_WITH_LIST = 5


class SetResponseType(IntEnum):
    NORMAL = 1
    WITH_BLOCK = 2
    WITH_LAST_BLOCK = 3
    LAST_BLOCK_WITH_LIST = 4
    WITH_LIST = 5


class ActionType(IntEnum):
    NORMAL = 1
    NEXT_PBLOCK = 2
    WITH_LIST = 3
    WITH_FIRST_PBLOCK = 4
    WITH_LIST_AND_FIRST_PBLOCK = 5
    WITH_PBLOCK = 6


class StateException(IntEnum):
    SERVICE_NOT_ALLOWED = 1
    SERVICE_UNKNOWN = 2


class ServiceException(IntEnum):
    OPERATION_NOT_POSSIBLE = 1
    SERVICE_NOT_SUPPORTED = 2
    OTHER_REASON = 3
    PDU_TOO_LONG = 4
    DECIPHERING_ERROR = 5
    INVOCATION_COUNTER_ERROR = 6


class ApplicationReferenceError(IntEnum):
    OTHER = 0
    TIME_ELAPSED = 1  # timeout since request sent
    APPLICATION_UNREACHABLE = 2  # peer AEi not reachable
    APPLICATION_REFERENCE_INVALID = 3  # addressing problems
    APPLICATION_CONTEXT_UNSUPPORTED = 4  # incompatible application context
    PROVIDER_COMMUNICATION_ERROR = 5  # error in local or remote equipment
    DECIPHERING_ERROR = 6  # Error detected in deciphering function.


class HardwareResourceError(IntEnum):
    OTHER = 0
    MEMORY_UNAVAILABLE = 1
    PROCESSOR_RESOURCE_UNAVAILABLE = 2
    MASS_STORAGE_UNAVAILABLE = 3
    OTHER_RESOURCE_UNAVAILABLE = 4


class VdeStateError(IntEnum):
    OTHER = 0
    NO_DLMS_CONTEXT = 1
    LOADING_DATASET = 2
    STATUS_NO_CHANGE = 3
    STATUS_INOPERABLE = 4


class ServiceError(IntEnum):
    OTHER = 0
    PDU_SIZE = 1  # PDU too long
    SERVICE_UNSUPPORTED = 2  # Service unsupported as in conformance block


class DefinitionError(IntEnum):
    OTHER = 0
    OBJECT_UNDEFINED = 1  # object not defined at the VDE
    OBJECT_CLASS_INCONSISTENT = 2  # class of object incompatible with asked service
    OBJECT_ATTRIBUTE_INCONSISTENT = 3  # object attributes are inconsistent to doc


class AccessError(IntEnum):
    OTHER = 0
    SCOPE_OF_ACCESS_VIOLATED = 1  # access denied through authorisation reason
    OBJECT_ACCESS_VIOLATED = 2  # access incompatible with object attribute
    HARDWARE_FAULT = 3  # access fail for hardware reasons
    OBJECT_UNAVAILABLE = 4  # VDE hands object for unavailable


class InitiateError(IntEnum):
    OTHER = 0
    DLMS_VERSION_TOO_LOW = 1  # proposed dlms version is too low
    INCOMPATIBLE_CONFORMANCE = 2  # proposed service not sufficient
    PDU_SIZE_TOO_SHORT = 3  # proposed pdu size is too short
    REFUSED_BY_VDE_HANDLER = 4  # vaa creation impossible or not allowed


class LoadDataError(IntEnum):
    OTHER = 0
    PRIMITIVE_OUT_OF_SEQUENCE = 1
    NOT_LOADABLE = 2
    DATASET_SIZE_TOO_LARGE = 3
    NOT_AWAITED_SEGMENT = 4
    INTERPRETATION_FAILURE = 5
    STORAGE_FAILURE = 6
    DATASET_NOT_READY = 7


class DataScopeError(IntEnum):
    OTHER = 0


class TaskError(IntEnum):
    OTHER = 0
    NO_REMOTE_CONTROL = 1
    TI_STOPPED = 2
    TI_RUNNING = 3
    TI_UNUSABLE = 4


class OtherError(IntEnum):
    OTHER = 0


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
    # PRIME_OFDM_PLC_MAC_ADDRESS_SETUP = 43
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


@unique
class ReleaseRequestReason(IntEnum):
    NORMAL = 0
    URGENT = 1
    USER_DEFINED = 30


@unique
class ReleaseResponseReason(IntEnum):
    NORMAL = 0
    NOT_FINISHED = 1
    USER_DEFINED = 30


class AuthenticationMechanism(IntEnum):
    NONE = 0
    LLS = 1
    HLS = 2
    HLS_MD5 = 3  # Insecure. Don't use with new meters
    HLS_SHA1 = 4  # Insecure. Don't use with new meters
    HLS_GMAC = 5
    HLS_SHA256 = 6
    HLS_ECDSA = 7


class AcseServiceUserDiagnostics(IntEnum):
    NULL = 0
    NO_REASON_GIVEN = 1
    APPLICATION_CONTEXT_NAME_NOT_SUPPORTED = 2
    CALLING_AP_TITLE_NOT_RECOGNIZED = 3
    CALLING_AP_INVOCATION_IDENTIFIER_NOT_RECOGNIZED = 4
    CALLING_AE_QUALIFIER_NOT_RECOGNIZED = 5
    CALLING_AE_INVOCATION_IDENTIFIER_NOT_RECOGNIZED = 6
    CALLED_AP_TITLE_NOT_RECOGNIZED = 7
    CALLED_AP_INVOCATION_IDENTIFIER_NOT_RECOGNIZED = 8
    CALLED_AE_QUALIFIER_NOT_RECOGNIZED = 9
    CALLED_AE_INVOCATION_IDENTIFIER_NOT_RECOGNIZED = 10
    AUTHENTICATION_MECHANISM_NAME_NOT_RECOGNIZED = 11
    AUTHENTICATION_MECHANISM_NAME_REQUIRED = 12
    AUTHENTICATION_FAILED = 13
    AUTHENTICATION_REQUIRED = 14


class AcseServiceProviderDiagnostics(IntEnum):
    NULL = 0
    NO_REASON_GIVEN = 1
    NO_COMMON_ACSE_VERSION = 2


class AssociationResult(IntEnum):
    ACCEPTED = 0
    REJECTED_PERMANENT = 1
    REJECTED_TRANSIENT = 2
    # TODO: What does transient rejection mean?


class ActionResultStatus(IntEnum):
    SUCCESS = 0
    HARDWARE_FAULT = 1
    TEMPORARY_FAILURE = 2
    READ_WRITE_DENIED = 3
    OBJECT_UNDEFINED = 4
    OBJECT_CLASS_INCONSISTENT = 9
    OBJECT_UNAVAILABLE = 11
    TYPE_UNMATCHED = 12
    SCOPE_OF_ACCESS_VIOLATED = 13
    DATA_BLOCK_UNAVAILABLE = 14
    LONG_ACTION_ABORTED = 15
    NO_LONG_ACTION_IN_PROGRESS = 16
    OTHER_REASON = 250
