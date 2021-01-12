from contextlib import contextmanager
from decimal import Decimal
from typing import *

import attr

from dlms_cosem import cosem, utils
from dlms_cosem.clients.dlms_client import DlmsClient
from dlms_cosem.cosem import Obis
from dlms_cosem.cosem.profile_generic import Data, ProfileGeneric
from dlms_cosem.protocol.xdlms.selective_access import RangeDescriptor


def force_obis(maybe_obis: Union[str, Obis]):
    if isinstance(maybe_obis, Obis):
        return maybe_obis
    else:
        return Obis.from_dotted(maybe_obis)


@attr.s(auto_attribs=True)
class NumericalMeterValue:
    """
    When parsing data from a DlmsMeter it can be a simple value that we know the meta
    data around before since it is predefined. For example static attribute on an
    interface class. For example capture_period on ProfileGeneric is an integer in
    minutes.
    Other attributes can be objects that is returned so that we may correctly parse
    data in other attributes: Ex. capture_objects in Profile Generic.
    Modeling values when they are not part of an attribute on an interface class is
    usually done via interface classes DATA and REGISTER.
    We also have numerial based values and string-based values.
    """

    # To avoid floating point rounding error we should always use Decimal to
    # represent a numerical value in a meter.
    value: Decimal

    # Scalar is used if the value provides one
    scalar: Optional[int]

    # see table 4 in Blue Book.
    # TODO: simple Enum or a factory that returns Unit objects?
    unit: Any


@attr.s(auto_attribs=True)
class StringlikeMeterValue:
    """
    For meter values that are string-like. Bytes should be represented as hexadecimal
    strings If we can't decode them to strings.
    """

    pass


@attr.s(auto_attribs=True)
class Meter:

    dlms_client: DlmsClient
    objects: Dict[str, Union[ProfileGeneric, Data]]

    def object_exists(self, object_obis: Obis) -> bool:
        return object_obis.dotted_repr() in self.objects.keys()

    @contextmanager
    def session(self):
        self.dlms_client.associate()
        yield self
        self.dlms_client.release_association()

    def get(
        self,
        logical_name: Union[str, Obis],
        attribute: int,
        selective_access: Optional[RangeDescriptor] = None,
    ):
        obis = force_obis(logical_name)
        instance = self.objects.get(obis.dotted_repr(), None)
        if instance is None:
            raise ValueError(
                f"Object with logical name {obis.dotted_repr()} does not exist on meter"
            )
        if instance.is_static_attribute(attribute):
            # check if the value is already present on the meter
            value = getattr(
                instance, instance.STATIC_ATTRIBUTES[attribute].attribute_name
            )
            if value:
                return value

        value = utils.parse_as_dlms_data(
            self.dlms_client.get(
                cosem_attribute=cosem.CosemAttribute(
                    interface=instance.INTERFACE_CLASS_ID,
                    instance=obis,
                    attribute=attribute,
                )
            )
        )

        if instance.is_static_attribute(attribute):
            setattr(
                instance, instance.STATIC_ATTRIBUTES[attribute].attribute_name, value
            )

        converter = instance.DYNAMIC_CONVERTERS.get(attribute, None)
        if converter:
            return converter(instance, value)
        return value
