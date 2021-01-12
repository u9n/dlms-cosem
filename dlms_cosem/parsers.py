from datetime import datetime, timedelta
from typing import *

import attr

from dlms_cosem import a_xdr, cosem, enumerations
from dlms_cosem.cosem import CosemAttribute
from dlms_cosem.cosem.association import (
    AccessRight,
    AssociationObjectListItem,
    AttributeAccessRights,
    MethodAccessRights,
)
from dlms_cosem.time import datetime_from_bytes


@attr.s(auto_attribs=True)
class ColumnValue:

    attribute: CosemAttribute
    value: Any


@attr.s(auto_attribs=True)
class ProfileGenericBufferParser:

    capture_objects: List[CosemAttribute]
    capture_period: int  # minutes

    def parse_bytes(self, profile_bytes: bytes):
        """
        Profile generic are sent as a sequence of A-XDR encoded DlmsData.
        """
        data_decoder = a_xdr.AXdrDecoder(
            encoding_conf=a_xdr.EncodingConf(
                attributes=[a_xdr.Sequence(attribute_name="data")]
            )
        )
        entries: List[List[Any]] = data_decoder.decode(profile_bytes)["data"]

        return self.parse_entries(entries)

    def parse_entries(
        self, entries: List[List[Optional[Any]]]
    ) -> List[List[Optional[ColumnValue]]]:
        """
        Returns a list of columns with the cosem attribut linked to the value with a
        ColumnValue.
        It also sets the timestamp on each column calculated from the prevoius entry
        if the data has been sent compressed using null values
        """
        parsed_entries = list()
        last_entry_timestamp: Optional[datetime] = None
        for entry in entries:
            if len(entry) != len(self.capture_objects):
                raise ValueError(
                    f"Unable to parse ProfileGeneric entry as the amount of columns "
                    f"({len(entry)}) differ from the parsers set capture_object length "
                    f"({len(self.capture_objects)}) "
                )
            parsed_column = list()
            for index, column in enumerate(entry):
                cosem_attribute = self.capture_objects[index]
                if column is not None:
                    if cosem_attribute.interface == enumerations.CosemInterface.CLOCK:
                        # parse as time.
                        value = datetime_from_bytes(column)[
                            0
                        ]  # TODO: do we need clock status?
                        last_entry_timestamp = value
                        parsed_column.append(
                            ColumnValue(attribute=cosem_attribute, value=value)
                        )
                    else:
                        parsed_column.append(
                            ColumnValue(attribute=cosem_attribute, value=column)
                        )
                else:
                    if cosem_attribute.interface == enumerations.CosemInterface.CLOCK:
                        if last_entry_timestamp:
                            value = last_entry_timestamp + timedelta(
                                minutes=self.capture_period
                            )
                            last_entry_timestamp = value
                            parsed_column.append(
                                ColumnValue(attribute=cosem_attribute, value=value)
                            )

                        else:
                            parsed_column.append(None)

            parsed_entries.append(parsed_column)

        return parsed_entries


class AssociationObjectListParser:
    @staticmethod
    def parse_bytes(profile_bytes: bytes):
        """
        Profile generic are sent as a sequence of A-XDR encoded DlmsData.
        """
        data_decoder = a_xdr.AXdrDecoder(
            encoding_conf=a_xdr.EncodingConf(
                attributes=[a_xdr.Sequence(attribute_name="data")]
            )
        )
        entries: List[List[Any]] = data_decoder.decode(profile_bytes)["data"]

        return AssociationObjectListParser.parse_entries(entries)

    @staticmethod
    def parse_access_right(access_right: int) -> List[AccessRight]:
        parsed_access_rights = list()
        if bool(access_right & 0b00000001):
            parsed_access_rights.append(AccessRight.READ_ACCESS)
        if bool(access_right & 0b00000010):
            parsed_access_rights.append(AccessRight.WRITE_ACCESS)
        if bool(access_right & 0b00000100):
            parsed_access_rights.append(AccessRight.AUTHENTICATED_REQUEST)
        if bool(access_right & 0b00001000):
            parsed_access_rights.append(AccessRight.ENCRYPTED_REQUEST)
        if bool(access_right & 0b00010000):
            parsed_access_rights.append(AccessRight.DIGITALLY_SIGNED_REQUEST)
        if bool(access_right & 0b00100000):
            parsed_access_rights.append(AccessRight.AUTHENTICATED_RESPONSE)
        if bool(access_right & 0b01000000):
            parsed_access_rights.append(AccessRight.ENCRYPTED_RESPONSE)
        if bool(access_right & 0b10000000):
            parsed_access_rights.append(AccessRight.DIGITALLY_SIGNED_RESPONSE)

        return parsed_access_rights

    @staticmethod
    def parse_attribute_access_rights(
        access_rights: List[List[Optional[Union[int, List[int]]]]]
    ):
        parsed_access_rights = list()
        for right in access_rights:
            parsed_access_rights.append(
                AttributeAccessRights(
                    attribute=right[0],
                    access_rights=AssociationObjectListParser.parse_access_right(
                        right[1]
                    ),
                    access_selectors=right[2],
                )
            )
        return parsed_access_rights

    @staticmethod
    def parse_method_access_rights(
        access_rights: List[List[int]],
    ) -> List[MethodAccessRights]:
        parsed_access_rights = list()
        for right in access_rights:
            parsed_access_rights.append(
                MethodAccessRights(
                    method=right[0],
                    access_rights=AssociationObjectListParser.parse_access_right(
                        right[1]
                    ),
                )
            )

        return parsed_access_rights

    @staticmethod
    def parse_entries(object_list):
        parsed_objects = list()
        for obj in object_list:
            interface = enumerations.CosemInterface(obj[0])
            version = obj[1]
            logical_name = cosem.Obis.from_bytes(obj[2])
            access_rights = obj[3]
            attribute_access_rights = (
                AssociationObjectListParser.parse_attribute_access_rights(
                    access_rights[0]
                )
            )
            attribute_access_dict = {
                access.attribute: access for access in attribute_access_rights
            }
            method_access_rights = (
                AssociationObjectListParser.parse_method_access_rights(access_rights[1])
            )
            method_access_dict = {
                access.method: access for access in method_access_rights
            }

            parsed_objects.append(
                AssociationObjectListItem(
                    interface=interface,
                    version=version,
                    logical_name=logical_name,
                    attribute_access_rights=attribute_access_dict,
                    method_access_rights=method_access_dict,
                )
            )
        return parsed_objects
