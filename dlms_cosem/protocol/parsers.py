import attr
from datetime import timedelta, datetime
from typing import *

from dlms_cosem.protocol import a_xdr, enumerations
from dlms_cosem.protocol.cosem import CosemAttribute
from dlms_cosem.protocol.time import datetime_from_bytes


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
