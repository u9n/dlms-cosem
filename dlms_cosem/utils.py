from dlms_cosem import a_xdr


def parse_as_dlms_data(data: bytes):
    data_decoder = a_xdr.AXdrDecoder(
        encoding_conf=a_xdr.EncodingConf(
            attributes=[a_xdr.Sequence(attribute_name="data")]
        )
    )
    return data_decoder.decode(data)["data"]
