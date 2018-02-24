from dlms_cosem.conf import settings
from dlms_cosem.dlms import apdu_factory
from dlms_cosem.utils.module_loading import import_string


class BaseDLMSHandler:

    _meter_managers = None
    _protection_managers = None
    _result_managers = None

    _raw_data = None
    _apdu = None
    _content = None

    _process_data_config = None
    _meter_system_title = None
    _meter_logical_device_name = None
    _security_suite = None

    def __init__(self, raw_data):
        self.load_managers()

        self._raw_data = raw_data

    def process_data(self):
        """
        Passes the handler down to all the different managers where the managers
        can add data to the handler for processing in the other managers.

        """

        self._apdu = apdu_factory.apdu_from_bytes(self._raw_data)

        self._meter_system_title = self._apdu.system_title

        for meter_manager in self._meter_managers:
            meter_manager.process_data(self)

        for protection_manager in self._meter_managers:
            protection_manager.process_data(self)

        result_list = list()
        for result_manager in self._result_managers:
            result = result_manager.process_data(self)
            if result is None:
                continue
            else:
                result_list.append(result)

        return result_list

    def load_managers(self):
        """
        Poppulate the managers from settings.XXX_MANAGERS
        """

        self._meter_managers = list()
        self._protection_managers = list()
        self._result_managers = list()

        for meter_manager_path in settings.METER_MANAGERS:

            manager = import_string(meter_manager_path)

            manager_instance = manager()

            self._meter_managers.append(manager_instance)

        for protection_managers_path in settings.PROTECTION_MANAGERS:

            manager = import_string(protection_managers_path)

            manager_instance = manager()

            self._protection_managers.append(manager_instance)

        for result_manager_path in settings.RESULT_MANAGERS:

            manager = import_string(result_manager_path)

            manager_instance = manager()

            self._result_managers.append(manager_instance)


