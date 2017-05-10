"""
Base class for Merou oneoffs. These are scripts are run in the Merou
environment via grouper-ctl.
"""


class BaseOneOff(object):
    def configure(self, service_name):
        """
        Called once the plugin is instantiated to identify the executable
        (grouper-api or grouper-fe).
        """
        pass

    def run(self, session, *args):
        raise NotImplemented
