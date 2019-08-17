"""Exceptions used by Lbws."""


class LbwsException(Exception):
    """General Lbws exception occurred."""

    pass


class LbwsNotConnectedError(LbwsException):
    """Exception raised when method needs to be connected and it's not."""

    def __init__(self):
        """Initialize the error."""
        super().__init__('Must call method auth() before using')
