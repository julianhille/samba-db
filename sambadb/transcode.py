# -*- coding: utf-8 -*-
"""Basic transcoding clases to pack and unpack."""

import struct


class SimpleDataType(object):
    """A simple data type base.

    Enables us to decode and encode easy structs like ints, bool, float etc
    """

    size = None  # type: int
    code = ''  # type: str

    @classmethod
    def decode(cls, packed_data):
        """Decode data based on defined code.

        Args:
            packed_data (bytes): data to decode

        Returns:
            tuple(int, str)
            the int is to be able to know how far we need to jump to
            the next position
        """
        value = struct.unpack('<{}'.format(cls.code),
                              packed_data[:cls.size])[0]
        return cls.size, value

    @classmethod
    def encode(cls, value):
        """Encode and pack data.

        Args:
            value (bytes): data to be packed

        Returns:
            data as packed struct
        """
        if value is None:
            value = 0

        return struct.pack('<{}'.format(cls.code), value)


class Uint16(SimpleDataType):
    """A unsigned int16 / short to decode and encode."""

    size = 2
    code = 'H'


class Uint32(SimpleDataType):
    """A unsigned int32 to decode and encode."""

    size = 4
    code = 'I'


class String(object):
    """A string is null terminated."""

    @classmethod
    def decode(cls, packed_data):
        """Decode a string from struct.

        A string / char has a null termination which we need to remove.

        Args:
            packed_data (bytes): data packed to unpack

        Returns:
            tuple(int, str)
            the int is to be able to know how far we need to jump
            to the next position

        """
        lookahead, string_len = Uint32.decode(packed_data)
        data_size = lookahead + string_len - 1
        if string_len > 0:
            value = struct.unpack('<{}s'.format(string_len - 1),
                                  packed_data[lookahead:data_size])[0]
        else:
            value = None
        return lookahead + string_len, value

    @classmethod
    def encode(cls, value):
        """Encode and pack data.

        Args:
            value (bytes): data to be packed

        Returns:
            data as packed struct
        """
        if value is None:
            return Uint32.encode(0)

        value += '\x00'
        size = len(value)
        return Uint32.encode(size) + struct.pack('{}s'.format(size), value)


class Pointer(object):
    """Decode and encode a pointer to/from a struct."""

    @classmethod
    def decode(cls, packed_data):
        """Decode a pointer.

        A pointer is unlike a string / char not null terminated.

        Args:
            packed_data (bytes): data packed to unpack

        Returns:
            tuple(int, value)
            the int is to be able to know how far we need to jump
            to the next position

        """
        lookahead, string_len = Uint32.decode(packed_data)
        data_size = lookahead + string_len
        if string_len > 0:
            value = struct.unpack('<{}s'.format(string_len),
                                  packed_data[lookahead:data_size])[0]
        else:
            value = None
        return lookahead + string_len, value

    @classmethod
    def encode(cls, value):
        """Encode and pack data.

        Args:
            value (bytes): data to be packed

        Returns:
            data as packed struct
        """
        if value is None:
            return Uint32.encode(0)

        size = len(value)
        return Uint32.encode(size) + struct.pack('{}s'.format(size), value)


class Password(Pointer):
    """Password is a pointer and is not extra null terminated."""

    @classmethod
    def decode(cls, packed_data):
        """Decode a password.

        Args:
            packed_data (bytes): data packed to unpack

        Returns:
            tuple(int, hex value of the password)
            the int is to be able to know how far we need to jump
            to the next position
        """
        lookahead, value = super(Password, cls).decode(packed_data)
        return lookahead, value if not value else value.encode('hex').upper()

    @classmethod
    def encode(cls, value):
        """Encode and pack password.

        Args:
            value (bytes): not as hex encoded bytes password.

        Returns:
            data as packed struct
        """
        value = value if not value else value.decode('hex')
        return super(Password, cls).encode(value)


class Struct(object):
    """Class for Sambas passdb structure.

    Offers methods for encoding and decoding the binary
    format samba uses.
    """

    attribute_map = []  # type: List[tuple[str, object]]

    def __init__(self):
        """Init the struct class."""
        self._data = {}

    def set(self, key, value):
        """Set a value for an attribute key.

        Args:
            key (str): Key of the attribute to set.
            value (int or str): Value of the attribute to set.
        Raises:
            AttributeError: If key is not in the map of attributes
        """
        for search_key, _ in self.attribute_map:
            if key == search_key:
                self._data[key] = value
                return
        raise AttributeError

    def decode(self, packed_data):
        """Decode given binary data.

        Args:
            packed_data (str): Binary data of Sambas passdb struct
        """
        start = 0
        for attribute, decoder in self.attribute_map:
            lookahead, value = decoder.decode(packed_data[start:])

            start += lookahead
            self._data[attribute] = value

    def encode(self):
        """Encode currently set attributes to binary data.

        Returns:
            completely packed data
        """
        value = ''
        for attribute, decoder in self.attribute_map:
            if attribute not in self._data:
                self._data[attribute] = None
            value += decoder.encode(self._data[attribute])
        return value
