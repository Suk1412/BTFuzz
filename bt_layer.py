#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from random import randint, randrange
from scapy.all import *
from scapy.packet import Packet


class garbage_value(Packet):
    fields_desc = [
                   LEShortField("garbage", 0)
                   ]


class new_L2CAP_ConnReq(Packet):
    name = "L2CAP Conn Req"
    fields_desc = [LEShortEnumField("psm", 0, {1: "SDP", 3: "RFCOMM", 5: "TCS-BIN", # noqa
                                               7: "TCS-BIN-CORDLESS", 15: "BNEP", 17: "HID-Control", # noqa
                                               19: "HID-Interrupt", 21: "UPnP", 23: "AVCTP-Control", # noqa
                                               25: "AVDTP", 27: "AVCTP-Browsing", 29: "UDI_C-Plane", # noqa
                                               31: "ATT", 33: "3DSP", 35: "IPSP", 37: "OTS"}), # noqa
                   LEShortField("scid", 0),
                   ]


class new_L2CAP_ConnResp(Packet):
    name = "L2CAP Conn Resp"
    fields_desc = [LEShortField("dcid", 0),
                   LEShortField("scid", 0),
                   LEShortEnumField("result", 0, ["success", "pend", "cr_bad_psm", "cr_sec_block", "cr_no_mem", "reserved", "cr_inval_scid", "cr_scid_in_use"]),  # noqa: E501
                   LEShortEnumField("status", 0, ["no_info", "authen_pend", "author_pend", "reserved"]),  # noqa: E501
                   ]


class new_L2CAP_ConfReq(Packet):
    name = "L2CAP Conf Req"
    fields_desc = [ LEShortField("dcid",0),
                    LEShortField("flags",0),
                    ByteField("type",0),
                    ByteField("length",0),
                    ByteField("identifier",0),
                    ByteField("servicetype",0),
                    LEShortField("sdusize",0),
                    LEIntField("sduarrtime",0),
                    LEIntField("accesslat",0),
                    LEIntField("flushtime",0),
                    ]


class new_L2CAP_ConfResp(Packet):
    name = "L2CAP Conf Resp"
    fields_desc = [LEShortField("scid",0),
                   LEShortField("flags",0),
                   LEShortField("result",0),
                   ByteField("type0",0),
                   ByteField("length0",0),
                   LEShortField("option0",0),
                   ByteField("type1",0),
                   ByteField("length1",0),
                   ]


class L2CAP_Create_Channel_Request(Packet):
    name = "L2CAP Create Channel Request"
    fields_desc = [LEShortEnumField("psm", 0, {1: "SDP", 3: "RFCOMM", 5: "TCS-BIN", # noqa
                                               7: "TCS-BIN-CORDLESS", 15: "BNEP", 17: "HID-Control", # noqa
                                               19: "HID-Interrupt", 21: "UPnP", 23: "AVCTP-Control", # noqa
                                               25: "AVDTP", 27: "AVCTP-Browsing", 29: "UDI_C-Plane", # noqa
                                               31: "ATT", 33: "3DSP", 35: "IPSP", 37: "OTS"}), # noqa
                   LEShortField("scid", 0),
                   ByteField("controller_id", 0),
                   ]


class L2CAP_Create_Channel_Response(Packet):
    name = "L2CAP Create Channel Response"
    fields_desc = [LEShortField("dcid", 0),
                   LEShortField("scid", 0),
                   LEShortEnumField("result", 0, {0: "Connection successful", 1: "Connection pending", 2: "Connection refused - PSM not supported",
                                                  3: "Connection refused - security block", 4: "Connection refused - no resources available", 5: "Connection refused - Controller ID not supported",
                                                  6: "Connection refused - Invalid Source CID", 7: "Connection refused - Source CID already allocated"}),
                   LEShortEnumField("status", 0, {0: "No further information available", 1: "Authentication pending", 2: "Authorization pending"}),
                   ]


class L2CAP_Move_Channel_Request(Packet):
    name = "L2CAP Move Channel Request"
    fields_desc = [LEShortField("icid", 0),
                   ByteField("cid", 0),
                   ]  # 0: move to Bluetooth BR/EDR, 1: move to wifi 802.11


class L2CAP_Move_Channel_Confirmation_Request(Packet):
    name = "L2CAP Move Channel Confirmation Request"
    fields_desc = [LEShortField("icid", 0),
                   LEShortEnumField("result", 0, {0: "Move success", 1: "Move failure"}),
                   ]


def random_psm():
    """
    random psm for connection state fuzzing

    Since PSMs are odd and the least significant bit of the most significant byte is zero,
    the following ranges do not contain valid PSMs: 0x0100-0x01FF, 0x0300-0x03FF,
    0x0500-0x05FF, 0x0700-0x07FF, 0x0900-0x09FF, 0x0B00-0x0BFF, 0x0D00-
    0x0DFF. All even values are also not valid as PSMs.
    """
    # Get random invalid psm value
    psm4fuzz = 0
    opt = randint(0, 7)
    if(opt == 0):
        psm4fuzz = randrange(0x0100, 0x01FF + 0x0001)
    elif(opt == 1):
        psm4fuzz = randrange(0x0300, 0x03FF + 0x0001)
    elif(opt == 2):
        psm4fuzz = randrange(0x0500, 0x05FF + 0x0001)
    elif(opt == 3):
        psm4fuzz = randrange(0x0700, 0x07FF + 0x0001)
    elif(opt == 4):
        psm4fuzz = randrange(0x0900, 0x09FF + 0x0001)
    elif(opt == 5):
        psm4fuzz = randrange(0x0B00, 0x0BFF + 0x0001)
    elif(opt == 6):
        psm4fuzz = randrange(0x0D00, 0x0DFF + 0x0001)
    elif(opt == 7):
        psm4fuzz = randrange(0x0000, 0xFFFF + 0x0001, 2)
    return psm4fuzz