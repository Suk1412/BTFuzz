#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from random import randrange, randint
from scapy.layers.bluetooth import L2CAP_CmdHdr, L2CAP_ConnReq, BluetoothL2CAPSocket, L2CAP_ConnResp, L2CAP_ConfReq, L2CAP_ConfResp
from statemachine import StateMachine, State
from bt_layer import L2CAP_Create_Channel_Request, L2CAP_Create_Channel_Response, L2CAP_Move_Channel_Request, L2CAP_Move_Channel_Confirmation_Request

OUR_LOCAL_SCID = 0x40
pkt_cnt = 0
crash_cnt = 0
conn_rsp_flag = 0

def send_pkt(bt_addr, sock, pkt):
    """
    Errno
        ConnectionResetError: [Errno 104] Connection reset by peer
        ConnectionRefusedError: [Errno 111] Connection refused
        TimeoutError: [Errno 110] Connection timed out
        and so on ..
    """
    global pkt_cnt
    global crash_cnt
    pkt_cnt += 1
    sock.send(pkt)
    # Reset Socket
    sock = BluetoothL2CAPSocket(bt_addr)
    return sock

class l2cap_state_machine(StateMachine):
    ### States ###
    # Basic States
    closed_state = State('Closed State', initial=True)  # Start
    open_state = State('Open State') # End
    wait_connect_state = State('Wait Connect State')
    wait_create_state = State('Wait Create State')
    wait_config_state = State('Wait Config State')

    wait_move_state = State('Wait Move State')
    wait_move_confirm_state = State('Wait Move Confirm State')

    # Configurateion States
    wait_send_config_state = State('Wait Send Config State')
    wait_config_rsp_state = State('Wait Config Rsp State')
    wait_final_rsp_state = State('Wait Final Rsp State')
    wait_ind_final_rsp_state = State('Wait Ind Final Rsp State')

    # from open_state
    open_to_closed = open_state.to(closed_state)
    open_to_w_move = open_state.to(wait_move_state)
    open_to_w_move_confirm = open_state.to(wait_move_confirm_state)

    # from wait_move_confirm_state
    w_move_confirm_to_open = wait_move_confirm_state.to(open_state)

    # from wait_move_state
    w_move_to_w_move_confirm = wait_move_state.to(wait_move_confirm_state)

    # from connect_state
    w_conn_to_closed = wait_connect_state.to(closed_state)

    # from create_state
    w_create_to_closed = wait_create_state.to(closed_state)

    # from wait_config_state
    w_conf_to_w_conf = wait_config_state.to.itself()
    w_conf_to_w_send_conf = wait_config_state.to(wait_send_config_state)
    w_conf_to_closed = wait_config_state.to(closed_state)

    # from wait_send_config_state
    w_send_conf_to_w_conf_rsp = wait_send_config_state.to(wait_config_rsp_state)

    # from closed_state
    closed_to_w_conn = closed_state.to(wait_connect_state)
    closed_to_w_create = closed_state.to(wait_create_state)
    closed_to_w_conf = closed_state.to(wait_config_state)
    closed_to_open = closed_state.to(open_state)

    # from wait_ind_final_rsp_state
    w_ind_final_rsp_to_w_final_rsp = wait_ind_final_rsp_state.to(wait_final_rsp_state)

    # from wait_config_rsp_state
    w_conf_rsp_to_w_ind_final_rsp = wait_config_rsp_state.to(wait_ind_final_rsp_state)

    # from wait_final_rsp_state
    w_final_rsp_to_open = wait_final_rsp_state.to(open_state)


def connection_state_fuzzing(bt_addr, sock, state_machine):
    print("[+] Tested %d packets" % (pkt_cnt))
    iteration = 1
    for i in range(0, iteration):
        cmd_code = 0x02
        pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConnReq(psm=1)/b'test'
        sock = send_pkt(bt_addr, sock, pkt)
        state_machine.closed_to_w_conn()

        cmd_code = 0x03
        pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConnResp(dcid=randrange(0x0040, 0x10000), scid=randrange(0x0040, 0x10000))/b'test'
        sock = send_pkt(bt_addr, sock, pkt)
        state_machine.w_conn_to_closed()


def creation_state_fuzzing(bt_addr, sock, state_machine):
    print("[+] Tested %d packets" % (pkt_cnt))
    iteration = 1
    for i in range(0, iteration):
        cmd_code = 0x0c
        pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Create_Channel_Request(psm=1)/b'test'
        sock = send_pkt(bt_addr, sock, pkt)
        state_machine.closed_to_w_create()

        cmd_code = 0x0D
        pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Create_Channel_Response(dcid=randrange(0x0040, 0x10000), scid=randrange(0x0040, 0x10000))/b'test'
        sock = send_pkt(bt_addr, sock, pkt)
        state_machine.w_create_to_closed()


def configuration_state_fuzzing(bt_addr, sock, state_machine, port):
    print("[+] Tested %d packets" % (pkt_cnt))
    iteration = 1
    while True:
        cmd_code = 0x02
        pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConnReq(psm=port, scid=OUR_LOCAL_SCID)
        sock = send_pkt(bt_addr, sock, pkt)
        global conn_rsp_flag
        global dcid_value
        if (conn_rsp_flag == 0):
            conn_rsp = sock.recv()
            try:
                dcid_value = conn_rsp.dcid
                result_value = conn_rsp.result
            except:
                dcid_value = OUR_LOCAL_SCID
                result_value = 1
            conn_rsp_flag = 1
            if(result_value != 0):
                print("[!] Device is not paired with host. \n[!] Can't test service port that you've selected. Now set port as default PSM, '1'.")
                port = 1
                continue
        break
    state_machine.closed_to_w_conf()

    # 1) Target State : Wait Config State
    for i in range(0, iteration):
        cmd_code = 0x04
        pkt4fuzz = L2CAP_CmdHdr(code=cmd_code) / L2CAP_ConfReq(dcid=randrange(0x0040, 0x10000)) / b'text'
        sock = send_pkt(bt_addr, sock, pkt4fuzz)
        state_machine.w_conf_to_w_conf()
    cmd_code = 0x04
    pkt = L2CAP_CmdHdr(code=cmd_code) / L2CAP_ConfReq(dcid=dcid_value)
    sock = send_pkt(bt_addr, sock, pkt)
    state_machine.w_conf_to_w_send_conf()

    # 2) Target State : Wait Send Config State
    for i in range(0, iteration):
        cmd_code = 0x04
        pkt4fuzz = L2CAP_CmdHdr(code=cmd_code) / L2CAP_ConfReq(dcid=randrange(0x0040, 0x10000)) / b'text'
        sock = send_pkt(bt_addr, sock, pkt4fuzz)
    state_machine.w_send_conf_to_w_conf_rsp()

    # 3) Target State : Wait Config Rsp State
    for i in range(0, iteration):
        cmd_code = 0x05
        pkt4fuzz = L2CAP_CmdHdr(code=cmd_code) / L2CAP_ConfResp(scid=randrange(0x0040, 0x10000)) / b'text'
        sock = send_pkt(bt_addr, sock, pkt4fuzz)
    cmd_code = 0x05
    pkt = L2CAP_CmdHdr(code=cmd_code) / L2CAP_ConfResp(scid=dcid_value)
    sock = send_pkt(bt_addr, sock, pkt)
    state_machine.w_conf_rsp_to_w_ind_final_rsp()

    # 4) Target State : Wait Ind Final Rsp State
    for i in range(0, iteration):
        cmd_code = 0x02
        pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConnReq(psm=1) / b'text'
        sock = send_pkt(bt_addr, sock, pkt)
    cmd_code = 0x02
    pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConnReq(psm=port, scid=OUR_LOCAL_SCID)
    sock = send_pkt(bt_addr, sock, pkt)
    state_machine.w_ind_final_rsp_to_w_final_rsp()

    for i in range(0, iteration):
        cmd_code = 0x04
        pkt4fuzz = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConfReq(dcid=randrange(0x0040, 0x10000)) / b'text'
        sock = send_pkt(bt_addr, sock, pkt4fuzz)
    cmd_code = 0x04
    pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConfReq(dcid=dcid_value)
    sock = send_pkt(bt_addr, sock, pkt)
    state_machine.w_final_rsp_to_open()

    state_machine.open_to_closed()

def shift_state_fuzzing(bt_addr,sock, state_machine):
    print("[+] Tested %d packets" % (pkt_cnt))
    state_machine.closed_to_open()
    iteration = 1
    for i in range(0,iteration):
        cmd_code = 0x0E
        pkt = L2CAP_CmdHdr(code=cmd_code) / L2CAP_Move_Channel_Request(dest_controller_id=0) / b"text"
        sock = send_pkt(bt_addr, sock, pkt)
    state_machine.open_to_w_move()
    state_machine.w_move_to_w_move_confirm()
    state_machine.w_move_confirm_to_open()

    for i in range(0, iteration):
        cmd_code = 0x0E
        pkt = L2CAP_CmdHdr(code=cmd_code) / L2CAP_Move_Channel_Confirmation_Request(icid=0) / b"text"
        sock = send_pkt(bt_addr, sock, pkt)

        state_machine.open_to_w_move_confirm()
        state_machine.w_move_confirm_to_open()
        state_machine.open_to_closed()

def disconnection_state_fuzzing():
    pass



