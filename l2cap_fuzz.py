# #!/usr/bin/python3
# # -*- encoding: utf-8 -*-
# from collections import OrderedDict
# from datetime import datetime
# from random import randrange
# from scapy.compat import raw
# from state_machine import Event
# from statemachine import StateMachine, State
# from scapy.layers.bluetooth import BluetoothL2CAPSocket, L2CAP_CmdHdr
#
# from bt_layer import new_L2CAP_ConnReq, random_psm, garbage_value, new_L2CAP_ConnResp
#
# pkt_cnt = 0
# crash_cnt = 0
# conn_rsp_flag = 0
#
#
# class l2cap_state_machine(StateMachine):
#     """
#     L2CAP Protocol Fuzzing with 'Stateful Fuzzing Algorithm'
#
#     A state machine is created for each new L2CAP_ConnectReq received.
#     The state machine always starts in the CLOSED state
#
#     *The state machine does not necessarily represent all possible scenarios.
#     """
#
#     #### States ####
#
#     # Basic States
#     closed_state = State('Closed State', initial=True)  # Start
#     open_state = State('Open State')  # End
#     wait_config_state = State('Wait Config State')
#     wait_connect_state = State('Wait Connect State')
#     wait_connect_rsp_state = State('Wait Connect Rsp State')
#     wait_disconnect_state = State('Wait Disconnect State')
#
#     # Optional States (Alternative MAC/PHY enabled operation)
#     wait_create_state = State('Wait Create State')
#     wait_create_rsp_state = State('Wait Create Rsp State')
#     wait_move_confirm_state = State('Wait Move Confirm State')
#     wait_move_state = State('Wait Move State')
#     wait_move_rsp_state = State('Wait Move Rsp State')
#     wait_confirm_rsp_state = State('Wait Confirm Rsp State')
#
#     # Configurateion States
#     wait_send_config_state = State('Wait Send Config State')
#     wait_config_req_rsp_state = State('Wait Config Req Rsp State')
#     wait_config_req_state = State('Wait Config Req State')
#     wait_config_rsp_state = State('Wait Config Rsp State')
#     wait_control_ind_state = State('Wait Control Ind State')
#     wait_final_rsp_state = State('Wait Final Rsp State')
#     wait_ind_final_rsp_state = State('Wait Ind Final Rsp State')
#
#     #### Transitions ####
#
#     # from open_state
#     open_to_w_discon = open_state.to(wait_disconnect_state)
#     open_to_closed = open_state.to(closed_state)
#     open_to_w_conf = open_state.to(wait_config_state)
#     open_to_w_move = open_state.to(wait_move_state)
#     open_to_w_move_rsp = open_state.to(wait_move_rsp_state)
#     open_to_w_move_confirm = open_state.to(wait_move_confirm_state)
#
#     # from wait_config_state
#     w_conf_to_closed = wait_config_state.to(closed_state)
#     w_conf_to_w_discon = wait_config_state.to(wait_disconnect_state)
#     w_conf_to_w_conf = wait_config_state.to.itself()
#     w_conf_to_w_send_conf = wait_config_state.to(wait_send_config_state)
#     w_conf_to_w_conf_req_rsp = wait_config_state.to(wait_config_req_rsp_state)
#
#     # from closed_state
#     closed_to_w_conn = closed_state.to(wait_connect_state)
#     closed_to_w_conf = closed_state.to(wait_config_state)
#     closed_to_w_conn_rsp = closed_state.to(wait_connect_rsp_state)
#     closed_to_w_create = closed_state.to(wait_create_state)
#     closed_to_w_create_rsp = closed_state.to(wait_create_rsp_state)
#
#     # from wait_connect_state
#     w_conn_to_closed = wait_connect_state.to(closed_state)
#     w_conn_to_w_conf = wait_connect_state.to(wait_config_state)
#
#     # from wait_connect_rsp_state
#     w_conn_rsp_to_closed = wait_connect_rsp_state.to(closed_state)
#     w_conn_rsp_to_w_conf = wait_connect_rsp_state.to(wait_config_state)
#
#     # from wait_disconnect_state
#     w_disconn_to_w_disconn = wait_disconnect_state.to.itself()
#     w_disconn_to_closed = wait_disconnect_state.to(closed_state)
#
#     # from wait_create_state
#     w_create_to_closed = wait_create_state.to(closed_state)
#     w_create_to_w_conf = wait_create_state.to(wait_config_state)
#
#     # from wait_create_rsp_state
#     w_create_rsp_to_closed = wait_create_rsp_state.to(closed_state)
#     w_create_rsp_to_w_conf = wait_create_rsp_state.to(wait_config_state)
#
#     # from wait_move_confirm_state
#     w_move_confirm_to_open = wait_move_confirm_state.to(open_state)
#
#     # from wait_move_state
#     w_move_to_w_move_confirm = wait_move_state.to(wait_move_confirm_state)
#
#     # from wait_move_rsp_state
#     w_move_rsp_to_w_confirm_rsp = wait_move_rsp_state.to(wait_confirm_rsp_state)
#     w_move_rsp_to_w_move = wait_move_rsp_state.to(wait_move_state)
#     w_move_rsp_to_w_move_confirm = wait_move_rsp_state.to(wait_move_confirm_state)
#     w_move_rsp_to_w_move_rsp = wait_move_rsp_state.to.itself()
#
#     # from wait_confirm_rsp_state
#     w_confirm_rsp_to_open = wait_confirm_rsp_state.to(open_state)
#
#     # from wait_send_config_state
#     w_send_conf_to_w_conf_rsp = wait_send_config_state.to(wait_config_rsp_state)
#
#     # from wait_config_req_rsp_state
#     w_conf_req_rsp_to_w_conf_req_rsp = wait_config_req_rsp_state.to.itself()
#     w_conf_req_rsp_to_w_conf_req = wait_config_req_rsp_state.to(wait_config_req_state)
#     w_conf_req_rsp_to_w_conf_rsp = wait_config_req_rsp_state.to(wait_config_rsp_state)
#
#     # from wait_config_req_state
#     w_conf_req_to_w_conf_req = wait_config_req_state.to.itself()
#     w_conf_req_to_open = wait_config_req_state.to(open_state)
#     w_conf_req_to_w_ind_final_rsp = wait_config_req_state.to(wait_ind_final_rsp_state)
#
#     # from wait_final_rsp_state
#     w_final_rsp_to_open = wait_final_rsp_state.to(open_state)
#     w_final_rsp_to_w_conf = wait_final_rsp_state.to(wait_config_state)
#
#     # from wait_control_ind_state
#     w_control_ind_to_w_conf = wait_control_ind_state.to(wait_config_state)
#     w_control_ind_to_open = wait_control_ind_state.to(open_state)
#
#     # from wait_ind_final_rsp_state
#     w_ind_final_rsp_to_w_final_rsp = wait_ind_final_rsp_state.to(wait_final_rsp_state)
#     w_ind_final_rsp_to_w_control_ind = wait_ind_final_rsp_state.to(wait_control_ind_state)
#     w_ind_final_rsp_to_w_conf = wait_ind_final_rsp_state.to(wait_config_state)
#
#     # from wait_config_rsp_state
#     w_conf_rsp_to_w_ind_final_rsp = wait_config_rsp_state.to(wait_ind_final_rsp_state)
#     w_conf_rsp_to_w_conf_rsp = wait_config_rsp_state.to.itself()
#     w_conf_rsp_to_open = wait_config_rsp_state.to(open_state)
#
# def send_pkt(bt_addr, sock, pkt, cmd_code, state):
#     """
#     Errno
#         ConnectionResetError: [Errno 104] Connection reset by peer
#         ConnectionRefusedError: [Errno 111] Connection refused
#         TimeoutError: [Errno 110] Connection timed out
#         and so on ..
#     """
#     global pkt_cnt
#     global crash_cnt
#     pkt_cnt += 1
#     sock.send(pkt)
#     # Reset Socket
#     sock = BluetoothL2CAPSocket(bt_addr)
#     return sock
#
#
# def connection_state_fuzzing(bt_addr, sock, state_machine):
#     """
#         l2cap 链接状态模糊测试
#     """
#     iteration = 2500
#     for i in range(0, iteration):
#         cmd_code = 0x02
#         pkt = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConnReq(psm=random_psm())/garbage_value(garbage=randrange(0x0000, 0x10000))
#         sock = send_pkt(bt_addr, sock, pkt, cmd_code, state_machine.current_state.name)
#         state_machine.closed_to_w_conn()
#
#         cmd_code = 0x03
#         pkt = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConnResp(dcid=randrange(0x0040, 0x10000), scid=randrange(0x0040, 0x10000))/garbage_value(garbage=randrange(0x0000, 0x10000))
#         sock = send_pkt(bt_addr, sock, pkt, cmd_code, state_machine.current_state.name)
#         state_machine.w_conn_to_closed()
#
#
# def l2cap_fuzzing(bt_addr, profile, port):
#         print("Start Fuzzing...")
#         sock = BluetoothL2CAPSocket(bt_addr)
#         state_machine = l2cap_state_machine()
#         try:
#             while 1:
#                 print("[+] Tested %d packets" % (pkt_cnt))
#                 connection_state_fuzzing(bt_addr, sock, state_machine)
#         except Exception as e:
#             print(f"[!] Error Message {e}")
#         except KeyboardInterrupt as k:
#             print(f"[!] Fuzzing Stopped {k}")
#
#
