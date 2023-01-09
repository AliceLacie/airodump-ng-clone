import struct
import socket 
import sys
import os
import time
import argparse
from argparse import RawTextHelpFormatter

parser = argparse.ArgumentParser(description='airodump-ng clone\n\nusage: python3 airodump-ng.py <interface>',formatter_class=RawTextHelpFormatter)
parser.add_argument('iface', help='<interface>')

args = parser.parse_args()

iface = args.iface
rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
rawSocket.bind((iface, 0x0003))

beacon_dict = {}
probe_dict = {}

pairwise_cipher_suite = {0:'Group_Cipher_Suite', 1:'WEP-40', 2:'TKIP', 3:'Reserved', 4:'CCMP', 5:'WEP-104', 6:'BIP'}
AKM_cipher_suite = {0:'Reserved', 1:'802.1X', 2:'PSK', 3:'IEEE 802.1x', 4:'FT authentication PSK', 5: 'SHA256', 6:'PSK with SHA256', 7:'TDLS', 8:'SAE', 9:'SAE with SHA 256'}
ENC_dict = {0:'WPE', 1:'WPA', 2:'WPA2', 3:'WPA3'}

now = time.time()
sys.stdout.write("\033[2J")

def format_mac(bytes_addr):
    bytes_s = map('{:02x}'.format, bytes_addr) 
    return ":".join(bytes_s).upper()


def struct_unpack(frame, formats, befor_size):
    size = struct.calcsize(formats)
    if len(frame[befor_size:befor_size+size])<size:
        return-1
    tmp_l = list(struct.unpack(formats, frame[befor_size:befor_size+size]))
    tmp_l.append(befor_size+size)
    return tmp_l


def tagged(SSID, frame, size, tmp_dict):
    # print(SSID)
    while True:
        if size == len(frame):
            return tmp_dict
        num, length = struct.unpack('BB', frame[size:size+2])
        size = size+2
        
        if num!=221:
            tmp_dict[num] = [length, struct.unpack(f'{length}s', frame[size:size+length])[-1]]

        elif num == 221 and length >10:
            
            OUI, OUI_type, version, m_OUI, m_type, un_count, tmp_size = struct_unpack(frame, '3s B h 3s B h', size)
            if format_mac(OUI) == '00:50:F2' and format_mac(m_OUI) == '00:50:F2':
                CIPHER_list = []
                AUTH_list = []
                OUI_CI = False
                OUI_AU = False
                for i in struct.unpack('3sB'*un_count, frame[tmp_size:un_count*4+tmp_size]):
                    if type(i) is bytes and format_mac(i) == '00:50:F2': 
                        OUI_CI = True
                    elif type(i) is int and OUI_CI:
                        CIPHER_list.append(i)
                        OUI_CI = False
                tmp_size = un_count*4+tmp_size
                
                akm_count, hsize = struct_unpack(frame, 'h', tmp_size)
                tmp_size = hsize
                for i in struct.unpack('3sB'*akm_count, frame[tmp_size:akm_count*4+tmp_size]):
                    if type(i) is bytes and format_mac(i) == '00:50:F2': 
                        OUI_AU = True
                    if type(i) is int and OUI_AU:
                        AUTH_list.append(i)
                        OUI_AU = False
                
                ENC, CIPHER, AUTH = enc_choice(CIPHER_list,AUTH_list)
                tmp_dict[num] = [ENC, CIPHER, AUTH]
                return tmp_dict
            else:
                tmp_dict[num] = [length, struct.unpack(f'{length}s', frame[size:size+length])[-1]]

        size = size + length


def check_enc(tag_dict):
    ENC = 'OPN'
    CIPHER = ''
    AUTH = ''
    tag_num = tag_dict.keys()    
    if 48 in tag_num:
        frame = tag_dict[48][-1]
        v, gcs, gcst, pcscount, enc_size = struct_unpack(frame,'h 3s B H', 0)
        psc_size = pcscount*4+enc_size

        AUTH_list = []
        CIPHER_list = []

        for i in struct.unpack('3sB'*pcscount, frame[enc_size:psc_size]):
            if type(i) is bytes and format_mac(i) == '00:0F:AC': 
                OUI_CI = True
            if type(i) is int and OUI_CI:
                CIPHER_list.append(i)
                OUI_CI = False

        akmcount = struct.unpack('H', frame[psc_size:psc_size+2])[-1]
        akm_size = akmcount*4+psc_size+2
        for i in struct.unpack('3sB'*akmcount, frame[psc_size+2:akm_size]):
            if type(i) is bytes and format_mac(i) == '00:0F:AC':
                OUI_AU = True
            if type(i) is int and OUI_AU:
                AUTH_list.append(i)
                OUI_AU = False
    
        return enc_choice(CIPHER_list, AUTH_list)
    elif 221 in tag_num:
        if len(tag_dict[221]) == 3:
            return tag_dict[221]
        # return 'OPN', '', ''
        return ENC, CIPHER, AUTH

def enc_choice(CIPHER_list, AUTH_list):
    CIPHER = pairwise_cipher_suite[max(CIPHER_list)]
    AUTH = AKM_cipher_suite[max(AUTH_list)]
    
    if 'SAE' in AUTH:
        ENC = ENC_dict[3]
    elif 'CCMP' in CIPHER:
        ENC = ENC_dict[2]
    elif 'TKIP' in CIPHER:
        ENC = ENC_dict[1]
    elif 'WEP' in CIPHER:
        ENC = ENC_dict[0]
    return ENC, CIPHER, AUTH
    

def print_func(channel, beacon_printable, probe_printable):
    
    sys.stdout.write("\033[2d\033[0G"+f'CH\t{channel}]\n\nBSSID\t\t\tPWR\t\tBeacons\t\tCH\tENC\tCIPHER\tAUTH\tESSID')
    sys.stdout.write(f"\033[6d\033[0G{beacon_printable}\nBSSID\t\t\tSTATION\t\t\tPWR\t\tProbes\n\n{probe_printable}")
    sys.stdout.write("\033[?25h")
    sys.stdout.write("\033[2J")


while True:
    for channel in range(1, 14):
        os.system("iwconfig " + iface + " channel " + str(channel))
        
        frame = rawSocket.recvfrom(65536)[0]
        formats = 'BBH8sBBHHhhh'
        size = struct.calcsize(formats)
        header_version, header_padding, header_size, present_flag, flag, \
            speed, channel_frequencies, channel_flag, antenna_siggnel1, RX_flag, antenna_siggnel2 = struct.unpack(formats, frame[:size])

        check_beacon = 'ss'
        check_size = struct.calcsize(check_beacon)
        subtype, Version_type = struct.unpack(check_beacon, frame[size:size+check_size])
        subtype = int.from_bytes(subtype, "little")>>4
        
        if antenna_siggnel1<127:
            antenna = antenna_siggnel1
        else:
            antenna = antenna_siggnel1-255

        if subtype == 8:
            aformats = '2s6s6s6s2s8s2s2sBB'
            asize = struct.calcsize(aformats)
            if len(frame[size+check_size:]) < (size+check_size+asize)-(size+check_size):
                continue
            
            duration, receiver_address, transmitter_address, BSSID, idk,\
                timestamp,beacon_interval, capabilities_information,\
                tag_num, tag_len = struct.unpack(aformats, frame[size+check_size:size+check_size+asize])

            SSID_size = size+check_size+asize+tag_len

            rate_check = struct_unpack(frame, 'BB', SSID_size)
            
            if rate_check == -1: continue
            rate_num,rate_length, full_size = rate_check

            ch_check = struct_unpack(frame, f'{rate_length}sBB', full_size)
            if ch_check == -1: continue
            d, channel_tag_num, channel_tag_length, full_size = ch_check

            if channel_tag_num == 3: CH = struct.unpack(f'{channel_tag_length}B', frame[full_size:full_size+channel_tag_length])[0]
            else: CH = 'no'
            
            BSSID = format_mac(BSSID)
            try: ESSID = frame[size+check_size+asize:size+check_size+asize+tag_len].decode()
            except UnicodeDecodeError as e: ESSID = f'<length : {tag_len}>'

            full_size = size+check_size+asize+tag_len
            deatil_dict = {}

            if frame[full_size:] == b'' or ESSID == '': continue
            
            try: a = tagged(ESSID, frame, full_size, deatil_dict)
            except struct.error as e: continue
            a = tagged(ESSID, frame, full_size, deatil_dict)

            ENC, CIPHER, AUTH = check_enc(a)

            tmp_list= [antenna, CH, ENC,CIPHER, AUTH, ESSID, 0]
            if BSSID not in beacon_dict.keys():
                beacon_dict[BSSID] = tmp_list
            else:
                for i in range(len(beacon_dict[BSSID])-1):
                    beacon_dict[BSSID][i] = tmp_list[i]
                beacon_dict[BSSID][-1] = beacon_dict[BSSID][-1]+1
            
        elif subtype == 4:
            aformats = '2s6s6s6s2s BB'
            asize = struct.calcsize(aformats)
            if len(frame[size+check_size:]) < (size+check_size+asize)-(size+check_size):
                continue
            
            duration, receiver_address, transmitter_address, BSSID, idk,\
                tag_num, tag_len = struct.unpack(aformats, frame[size+check_size:size+check_size+asize])
            if tag_num == 0:
                full_size = size+check_size+asize
                ESSID = struct.unpack(f'{tag_len}s', frame[full_size:full_size+tag_len])[-1].decode()
            else:
                ESSID = ''
            STATION = format_mac(transmitter_address)
            BSSID = format_mac(BSSID)
            if 'FF:FF:FF:FF:FF:FF' == BSSID:
                BSSID = '(not associated)'

            tmp_list= [BSSID, antenna, ESSID]
            probe_dict[STATION] = tmp_list

        beacon_printable = ''
        probe_printable = ''
        if now+6 < time.time():
            beacon_dict = dict(sorted(beacon_dict.items(), key=lambda item: item[1][0], reverse=True))
            for i in beacon_dict.keys():
                beacon_printable += f'{i}\t{beacon_dict[i][0]}\t\t{beacon_dict[i][-1]}\t\t{beacon_dict[i][1]}\t{beacon_dict[i][2]}\t{beacon_dict[i][3]}\t{beacon_dict[i][4]}\t{beacon_dict[i][5]}\n'
            now = time.time()
        else:
            for i in beacon_dict.keys():
                beacon_printable += f'{i}\t{beacon_dict[i][0]}\t\t{beacon_dict[i][-1]}\t\t{beacon_dict[i][1]}\t{beacon_dict[i][2]}\t{beacon_dict[i][3]}\t{beacon_dict[i][4]}\t{beacon_dict[i][5]}\n'

        if beacon_dict and not probe_dict:
            print_func(channel, beacon_printable, '')
        elif probe_dict:
            if len(probe_dict) + len(beacon_dict) >= 45:
                for idx,bs in zip(range(len(probe_dict)), probe_dict):
                    if idx >= (len(probe_dict) + len(beacon_dict)) - 45:
                        probe_printable += f'{probe_dict[bs][0]}\t{bs}\t{probe_dict[bs][1]}\t\t{probe_dict[bs][2]}\n'
                print_func(channel, beacon_printable, probe_printable)
            else:
                for i in probe_dict.keys():
                    probe_printable += f'{probe_dict[i][0]}\t{i}\t{probe_dict[i][1]}\t\t{probe_dict[i][2]}\n'
                print_func(channel, beacon_printable, probe_printable)