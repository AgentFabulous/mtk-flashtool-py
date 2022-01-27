import glob
import sys
import time

import serial
from struct import unpack

from chip_mapping import chip_map

SKIP_SLA = False
DEBUG = False


def serial_ports():
    if sys.platform.startswith('win'):
        _ports = ['COM%s' % (i + 1) for i in range(256)]
    elif sys.platform.startswith('linux') or sys.platform.startswith('cygwin'):
        _ports = glob.glob('/dev/tty[A-Za-z]*')
    elif sys.platform.startswith('darwin'):
        # Don't accidentally look up wlan-debug and bluetooth ports
        _ports = glob.glob('/dev/tty.usbmodem*')
    else:
        raise EnvironmentError('Unsupported platform')

    result = []
    for port in _ports:
        try:
            s = serial.Serial(port)
            s.close()
            result.append(port)
        except (OSError, serial.SerialException):
            pass
    return result


def hex_list_to_str(hex_list):
    return '[ ' + ' '.join(hex_list) + ' ]'


def write_serial(s, data):
    cmd_bytes = bytearray.fromhex(data)
    write_serial_raw(s, cmd_bytes)


def write_serial_raw(s, data, nowrite=False):
    sdata = []
    for cmd_byte in data:
        hex_byte = ("{0:02x}".format(cmd_byte))
        # print(hex_byte, end=' ')
        sdata.append(hex_byte)
        if not nowrite:
            s.write(bytearray.fromhex(hex_byte))
    if DEBUG:
        print('TX ->', hex_list_to_str(sdata))


def read_serial(s, byte_count):
    ret = []
    for i in range(byte_count):
        ret.append(s.read(1).hex())
    if DEBUG:
        print('RX <-', hex_list_to_str(ret))
    return ret


def try_handshake(s, port):
    print('\nAttempting handshake on [{}]...'.format(port))
    data = 'a00a5005'
    is_preloader = False
    handshake_magic = '5ff5affa'
    preloader_greet = str(b'READY'.hex())
    cmd_bytes = bytearray.fromhex(data)
    retry = True
    rdata = ''
    while retry:
        rdata = ''
        for cmd_byte in cmd_bytes:
            _data = ("{0:02x}".format(cmd_byte))
            write_serial(s, _data)
            while not s.in_waiting:
                continue
            rdata += ''.join(read_serial(s, 1))
            rb_count = s.in_waiting
            for i in range(rb_count):
                rdata += ''.join(read_serial(s, 1))
            if rdata == preloader_greet:
                is_preloader = True
                break
            retry = False
    if rdata == handshake_magic:
        print('Handshake success! Found MTK device at', port)
        print('Device connected via', 'Preloader' if is_preloader else "BootROM")
        return True
    elif rdata == data:
        print('Handshake complete. Warning: device returned input data. (Is Handshake already done?)')
    else:
        print('Handshake failed! Aborting.')
        sys.exit(0)


def check_preloader(s):
    print('\nChecking preloader version...')
    data = 'fe'
    write_serial(s, data)
    rb = ''.join(read_serial(s, 1))
    if rb == data:
        print('Invalid preloader version! BootROM connection.')
    else:
        print('Preloader version = 0x' + rb)


def read_resp(s, cmd, inital_sleep=0.1):
    write_serial(s, cmd)
    if ''.join(read_serial(s, 1)) == cmd:
        if DEBUG:
            print("ACK - [", cmd, ']')
        ctr = 0
        time.sleep(inital_sleep)
        while not s.in_waiting:
            time.sleep(0.1)
            if ctr == 15:  # Keep checking for responses for 1.5 seconds
                break
            else:
                ctr += 1
                continue
        return read_serial(s, s.in_waiting)


def bstr_to_int(bstr):
    return int.from_bytes(bytes.fromhex(''.join(bstr)), "big")


def get_chip_id(s):
    print('\nQuerying Chip ID...')
    hw_code_cmd = 'fd'
    hw_sub_cmd = 'fc'
    hw_code_resp = bstr_to_int(read_resp(s, hw_code_cmd))
    hw_sub_resp = bstr_to_int(read_resp(s, hw_sub_cmd))
    chip_config = chip_map[hw_code_resp >> 16]
    chip_config['hw_sub_code'] = (hw_sub_resp >> 32) >> 16
    chip_config['hw_version'] = (hw_sub_resp >> 32) & 0xFFFF
    chip_config['sw_version'] = hw_sub_resp & 0xFFFFFFFF
    print("==============================")
    print("======= Chip detected! =======")
    print("==============================")
    print("======= {} ({}) =======".format(chip_config['name'], hex(chip_config['id'])))
    print("  Hardware Code:", hex(chip_config['hw_code']))
    print("  Hardware Sub-code:", hex(chip_config['hw_sub_code']))
    print("  Hardware Version:", hex(chip_config['hw_version']))
    print("  Software Version:", hex(chip_config['sw_version']))
    print("==============================")
    return chip_config


def load_auth_file():
    return open('auth_sv5.auth', 'rb').read()


def send_auth_file(s):
    print('\nLoading and sending auth file')
    data = 'e2'
    write_serial(s, data)
    if ''.join(read_serial(s, 1)) == data:
        data = '000008d0'
        write_serial(s, data)
        if ''.join(read_serial(s, 4)) == data:
            read_serial(s, 2)
            write_serial_raw(s, load_auth_file())
            read_serial(s, 2)
            if ''.join(read_serial(s, 2)) == '0000':
                print('Auth file send success!')
            else:
                print('Failed to send auth file! Aborting.')
                sys.exit(0)
        else:
            print('Bad command! Aborting.')
            sys.exit(0)
    else:
        print('Send Auth File failed! Aborting.')
        sys.exit(0)


def qualify_host(s):
    print('\nQualify Host')
    if SKIP_SLA:
        print('Skipping qualify host! (SLA_Challenge)')
        return
    else:
        data = 'e3'
        write_serial(s, data)
        if ''.join(read_serial(s, 1)) == data:
            read_serial(s, 2)
            read_serial(s, 4)
            ip = read_serial(s, 16)
            data = '00000100'
            write_serial(s, data)
            if ''.join(read_serial(s, 4)) == data:
                read_serial(s, 2)
                for i in range(0, 16):
                    write_serial(s, ''.join(ip))
                read_serial(s, 2)


def load_da():
    target_da = 'MTK_AllInOne_DA.bin'
    f = open(target_da, 'rb')
    pos = 0x68
    f.seek(pos)
    print("\n==============================")
    print("========= DA Loader ==========")
    print("==============================")
    print("  Loading {}...".format(target_da))
    print("  Supported Chips: ")
    da_count = unpack("<I", f.read(4))[0]
    for i in range(da_count):
        hw_code = hex(unpack("<I", f.read(4))[0] >> 16)
        print('    - MT' + str(hw_code).split('x')[1])
        # Comparing len between each "0xDADA" in header, consistently 220
        f.seek(f.tell() + 220 - 4)
    print("  Loaded DA!\n  Found {} supported chips.".format(da_count))
    print("==============================")


def send_da(s):
    print('\nSend DA')
    data = 'd7'
    write_serial(s, data)
    if ''.join(read_serial(s, 1)) == data:
        data = '00200000'
        write_serial(s, data)
        if ''.join(read_serial(s, 4)) != data:
            return
        data = '000361a8'
        write_serial(s, data)
        if ''.join(read_serial(s, 4)) != data:
            return
        data = '00000100'
        write_serial(s, data)
        if ''.join(read_serial(s, 4)) != data:
            return
        read_serial(s, 2)
        ba = load_da()
        print('Loaded DA. Sending...')
        for i in range(int(len(ba) / 8192)):
            write_serial_raw(s, ba[i * 8192:(i + 1) * 8192])
        read_serial(s, 2)
        read_serial(s, 2)


if __name__ == '__main__':
    print('Listening for ports!')
    abort = False
    while not abort:
        time.sleep(1)
        ports = serial_ports()
        if len(ports) > 0:
            print('Got ports:', ports)
            print('Initializing port', ports[0])
            ser = serial.Serial(port=ports[0], baudrate=115200)
            try_handshake(ser, ports[0])
            check_preloader(ser)
            get_chip_id(ser)
            load_da()
            #            send_auth_file(ser)
            #            qualify_host(ser)
            #            send_da(ser)
            abort = True
