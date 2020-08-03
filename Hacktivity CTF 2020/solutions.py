import time


def impartial():
    import re
    import socket
    HOST = 'jh2i.com'  # Standard loopback interface address (localhost)
    PORT = 50026  # Port to listen on (non-privileged ports are > 1023)

    valid = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_{}"
    wrong = {}
    correct = {}
    seen = {}
    i = 0
    response = {}
    catch_resp = False
    logged_in = False
    num1 = ''
    num2 = ''
    num3 = ''

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        while True:
            time.sleep(0.2)
            data = s.recv(1024)
            if catch_resp:
                response[str(valid[i % 65])] = data
                catch_resp = False
                matches = re.findall("(WRONG|CORRECT)", str(data))

                if 'C' in matches[0]:
                    correct[num1] = str(valid[(i - 1) % 65])
                if 'C' in matches[1]:
                    correct[num2] = str(valid[(i - 1) % 65])
                if 'C' in matches[2]:
                    correct[num3] = str(valid[(i - 1) % 65])
            if "only the characters" in str(data):
                submatch = re.findall("characters..at position.*\\(sep", str(data))
                indexmatch = re.findall("[0-9]+", submatch[0])
                num1 = indexmatch[0]
                num2 = indexmatch[1]
                num3 = indexmatch[2]
                print('nums', num1, num2, num3)
                # print('SEEN NUMBERS;', num1, num2, num3)
                seen[num1] = True
                seen[num2] = True
                seen[num3] = True
            if "Exit" in str(data):
                s.send(b'2\n')
            if "Username" in str(data):
                s.send(b'admin\n')
            if "Password:" in str(data):
                # print('debug',str(data))
                s.send((str.encode(valid[i % 65] + ' ' + valid[i % 65] + ' ' + valid[i % 65] + '\n')))
                catch_resp = True
                print('Sent', valid[i % 65])
                i = i + 1
            print('Received', repr(data), correct)


def dumpster():
    import csv
    from operator import itemgetter
    data = {}
    with open('dumpster.csv') as csvfile:
        reader = csv.DictReader(csvfile)
        line = 0
        for row in reader:
            # print(row)

            data[line] = {'flag_char': row['ascii'],
                          'date': "0x" + "".join(
                              [format(int(row['byte8']), '02x'),
                               format(int(row['byte7']), '02x'),
                               format(int(row['byte6']), '02x'),
                               format(int(row['byte5']), '02x'),
                               format(int(row['byte4']), '02x'),
                               format(int(row['byte3']), '02x'),
                               format(int(row['byte2']), '02x'),
                               format(int(row['byte1']), '02x')])
                          }
            print(row['ascii'], int(data[line]['date'], 16))

            line += 1

        # sortedData = sorted(data.values(), key=itemgetter('date'))
        # for item in sortedData:
        #    print(chr(int(item['flag_char'])), end='')


def pinno():
    import requests

    # defining the api-endpoint
    API_ENDPOINT = "http://jh2i.com:50029"
    pins = ['{0:04}'.format(num) for num in range(0, 10000)]
    for pin in pins:
        data = {'pin': str(pin)}

        r = requests.post(url=API_ENDPOINT, json={"pin": str(pin)})
        print(pin, r.text)


def dino():
    import base64
    import binascii

    h = binascii.hexlify
    b = base64.b64encode

    c = b'37151032694744553d12220a0f584315517477520e2b3c226b5b1e150f5549120e5540230202360f0d20220a376c0067'

    def dec(e):
        e = binascii.unhexlify(e)
        e = [x for x in e]
        print('e', e)
        z = []
        i = 0
        while i < len(e):
            z += [e[i] ^ e[((i + 1) % len(e))]]
            i = i + 1
        print('z', z)
        encoded = "".join(chr(i) for i in z)
        return encoded
        # return base64.b64decode(encoded)

    def enc(f):
        e = b(f)
        z = []
        i = 0
        print('e', e)
        while i < len(e):
            print(e, i, e[i], e[(i + 1) % len(e)], [e[i] ^ e[((i + 1) % len(e))]])
            z += [e[i] ^ e[((i + 1) % len(e))]]
            i = i + 1
        print('z', z)
        c = h(bytearray(z))
        return c

    print(enc(b"TEST_FLAG"))
    print(dec(b'13130202107f7e1311030e1e'))


def email():
    raw = open('email.txt', 'rb')
    byte = raw.read(1)
    stripped = ""
    while byte:
        if byte == '\x0a':
            stripped += '-'
        if byte == '\x2e':
            stripped += '.'
        byte = raw.read(1)
        print(byte)

    print(stripped)


def prohpecy():
    import re
    import socket
    HOST = 'jh2i.com'
    PORT = 50012

    stages = {}
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            i = 0
            stages[str(i)] = 99126
            s.connect((HOST, PORT))
            while True:
                time.sleep(0.2)
                data = s.recv(8192)
                print(data)
                if "W H A T I S T H E N E X T N U M B E R T O C O M E F R O M T H E F U T U R E" in str(data):
                    print(stages)
                    if str(i) in stages.keys():
                        print(i, stages[str(i)])
                        s.send(str.encode("" + str(stages[str(i)]) + '\n'))
                        i += 1
                    else:
                        s.send(b'1\n')

                if "F A I L U R E" in str(data):
                    rawLine = re.findall("W A S [0-9]+", str(data))[0]
                    newNum = re.findall("[0-9]+$", rawLine)[0]
                    print(newNum)
                    stages[str(i)] = newNum
                    s.close()
                    break


def redirection():
    import requests
    import re
    seen = {}
    next = "/site/flag.php"
    flag = []
    i=0
    while True:
        r = requests.get('http://jh2i.com:50011' + next, allow_redirects=False)
        if 'location' not in r.headers:
            break
        next = r.headers['Location']
        seen[next] = True
        flag += [r.content]
        i+=1
    for line in flag:
        if line is None or len(line) < 27:
            continue
        print(chr(int(line[len(line)-2])), end='')
        #print(re.findall("...$", str(line)), end='')



def interesting():
    str1 = "NOTFLAG(the_fLag_ISN\'T_here!!!!)"
    str2 = "\x28\x23\x35\x21\x37\x2c\x26\x51\x16\x0d\x3a\x3e\x39\x20\x08\x13\x2b\x25\x36\x11\x4e\x3a\x2b\x0d\x17\x17\x16\x55\x48\x4f\x46\x54"
    i = 0
    for c in str1:
        print(chr(ord(c) ^ ord(str2[i])), end='')
        i+=1


def wireshark():
    import binascii
    import sys
    import itertools
    string = open('wiresharkpacket', 'r').read()
    f = open('output.png', 'w+b')
    f0 = open('output0.png', 'w+b')
    f1 = open('output1.png', 'w+b')
    f2 = open('output2.png', 'w+b')
    raw = binascii.unhexlify(string)

    f.write(raw)

    grouped = [raw[x:x + 16] for x in range(0, len(raw), 16)]
    i = 0
    for line in grouped:
        print(i % 3, line)
        if i % 3 == 0:
            f0.write(line)
        elif i % 3 == 1:
            f1.write(line)
        elif i % 3 == 2:
            f2.write(line)
        i = i + 1


