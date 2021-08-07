#!/usr/bin/python3
from subprocess import PIPE
import subprocess, re, sys

if len(sys.argv) != 2:
    print("[!] USAGE: ./decode.py <file.pcap>")
    exit()

usb_codes_printable = { #https://www.usb.org/sites/default/files/documents/hut1_12v2.pdf
    0x04:"aA",      0x05:"bB",      0x06:"cC",      0x07:"dD",      0x08:"eE",      0x09:"fF",
    0x0A:"gG",      0x0B:"hH",      0x0C:"iI",      0x0D:"jJ",      0x0E:"kK",      0x0F:"lL",
    0x10:"mM",      0x11:"nN",      0x12:"oO",      0x13:"pP",      0x14:"qQ",      0x15:"rR",
    0x16:"sS",      0x17:"tT",      0x18:"uU",      0x19:"vV",      0x1A:"wW",      0x1B:"xX",
    0x1C:"yY",      0x1D:"zZ",      0x1E:"1!",      0x1F:"2@",      0x20:"3#",      0x21:"4$",
    0x22:"5%",      0x23:"6^",      0x24:"7&",      0x25:"8*",      0x26:"9(",      0x27:"0)",
    0x2C:"  ",      0x2D:"-_",      0x2E:"=+",      0x2F:"[{",      0x30:"]}",      0x31:"\|",
    0x32:"#~",      0x33:";:",      0x34:"\'\"",    0x35:"`~",      0x36:",<",      0x37:".>",
    0x38:"/?",      0x54:"//",      0x55:"**",      0x56:"--",      0x57:"++",      0x59:"11",
    0x5A:"33",      0x5B:"44",      0x5C:"55",      0x5D:"66",      0x5E:"77",      0x5F:"88",
    0x60:"99",      0x61:"00"
    }

usb_codes_other ={
    0x01:"[Err_Roll]",      0x02:"[POST_Fail]",       0x03:"[Err_Undef]",     0x28:"\\n",
    0x2B:"\\t",             0x39:"[Caps]",            0x3A:"[F1]",            0x3B:"[F2]",
    0x3C:"[F3]",            0x3D:"[F4]",              0x3E:"[F5]",            0x3F:"[F6]",
    0x40:"[F7]",            0x41:"[F8]",              0x42:"[F9]",            0x43:"[F10]",
    0x44:"[F11]",           0x45:"[F12]",             0x46:"[PrtSc]",         0x47:"[ScrLk]",
    0x48:"[Pause]",         0x49:"[Insert]",          0x4A:"[Home]",          0x4B:"[PgUp]",
    0x4C:"[Delete]",        0x4D:"[End]",             0x4E:"[PgDwn]",         0x4F:"[RtArrow]",
    0x50:"[LfArrow]",       0x51:"[DwArrow]",         0x52:"[UpArrow]",       0x53:"[NumLk/Clr]",
    0x58:"[Keypad Entr]"
    }

#Extract stroke data from the pcap
result = subprocess.run(['tshark','-r', sys.argv[1], '-V'], stdout=PIPE)

#Grab the "Leftover Capture Data"
capture_data = [i[23:] for i in [i.group() for i in re.finditer( r'Leftover Capture Data: .{16}', result.stdout.decode('ascii'))]]

#Decode strokes
output=""
for capture in capture_data:
    stroke = int(capture[4:6],16)

    if stroke in usb_codes_printable.keys():
        if int(capture[0:2],16) == 32: #shift
            output+=usb_codes_printable[stroke][1]
        else: output+=usb_codes_printable[stroke][0]
    elif stroke in usb_codes_other.keys():
        output+=usb_codes_other[stroke]
    elif (stroke == 0):
        continue
    else:
        print(f"Unknown stroke: {stroke}")

print(output)
