# -*- coding: utf-8 -*-
"""
Created on Thu Jan 14 09:22:22 2022

@author: yosra
"""
# Encoding and decoding : UTF-8, ASCII, Base64, Base32 and Base16
import base64

# UTF-8 Encoding
def encode_utf8(data):
    return data.encode('utf8')
def decode_utf8(coded_data):
    return coded_data.decode('utf8')

# ASCII Encoding
def encode_ascii(data):
    return data.encode('ascii')
def decode_ascii(coded_data):
    return coded_data.decode('ascii')

# Base64 Encoding
def encode_base64(data):
    return base64.b64encode(data.encode('ascii')).decode('ascii')
def decode_base64(coded_data):
    return base64.b64decode(coded_data.encode('ascii')).decode('ascii')
# Base32 Encoding
def encode_base32(data):
    return base64.b32encode(data.encode('ascii')).decode('ascii')
def decode_base32(coded_data):
    return base64.b32decode(coded_data.encode('ascii')).decode('ascii')

# Base16 Encoding
def encode_base16(data):
    return base64.b16encode(data.encode('ascii')).decode('ascii')
def decode_base16(coded_data):
    return base64.b16decode(coded_data.encode('ascii')).decode('ascii')
    
# =============================================================================
# def encode(data, method):
#     if method in ['utf8','ascii']:
#         return data.encode(encoding=method)
# 
#     elif(method == 'base64'):
#    		return base64.b64encode(data.encode('ascii')).decode('ascii')
# 
#     elif(method == 'base32'):
#    		return base64.b32encode(data.encode('ascii')).decode('ascii')
# 
#     elif(method=='base16'):
#    		return base64.b16encode(data.encode('ascii')).decode('ascii')
# 
# 
# def decode(encoded_data, method):
#     if(method in ['utf8','ascii']):
#         return encoded_data.decode(encoding=method)
# 		
#     elif(method == 'base64'):
#    		return base64.b64decode(encoded_data.encode('ascii')).decode('ascii')
# 
#     elif(method == 'base32'):
#    		return base64.b32decode(encoded_data.encode('ascii')).decode('ascii')
# 
#     elif(method=='base16'):
#    		return base64.b16decode(encoded_data.encode('ascii')).decode('ascii')
# =============================================================================
