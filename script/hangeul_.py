# d559;c704;b17c;bb38;20;c81c;cd9c;20;b3d9;c758;c11c;d;Size:18
# Given a string of hex values, convert to unicode

input_str = "d559;c704;b17c;bb38;20;c81c;cd9c;20;b3d9;c758;c11c;d;Size:18"
input_str = input_str.split(";")[:-1]
input_str = [int(x, 16) for x in input_str]
input_str = [chr(x) for x in input_str]
input_str = "".join(input_str)
print(input_str)
