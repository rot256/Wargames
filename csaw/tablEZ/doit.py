
t = [
    0x27, 0xb3, 0x73, 0x9d, 0xf5, 0x11, 0xe7, 0xb1,
    0xb3, 0xbe, 0x99, 0xb3, 0xf9, 0xf9, 0xf4, 0x30,
    0x1b, 0x71, 0x99, 0x73, 0x23, 0x65, 0x99, 0xb1,
    0x65, 0x11, 0x11, 0xbe, 0x23, 0x99, 0x27, 0xf9,
    0x23, 0x99, 0x5, 0x65, 0xce, 0x0]


trans_tbl = [
    0x01, 0xbb, 0x02, 0x9b, 0x03, 0xc4, 0x04, 0x6c, 0x05, 0x4a,
    0x06, 0x2e, 0x07, 0x22, 0x08, 0x45, 0x09, 0x33, 0x0a, 0xb8,
    0x0b, 0xd5, 0x0c, 0x06, 0x0d, 0x0a, 0x0e, 0xbc, 0x0f, 0xfa,
    0x10, 0x79, 0x11, 0x24, 0x12, 0xe1, 0x13, 0xb2, 0x14, 0xbf,
    0x15, 0x2c, 0x16, 0xad, 0x17, 0x86, 0x18, 0x60, 0x19, 0xa4,
    0x1a, 0xb6, 0x1b, 0xd8, 0x1c, 0x59, 0x1d, 0x87, 0x1e, 0x41,
    0x1f, 0x94, 0x20, 0x77, 0x21, 0xf0, 0x22, 0x4f, 0x23, 0xcb,
    0x24, 0x61, 0x25, 0x25, 0x26, 0xc0, 0x27, 0x97, 0x28, 0x2a,
    0x29, 0x5c, 0x2a, 0x08, 0x2b, 0xc9, 0x2c, 0x9f, 0x2d, 0x43,
    0x2e, 0x4e, 0x2f, 0xcf, 0x30, 0xf9, 0x31, 0x3e, 0x32, 0x6f,
    0x33, 0x65, 0x34, 0xe7, 0x35, 0xc5, 0x36, 0x39, 0x37, 0xb7,
    0x38, 0xef, 0x39, 0xd0, 0x3a, 0xc8, 0x3b, 0x2f, 0x3c, 0xaa,
    0x3d, 0xc7, 0x3e, 0x47, 0x3f, 0x3c, 0x40, 0x81, 0x41, 0x32,
    0x42, 0x49, 0x43, 0xd3, 0x44, 0xa6, 0x45, 0x96, 0x46, 0x2b,
    0x47, 0x58, 0x48, 0x40, 0x49, 0xf1, 0x4a, 0x9c, 0x4b, 0xee,
    0x4c, 0x1a, 0x4d, 0x5b, 0x4e, 0xc6, 0x4f, 0xd6, 0x50, 0x80,
    0x51, 0x2d, 0x52, 0x6d, 0x53, 0x9a, 0x54, 0x3d, 0x55, 0xa7,
    0x56, 0x93, 0x57, 0x84, 0x58, 0xe0, 0x59, 0x12, 0x5a, 0x3b,
    0x5b, 0xb9, 0x5c, 0x09, 0x5d, 0x69, 0x5e, 0xba, 0x5f, 0x99,
    0x60, 0x48, 0x61, 0x73, 0x62, 0xb1, 0x63, 0x7c, 0x64, 0x82,
    0x65, 0xbe, 0x66, 0x27, 0x67, 0x9d, 0x68, 0xfb, 0x69, 0x67,
    0x6a, 0x7e, 0x6b, 0xf4, 0x6c, 0xb3, 0x6d, 0x05, 0x6e, 0xc2,
    0x6f, 0x5f, 0x70, 0x1b, 0x71, 0x54, 0x72, 0x23, 0x73, 0x71,
    0x74, 0x11, 0x75, 0x30, 0x76, 0xd2, 0x77, 0xa5, 0x78, 0x68,
    0x79, 0x9e, 0x7a, 0x3f, 0x7b, 0xf5, 0x7c, 0x7a, 0x7d, 0xce,
    0x7e, 0x0b, 0x7f, 0x0c, 0x80, 0x85, 0x81, 0xde, 0x82, 0x63,
    0x83, 0x5e, 0x84, 0x8e, 0x85, 0xbd, 0x86, 0xfe, 0x87, 0x6a,
    0x88, 0xda, 0x89, 0x26, 0x8a, 0x88, 0x8b, 0xe8, 0x8c, 0xac,
    0x8d, 0x03, 0x8e, 0x62, 0x8f, 0xa8, 0x90, 0xf6, 0x91, 0xf7,
    0x92, 0x75, 0x93, 0x6b, 0x94, 0xc3, 0x95, 0x46, 0x96, 0x51,
    0x97, 0xe6, 0x98, 0x8f, 0x99, 0x28, 0x9a, 0x76, 0x9b, 0x5a,
    0x9c, 0x91, 0x9d, 0xec, 0x9e, 0x1f, 0x9f, 0x44, 0xa0, 0x52,
    0xa1, 0x01, 0xa2, 0xfc, 0xa3, 0x8b, 0xa4, 0x3a, 0xa5, 0xa1,
    0xa6, 0xa3, 0xa7, 0x16, 0xa8, 0x10, 0xa9, 0x14, 0xaa, 0x50,
    0xab, 0xca, 0xac, 0x95, 0xad, 0x92, 0xae, 0x4b, 0xaf, 0x35,
    0xb0, 0x0e, 0xb1, 0xb5, 0xb2, 0x20, 0xb3, 0x1d, 0xb4, 0x5d,
    0xb5, 0xc1, 0xb6, 0xe2, 0xb7, 0x6e, 0xb8, 0x0f, 0xb9, 0xed,
    0xba, 0x90, 0xbb, 0xd4, 0xbc, 0xd9, 0xbd, 0x42, 0xbe, 0xdd,
    0xbf, 0x98, 0xc0, 0x57, 0xc1, 0x37, 0xc2, 0x19, 0xc3, 0x78,
    0xc4, 0x56, 0xc5, 0xaf, 0xc6, 0x74, 0xc7, 0xd1, 0xc8, 0x04,
    0xc9, 0x29, 0xca, 0x55, 0xcb, 0xe5, 0xcc, 0x4c, 0xcd, 0xa0,
    0xce, 0xf2, 0xcf, 0x89, 0xd0, 0xdb, 0xd1, 0xe4, 0xd2, 0x38,
    0xd3, 0x83, 0xd4, 0xea, 0xd5, 0x17, 0xd6, 0x07, 0xd7, 0xdc,
    0xd8, 0x8c, 0xd9, 0x8a, 0xda, 0xb4, 0xdb, 0x7b, 0xdc, 0xe9,
    0xdd, 0xff, 0xde, 0xeb, 0xdf, 0x15, 0xe0, 0x0d, 0xe1, 0x02,
    0xe2, 0xa2, 0xe3, 0xf3, 0xe4, 0x34, 0xe5, 0xcc, 0xe6, 0x18,
    0xe7, 0xf8, 0xe8, 0x13, 0xe9, 0x8d, 0xea, 0x7f, 0xeb, 0xae,
    0xec, 0x21, 0xed, 0xe3, 0xee, 0xcd, 0xef, 0x4d, 0xf0, 0x70,
    0xf1, 0x53, 0xf2, 0xfd, 0xf3, 0xab, 0xf4, 0x72, 0xf5, 0x64,
    0xf6, 0x1c, 0xf7, 0x66, 0xf8, 0xa9, 0xf9, 0xb0, 0xfa, 0x1e,
    0xfb, 0xd7, 0xfc, 0xdf, 0xfd, 0x36, 0xfe, 0x7d, 0xff, 0x31,
    0x47, 0x43, 0x43, 0x3a, 0x20, 0x28, 0x47, 0x4e, 0x55, 0x29,
    0x20, 0x37, 0x2e, 0x32, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x00][:(0xfe + 1) * 2]

print trans_tbl

pairs = [(trans_tbl[c], trans_tbl[c+1]) for c in range(0, len(trans_tbl), 2)]
invert = dict(map(lambda (k, v): (v, k), pairs))

print len(set(invert.keys()))
print len(set(invert.values()))

flag = map(lambda x: invert[x], t[:-1])
print ''.join(map(chr, flag))



