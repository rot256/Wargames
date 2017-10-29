
https://www2.eecs.berkeley.edu/Pubs/TechRpts/2014/EECS-2014-54.pdf

[0x000190e4]> axt sym.imp.fprintf
null 0x10290 addi a2, sp, sym.imp.fprintf in unknown function
[0x000190e4]> axt sym.imp.puts
null 0x102c0 addi a2, sp, sym.imp.puts in unknown function

Register ABI Name Description Saver
x0 zero Hard-wired zero —
x1 ra Return address Caller
x2 s0/fp Saved register/frame pointer Callee
x3–13 s1–11 Saved registers Callee
x14 sp Stack pointer Callee
x15 tp Thread pointer Callee
x16–17 v0–1 Return values Caller
x18–25 a0–7 Function arguments Caller
x26–30 t0–4 Temporaries Caller
x31 gp Global pointer —
f0–15 fs0–15 FP saved registers Callee
f16–17 fv0–1 FP return values Caller
f18–25 fa0–7 FP arguments Caller
f26–31 ft0–5 FP temporaries Caller


|           0x00010404      2334117e       sd ra, 2024(sp)
|           0x00010408      2330817e       sd s0, 2016(sp)
|           0x0001040c      233c917c       sd s1, 2008(sp)
|           0x00010410      2338217d       sd s2, 2000(sp)
|           0x00010414      2334317d       sd s3, 1992(sp)
|           0x00010418      2330417d       sd s4, 1984(sp)
|           0x0001041c      233c517b       sd s5, 1976(sp)
|           0x00010420      2338617b       sd s6, 1968(sp)
|           0x00010424      2334717b       sd s7, 1960(sp)
|           0x00010428      2330817b       sd s8, 1952(sp)
|           0x0001042c      233c9179       sd s9, 1944(sp)
|           0x00010430      2338a179       sd s10, 1936(sp)
|           0x00010434      2334b179       sd s11, 1928(sp)
|           0x00010438      8947           li a5, 2
|           0x0001043a      5571           addi sp, sp, -208
|           0x0001043c      6304f500       beq a0, a5, 0x10444
|           0x00010440      6f803045       j 0x19092
|           0x00010444      9865           ld a4, 8(a1)
|           0x00010446      9567           lui a5, 0x5



                                | addi sp, sp, -208 ;[gc]                                                         |
                                | beq a0, a5, 0x10444 ;[gd]                                                       |
                                `---------------------------------------------------------------------------------'
                                        f t
                                        '--------------.-------------------------.
                                                       |                         |
                                                       |                         |
                                               .--------------------.      .--------------------------.
                                               |  0x10440 ;[gf]     |      |  0x10444 ;[gd]           |
                                               | j 0x19092          |      | ld a4, 8(a1)             |
                                               `--------------------'      | lui a5, 0x5 ;[gg]        |

