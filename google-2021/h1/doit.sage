n = 8948962207650232551656602815159153422162609644098354511344597187200057010413418528378981730643524959857451398370029280583094215613882043973354392115544169

mod = 8948962207650232551656602815159153422162609644098354511344597187200057010413552439917934304191956942765446530386427345937963894309923928536070534607816947

a = 6294860557973063227666421306476379324074715770622746227136910445450301914281276098027990968407983962691151853678563877834221834027439718238065725844264138
b = 3245789008328967059274849584342077916531909009637501918328323668736179176583263496463525128488282611559800773506973771797764811498834995234341530862286627
n = 8948962207650232551656602815159153422162609644098354511344597187200057010413418528378981730643524959857451398370029280583094215613882043973354392115544169
G = (5139617820728399941653175323358137352238277428061991823713659546881441331696699723004749024403291797641521696406798421624364096550661311227399430098134141,
     1798860115416690485862271986832828064808333512613833729548071279524320966991708554765227095605106785724406691559310536469721469398449016850588110200884962,
     5042518522433577951395875294780962682755843408950010956510838422057522452845550974098236475624683438351211176927595173916071040272153903968536756498306512)

import os
import hashlib

def RNG(nbits, a, b):
    nbytes = nbits // 8
    B = os.urandom(nbytes)
    return a * sum([B[i] * b ** i for i in range(len(B))]) % 2**nbits

B = 32
L = 512

F = GF(n)
D = GF(mod)
E = EllipticCurve(D, [a, b])
G = E(G[0] / D(G[2])^2, G[1] / D(G[2])^3)

def lll_solve(t, u):

    cols = (L // B) * 2 + 1

    K = 2^8

    M = []
    M.append([n] + (cols - 1) * [0])

    inv = F(0x01010101)^-1

    ci = [0x01010101 * 2^(B * i) for i in range(L / B)]
    ti = ci + [ci[i] * t for i in range(L / B)]
    ti = [int(v * inv) for v in ti]

    for i, v in enumerate(ti[1:]):
        M.append([v] + [0] * i + [1] + [0] * (cols - i - 2))

    M.append([int(u * inv)] + [0] * (cols - 2) + [K])

    for row in M:
        print(row)

    M = Matrix(M)

    for row in M.LLL():
        print(row)
        break

    # flip
    row[0] = -row[0]

    k1 = int(''.join([4 * ('%02x' % v) for v in row[:16]][::-1]), 16)
    k2 = int(''.join([4 * ('%02x' % v) for v in row[16:32]][::-1]), 16)

    return k1, k2


def get_u_t(s1, r1, h1, s2, r2, h2):

    s1 = F(s1)
    r1 = F(r1)

    s2 = F(s2)
    r2 = F(r2)

    t = - s1^-1 * s2 * r1 * r2^-1
    u = s1^-1 * r1 * h2 * r2^-1 - s1^-1 * h1
    return (t, u)

def msg_to_h(msg):
    def Transform(m, l):
        z = m
        shift = l - int(n).bit_length()
        if shift > 0:
            z >>= shift
        return z
    h = hashlib.sha512(msg)
    z = Transform(int.from_bytes(h.digest(), 'big'), h.digest_size*8)
    return z

msgb_1 = b'Hello Alice.'
msgb_2 = b'Dinner sounds good. Thanks for the flag.'

z1 = msg_to_h(msgb_1)
z2 = msg_to_h(msgb_2)

# t = int(F.random_element())
# u = int(F(- k1 - t * k2))




r1, s1, c1 = (6706720197123832142768727143395528571627385686729472279085077699672602636953568596628477227511870037092766007177588966333093607595831000050978265637877796, 1073779379108240410856990657565545229209771903946426639922087094813786902448520023335130808991515066506036954730763452318418336144389425011731474342543709, 111403492170712993917428321974111102656)
r2, s2, c2 = (7616464676048536081690041693308621105395807976530049374449777558721544903144139995398352331701243976154631946836252022822278420653297509476320989403738186, 7381293847317597354132365685036776332763847784351725370466906894121224725876600151244989563125805807680044723478850091886778158534219876869209592138625256, 7994736246642278834331127451449673561762900804586058657648578638831731501930073150317394505661139656896430884711113)

'''
d =  10486390420359598305867487378559457096552700622651143034820326571705569321183651060931366989531553283451502679632077848068089863986872734957352381678072771
z1 =  2490035435756055592518393323508734348993321138839618214891430908777557331064506015397928447645347813126543108920365730404888727021522356793461869735549952
k1 =  3522835810659705153641982295932723092835119397587109285016567402448233278052579603248553895607073672046678717271327459133654726619654417366018727038939119
r1 =  70522118749912226046440464784585832590757147297475471072189245567636899986124763940682503411841683354007542293875839278124315189290476552821221990650845
s1 =  915430411333519896987824857585778698334095422444598299607059204572797103716775327047785884445381883126545093778121690754921353251562513123613933095013423

assert z1 == h1
assert s1 == pow(k1, -1, n) * (z1 + r1 * d) % n

d =  10486390420359598305867487378559457096552700622651143034820326571705569321183651060931366989531553283451502679632077848068089863986872734957352381678072771
z2 =  3572240903692100744611111395231555416102753802082328034327422298312051266319958347578043254697090728526174261720137316806273263536603415253647930266590875
k2 =  3890893283625871368260572041740566335828260934686261395244357093518152400965259240487996340551873293690570070138491312937321518610679620906157825399451631
r2 =  2040670654917460204782762728813624278369656902351982746983563521031173842770500386374855672115013554443118677334525127122864017606788036963838113118618624
s2 =  6203253054390208001728764330824809582778489560446928594000995889887562327020152812819445086460466536667382567460228184482405538251128117127537534114147847
'''

# assert z2 == h2
# assert s2 == pow(k2, -1, n) * (z2 + r2 * d) % n

# s2 * k2 - z2 == r2 * d
# s1 * k1 - z1 == r1 * d

# (s2 * k2 - z2) / (s1 * k1 - z1) == r2 / r1
# (s2 * k2 - z2) * r1 == (s1 * k1 - z1) * r2
# (s2 * k2 - z2) * r1 / (s1 * r2) == k1 - z1 / s1
# (s2 * k2 - z2) * r1 / (s1 * r2) + z1 / s1 == k1
# (s2 * k2 * r1 - z2 * r1) / (s1 * r2) + z1 / s1 == k1
# (s2 * r1 / (s1 * r2)) * k2 + (- z2 * r1 / (s1 * r2) + z1 / s1) == k1

# assert (s2 * r1 / F(s1 * r2)) * k2 + (- z2 * r1 / F(s1 * r2) + F(z1) / F(s1)) == F(k1)

u = - z2 * r1 / F(s1 * r2) + F(z1) / F(s1)
t = s2 * r1 / F(s1 * r2)

u = -1 * u
t = -1 * t

# t, u = get_u_t(r1, s1, h1, r2, s2, h2)

k1, k2 = lll_solve(t, u)

assert F(k1) + t * F(k2) + u == F(0)

print('k1 = 0%x' % k1)
print('k2 = 0%x' % k2)

d = (k1 * s1 - z1) / F(r1)
d = int(d)

print('d =', d)


# Alice -> Bob:
r, s, _ = (8618416354247009865173783322782283385800726568519779763790691157278063798628048418532907783021806238103423515210146966468025964847364086792099622893845216, 2932674107137731789093617068375500084388905453653468925392946088867116597531950960271857205235755778202380084260003117176704579423285955014316540314931750, 27865871384804321325511205140263204607)

msga = b'Hello Bob.'

def recover_key(r, s, h):

    # compute possible x-coordinates
    xs = [D(int(r))]
    if D.order() > F.order():
        xs.append(D(int(r) + n))

    pks = []
    for x in xs:

        # find curve point with the given x-coordinate
        try:
            R = E.lift_x(x)
        except ValueError:
            # not on the curve
            continue

        # it is either R or -R (for which the x-coordinate is the same)
        pks.append(int(r^-1) * (int(s) * R - int(h) * G))
        pks.append(int(r^-1) * (int(s) * (-R) - int(h) * G))

    return pks


R = E.lift_x(D(r))
r = F(r)
s = F(s)

for pk in recover_key(r, s, h = msg_to_h(msga)):
    ss = int((int(d) * pk)[0])
    print('ss = 0x%x' % ss)


