from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import unpad
import hashlib
from Crypto.Cipher import AES
from params import A,B,ct
from gmpy2 import is_prime
from libnum import invmod
import random

class Curve:

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def add(self, p1, p2):
        if p1 == self.zero:
            return p2

        if p2 == self.zero:
            return p1

        x1, y1 = p1
        x2, y2 = p2

        if x1 != x2:
            l = (y2 - y1) * invmod(x2 - x1, P)
        else:
            l = 2 * self.a * x1 + self.b

        x = ((l - self.b) * invmod(self.a, P) - self.zero[0]) % P
        y = ((x - self.zero[0]) * l + self.zero[1]) % P

        return (x, y)

    def mul(self, p1, n):
        if n == 0 or p1 == self.zero:
            return self.zero

        res = self.zero
        while n:
            if n & 1:
                res = self.add(res, p1)
            p1 = self.add(p1, p1)
            n >>= 1
        return res

    def gen_key(self):
        sk = random.randint(1, P)
        pk = self.mul(self.gen, sk)
        return sk, pk


a = 338105350242668308929697763396044301660
b = 70631159681042046635446173236982478064116538177970218795092411634131296885767
zero = (9754705134713370500425418962906364916694128219443986534870265438313712052553913556304578048773182865236181393234774811636563665254738358548547686098321918938336999994543320310489785839068889289585561389237322554300534800377365494547910434446171077511660646734142974631896227159038644834795595939445003783184271907835168083982210804135992472981458997056367475361358045062954295385753362817510369968941277639065938619221482008127361125972584968230982231483416783792258479416113581249377750311129019561848383083514672254514692875070293706012921153875918378772956871354902564753931679232128607231527456371560574893648150, 1568631189076775839914050721386821274436631828518639911590203429753674249963724465949098434816249858592209181914562366684848647341809527620103035336678319490054708958682690371323396425059326761139960520329829342510826324634871361342587962617109233961205192373716747727013613655062002124851676969800006190929713777159839273173689438005523473921392011053323705509027606365967531781465002057406686284573053674133382181877418753925610208463393821516137543581472014268533517599374830226690216017114664929426655189944119312800402788151756994817725042844409983509754618168400455155658767237036605650525875166823462486072842)
gen = (12532998589621080097666945122441206260965625062664570083674602252675892295679594034580389931735096079697125441246960301905307858329289188790029626634485829771734823159182904621402737540757430079518142479215838577833498703259391220160619426650385355407344355318793784733990238754982178179201863773450543367485332580658467529082154218982726945799974265641603861234501912638573835723384717842487988638277214429988591192513007462677389252245306874828268739787612245357189986581131725474432904172834643657027954405787429995826738074015516166702962206858859896933459093477305874443350335332968385035927605359630747331204285, 9677982578222119974363478748399786948047636069661692206522662047830643067492306311529114015320387572903840619331518584584400368845497864412752196098241604714699115186432809693851692194762433385961429711487895639093866274072187416400859677893102613898063134064507994013600600120524875666883108971040402000931357050726739367647257578379098507781478457700720118945453670136245178829199722575486626106268256525611370267664890630521019846806960099333376121482220389744953231843397729642415527736926160072478730239575933321480584291410141867063436921546657245313608614224909988684794138541856898030369431518091733072867437)

curve = Curve(
    a=a,
    b=b,
    zero=zero,
    gen=gen,
)

def get_kp(point):
    return a * (pow(point[0],2) - pow(zero[0],2)) + b * (point[0] - zero[0]) + zero[1] - point[1]

def get_point(x):
    return (x % P,(a * (pow(x,2) - pow(zero[0],2)) + b * (x - zero[0]) + zero[1]) % P)

assert get_point(A[0]) == A and get_point(B[0]) == B and get_point(gen[0]) == gen

v1 = get_kp(A)
v2 = get_kp(B)
v3 = get_kp(gen)

kp = Integer(gcd(v1,v3)) #small multiple of P
#after factoring kp
P = 16964155551072495694293641975607630224727620299506094680698561697517114055981456463802735036670824528486635128253757386796419676408241481233714972382812783160754601985902695360703612064223677630625126592834772106201583720344150312382723959316671117708799304253580291408927697557459674805267132980104779404642276846095233729275890317878916892907703929715499923974553217760175425647369679697361138159243363407958468903965694813367459663590914481184614924748816307473556323329341018650081832249242635801731713869201574073433674020290004290751530577883843107369211669006291178070342858539229191025760918841972906522445981
assert is_prime(P) #P recovered!
assert zero == curve.mul(gen, P) #order of gen is P


points = {}
start = random.randint(1,P)
xs = {}

for i in range(1,10):
    xs[i] = curve.mul(gen, i)[0]

diffs = [(xs[i] - xs[i-1]) % P for i in range(2,max(xs) + 1)] #constant diffs
diff = diffs[0]

ak = (1 + (A[0] - gen[0])*invmod(diff,P)) % P #From Ax = Gx + (a-1)*diff mod P
assert curve.mul(gen, ak) == A

shared = curve.mul(B, ak)[0]
key = hashlib.sha256(long_to_bytes(shared)).digest()
aes = AES.new(key, AES.MODE_ECB)
flag = unpad(aes.decrypt(long_to_bytes(ct)),AES.block_size)
print(flag) 