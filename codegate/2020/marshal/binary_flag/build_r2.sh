git clone https://github.com/radareorg/radare2.git
cd radare2
git reset --hard 04f065c68c35e49996dc138560e99489e0a45dcb
patch -s -p1 < ../patch.diff
./configure --disable-debugger
export CC=afl-gcc
make
make install
