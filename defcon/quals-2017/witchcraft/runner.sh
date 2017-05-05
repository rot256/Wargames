while read p; do
  python2 doit.py "./bins/$p"
done <$1
