d = 0
d.c = a  # leaks from a to c
c = a  # leaks from a to c
e = a
e.k = e
d.c = e.k  # leaks from a (through e and then e.k) to c
