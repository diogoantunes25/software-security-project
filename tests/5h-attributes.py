d = 0
d.k = 0
d.k.j = a3()
d.k = a2() # overwrites previous taint
d = a1()
c(d.k)
