a = source()
if(c>0):
    a=0
else:
    a=f
    b=source()
sink(a)
sink(b)

# variable with taint is rewritten
# taken from group 25 (T25-04)
