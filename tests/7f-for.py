a=source()
for a in range(7):
    sink(source)
    pass
sink(a)

a=source()
for a in source():
    pass
sink(a)

a=source()
for a in 'ola':
    pass
sink(a)

# for assignments
# adapted from group 25
