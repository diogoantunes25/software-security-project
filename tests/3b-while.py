a = 0
b = 0
c = source

# The state is always changing >:)
while input():
    t = a
    a = b
    b = c
    c = t

sink = a

# taken from group 4 (test T04-05)
