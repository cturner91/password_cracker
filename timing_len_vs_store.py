import timeit

class Base:
    def __init__(self):
        self.chars = list('abcdefghijklmnopqrstuvwxyz')
        self.chars.extend([char.upper() for char in self.chars])
        self.chars.extend(list('0123456789'))
        self._length = len(self.chars)

BASE = Base()

execution_time = timeit.timeit('BASE._length', number=1_000_000, globals={'BASE': BASE})
print(execution_time)

execution_time = timeit.timeit('len(BASE.chars)', number=1_000_000, globals={'BASE': BASE})
print(execution_time)

# len() is twice as slow -> 37ms vs 67ms
