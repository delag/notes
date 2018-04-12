Global vs Local variables

If there is no local variable in a given function Python will assume that you want the global variable.
```
>>> def spam():
	print(eggs)

>>> eggs = 32
>>> spam()
32
```

If you do pass a local variable python will use it when calling the function. However global variables will print if called on their own.
```
>>> def spam():
	eggs = 20
	print(eggs)

>>> eggs = 'Hi!'
>>> spam()
20
>>> print(eggs)
Hi!
```

If you append `global` to the local variable inside a function it will make it a global variable.
```
>>> def spam():
	global eggs
	eggs = 'Hello'
	print(eggs)

>>> eggs = 43
>>> spam()
Hello
>>> print(eggs)
Hello
```

https://stackoverflow.com/questions/15286401/print-multiple-arguments-in-python
