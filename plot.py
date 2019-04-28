import pylab
import matplotlib.pyplot as plt

X = []
Y = []
s = float(input())
while s != -1.0:
	X.append(s)
	s = float(input())
	Y.append(int(s))
	s = float(input())
plt.xlabel('Key length (bits)')
plt.ylabel('Time (seconds)')
plt.title('DES bruteforce attack')
plt.plot(X,Y)
pylab.show()
