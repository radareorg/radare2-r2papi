from .base import R2Base, Result, ResultArray

class CPU(R2Base):
	def __init__(self, r2):
		super(CPU, self).__init__(r2)

	def readRegister(self, reg_name):
		res = self._exec('drj', json=True)
		try:
			return res[reg_name]
		except:
			return None

	def __getattr__(self, attr):
		return self.readRegister(attr)


class Debugger(R2Base):
	def __init__(self, r2):
		super(Debugger, self).__init__(r2)

		self.CPU = CPU(r2)

		self.listBreakpoints = lambda: ResultArray(self._exec('dbj', json=True))
		self.step = lambda: self._exec('ds')
		self.memoryMaps = lambda: ResultArray(self._exec('dmj', json=True))

	def start(self):
		self._exec('doo')

	def cont(self):
		self._exec('dc')

	def setBreakpoint(self, addr=0):
		if self._tmp_off != '':
			# '@ foo' -> 'foo'
			addr = self._tmp_off[2:]
		self._exec('db %s' % addr)
		self._tmp_off = ''

	def deleteBreakpoint(self, addr=0):
		if self._tmp_off != '':
			# '@ foo' -> 'foo'
			addr = self._tmp_off[2:]
		self._exec('db- %s' % addr)
		self._tmp_off = ''
