from .base import R2Base, Result, ResultArray

class Binary(R2Base):
	def __init__(self, r2):
		super(Binary, self).__init__(r2)

		self.info = lambda: Result(self._exec('ij', json=True))
		self.searchIn = lambda x: self._exec('e search.in=%s'%(x))
		self.analyzeAll = lambda: self._exec('aaa')
		self.analyzeCalls = lambda: self._exec('aac')
		self.functions = lambda: ResultArray(self._exec('aflj', json=True))
		self.basicBlocks = lambda: ResultArray(self._exec('afbj', json=True))
		self.xrefsAt = lambda: ResultArray(self._exec('axtj', json=True))
		self.refsTo = lambda: ResultArray(self._exec('axfj', json=True))
		self.opInfo = lambda: ResultArray(self._exec('aoj', json=True))[0]
		self.seek = lambda x: self._exec('s %s'%(x))


	def analyzeFunction(self):
		res = self._exec('af %s|'%(self._tmp_off))
		self._tmp_off = ''
		return res

	def disasmFunction(self):
		res = self._exec('pdr %s|'%(self._tmp_off))
		self._tmp_off = ''
		return res

	def disasm(self, x):
		res = self._exec('pd %s%s|'%(x, self._tmp_off))
		self._tmp_off = ''
		return res

	def disasmBytes(self, x):
		res = self._exec('pD %s%s|'%(x, self._tmp_off))
		self._tmp_off = ''
		return res

	def bytes(self, x):
		res = self._exec('p8 %s%s|'%(x,self._tmp_off))
		self._tmp_off = ''
		return res

	def hexdump(self, x):
		res = self._exec('px %s%s|'%(x,self._tmp_off))
		self._tmp_off = ''
		return res

	def read(self, len):
		res = self._exec('p8 %s%s|'%(len, self._tmp_off))
		self._tmp_off = ''
		return res.decode("hex")

	def write(self, buf):
		res = self._exec('wx %s%s|'%(buf.encode("hex")), self._tmp_off)
		self._tmp_off = ''
		return res

	def __getitem__(self, k):
		if type(k) ==  slice:
			_from = k.start
			if type(k.start) == str:
				_from = self.sym_to_addr(k.start)

			_to = k.stop
			if type(k.stop) == str:
				_to = self.sym_to_addr(k.stop)

			read_len = _to - _from
			at_addr = _from
		else:
			read_len = 1
			at_addr = k
		return self.at(at_addr).read(read_len)

	def __setitem__(self, k, v):
		return self.at(k).write(v)
