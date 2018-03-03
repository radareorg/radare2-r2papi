def ResultArray(o):
	self = []
	for a in o:
		self.append(Result(a))
	return self

class Result:
	def __init__(self, o):
		self._dict = {}
		try:
			for a in o['bin']:
				setattr(self, a, o['bin'][a])
				self._dict[a] = o['bin'][a]
		except:
			for a in o:
				setattr(self, a, o[a])
				self._dict[a] = o[a]

	def pprint(self):
		ret_str = ''
		for k, v in self._dict.iteritems():
			ret_str += '{:<10}{}\n'.format(k, v)
		# Don't return last newline
		return ret_str[:-1]

	def __str__(self):
		return self.pprint()

class R2Api:
	def __init__(self, r2):
		try:
			r2.cmd('px 1')
		except IOError:
			raise ValueError('Invalid r2pipe object')

		self.r2 = r2
		self._tmp_off = ''

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

	def _exec(self, cmd, json=False):
		if json:
			return self.r2.cmdj(cmd)
		else:
			return self.r2.cmd(cmd)

	def read(self, len):
		res = self._exec('p8 %s%s|'%(len, self._tmp_off))
		self._tmp_off = ''
		return res.decode("hex")

	def write(self, buf):
		res = self._exec('wx %s%s|'%(buf.encode("hex")), self._tmp_off)
		self._tmp_off = ''
		return res

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

	def at(self, x):
		self._tmp_off = "@ %s"%(x)
		return self

	def quit(self):
		self.r2.quit()
		self.r2 = None

	def __getitem__(self, k):
		if type(k) ==  slice:
			read_len = k.stop - k.start
			at_addr = k.start
		else:
			read_len = 1
			at_addr = k
		return self.at(at_addr).read(read_len)

	def __setitem__(self, k, v):
		return self.at(k).write(v)
