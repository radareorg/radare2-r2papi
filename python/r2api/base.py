from . import utils as r2_utils

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

class R2Base(object):
	def __init__(self, r2):
		if not r2_utils.r2_is_valid(r2):
			raise ValueError('Invalid r2pipe object')

		self.r2 = r2
		self._tmp_off = ''

	def _exec(self, cmd, json=False):
		if json:
			return self.r2.cmdj(cmd)
		else:
			return self.r2.cmd(cmd)

	def curr_seek_addr(self):
		try:
			res = int(self._exec('? $$ %s' % self._tmp_off).split()[0])
			return res
		except:
			err_str = 'Invalid address %s' % self._tmp_off
			raise ValueError(err_str)
		finally:
			self._tmp_off = ''

	def sym_to_addr(self, sym):
		if type(sym) != str:
			raise TypeError('Symbol type must be string')
		return self.at(sym).curr_seek_addr()

	def at(self, x):
		self._tmp_off = "@ %s"%(x)
		return self
