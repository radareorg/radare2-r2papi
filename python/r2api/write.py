from .base import R2Base

class Write(R2Base):
	def __init__(self, r2):
		super(Write, self).__init__(r2)

	def hex(self, hex_string):
		ret = self._exec('wx %s%s' % (hex_string, self._tmp_off))
		self._tmp_off = ''
		return ret

	def string(self, string, final_nullbyte=False):
		if final_nullbyte:
			string = string + '\\x00'
		ret = self._exec('"w %s" %s' % (string, self._tmp_off))
		self._tmp_off = ''
		return ret

	def base64(self, string, encode=True):
        # TODO: Check and finish this
		if encode:
			ret = self._exec('w6e %s %s' % (string, self._tmp_off))
		else:
			# TODO: Decode not working (?) w6d
			pass
		self._tmp_off = ''
		return ret

	def assembly(self, asm_str):
		ret = self._exec('"wa %s" %s' % (asm_str, self._tmp_off))
		self._tmp_off = ''
		return ret

	def random(self, size=0):
		ret = self._exec('wr %s%s' % (size, self._tmp_off))
		self._tmp_off = ''
		return ret

	def nop(self):
		self._exec('wao nop %s' % (self._tmp_off))
		self._tmp_off = ''
