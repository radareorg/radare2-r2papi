from .base import R2Base

class Debugger(R2Base):
	def __init__(self, r2):
		super(Debugger, self).__init__(r2)

	def start(self):
		self._exec('doo')
