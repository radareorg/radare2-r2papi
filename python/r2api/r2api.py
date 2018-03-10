from .base import R2Base, Result, ResultArray
from .binary import Binary
from .debugger import Debugger

class R2Api(R2Base):
	def __init__(self, r2):
		super(R2Api, self).__init__(r2)

		self.binary = Binary(r2)
		self.debugger = Debugger(r2)

	def quit(self):
		self.r2.quit()
		self.r2 = None
