// if nodejs then require (r2pipe.orig");

class R2PipeInstance() {
	constructor() {
	}
	cmd(s: string) string {
		return "";
	}
}

module.exports = {
	open: function() {
	      return new R2PipeInstance();
      }
}
