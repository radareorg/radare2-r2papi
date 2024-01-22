from os import listdir
import re

def slurp(f):
	fd = open(f, errors="ignore")
	data = fd.read()
	fd.close()
	return str(data)

def dump(f, x):
	fd = open(f, "w")
	fd.write(x)
	fd.close()

def asyncify_function(lines):
	def asyncify_line(line):
		hascall = False
		if "this.r2.cmd" in line or "this.r2.call" in line:
			hascall = True
			if "return" not in line:
				line = line.replace("this.r2.c", "await this.r2.c")
		elif "r2.cmd" in line or "r2.call" in line:
			hascall = True
			if "return" not in line:
				line = line.replace("r2.c", "await r2.c")
		if hascall and ".trim" in line:
			line += " // XXX"
		return line
	def is_async_function(lines):
		allcode = "\n".join(lines)
		return "r2.cmd" in allcode or "r2.call" in allcode or "api.call" in allcode
	if is_async_function(lines):
		code = []
		code.append(lines[0].replace("\t", "\tasync "))
		for line in lines[1:]:
			code.append(asyncify_line(line))
		return "\n".join(code)
	return "\n".join(lines)

def asyncify(s):
	f = f"async/{s}"
	data = slurp(f)
	async_method = False
	lines = []
	def is_function_start(line):
		if re.match(r"^\t[a-z]", line) and ("constructor" not in line):
		       	return line.endswith("{") or "{ // " in line
		return False
	def is_function_end(line):
		return line == "\t}"
	function = []
	in_function = False
	for line in data.split("\n"):
		if in_function:
			if is_function_end(line):
				function.append(line)
				afunc = asyncify_function(function)
				lines.append(afunc)
				in_function = False
				function = []
			else:
				function.append(line)
		elif is_function_start(line):
			in_function = True
			function.append(line)
		else:
			lines.append(line)
	dump(f, "\n".join(lines))

for file in listdir("async"):
	asyncify(file)
